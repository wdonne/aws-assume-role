use crate::OperatorError::{EcrTokenFormat, NoCredentials, NoEcrToken, NoRepositoryUrl};
use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_sdk_ecr::config::http::HttpResponse;
use aws_sdk_ecr::operation::get_authorization_token::GetAuthorizationTokenError;
use aws_sdk_sts::error::SdkError;
use aws_sdk_sts::operation::assume_role::AssumeRoleError;
use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;
use aws_sdk_sts::types::Credentials;
use base64::prelude::BASE64_STANDARD;
use base64::{DecodeError, Engine};
use chrono::{DateTime, TimeDelta, Utc};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::ByteString;
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::{watcher, Config, Controller};
use kube::{Api, Client, Resource, ResourceExt};
use kube_operator_util::status::set_ready;
use log::{error, info};
use ::resource::{AWSAssumeRole, SecretType};
use rustls::crypto::ring::default_provider;
use serde_json::json;
use std::collections::BTreeMap;
use std::error::Error;
use std::str::Utf8Error;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_DURATION: i32 = 900;

struct Data {
    account_id: String,
    client: Client,
    sts_client: aws_sdk_sts::Client,
}

struct EcrToken {
    password: String,
    username: String,
}

#[derive(Error, Debug)]
enum OperatorError {
    #[error("the AWS role could not be assumed")]
    AssumeRole(#[from] Box<SdkError<AssumeRoleError>>),
    #[error("string is not encoded in Base64")]
    Decode(#[from] DecodeError),
    #[error(" an ECR token should have a username and a password with a colon in between")]
    EcrTokenFormat,
    #[error("the ECR authorization token could not be fetched")]
    GetAuthorization(#[from] Box<SdkError<GetAuthorizationTokenError, HttpResponse>>),
    #[error("kube API error")]
    Kube(#[from] kube::Error),
    #[error("no AWS credentials were received")]
    NoCredentials,
    #[error("no ECR authorization token was received")]
    NoEcrToken,
    #[error("the URL of the ECR repository is missing")]
    NoRepositoryUrl,
    #[error("the secret could not be created: {0}")]
    SecretCreation(String),
    #[error("the status of {0} could not be updated")]
    StatusPatch(String),
    #[error("string is not encoded in UTF-8")]
    Utf8(#[from] Utf8Error),
}

async fn account_id(
    sts_client: &aws_sdk_sts::Client,
) -> Result<String, SdkError<GetCallerIdentityError>> {
    Ok(sts_client
        .get_caller_identity()
        .send()
        .await?
        .account
        .unwrap())
}

fn almost_expired(obj: &AWSAssumeRole, last_update: &DateTime<Utc>) -> bool {
    Utc::now()
        > *last_update
            + TimeDelta::try_seconds(almost_expired_seconds(obj) as i64)
                .map_or(TimeDelta::zero(), |s| s)
}

fn almost_expired_seconds(obj: &AWSAssumeRole) -> u64 {
    (obj.spec.duration_seconds.map_or(DEFAULT_DURATION, |d| d) as f32 * 0.9).round() as u64
}

async fn aws_credentials(
    assume_role: &AWSAssumeRole,
    ctx: &Data,
) -> Result<Credentials, OperatorError> {
    let output = ctx
        .sts_client
        .assume_role()
        .role_arn(role_arn(&ctx.account_id, &assume_role.spec.role_name))
        .duration_seconds(
            assume_role
                .spec
                .duration_seconds
                .map_or(DEFAULT_DURATION, |d| d),
        )
        .role_session_name(Uuid::new_v4())
        .send()
        .await
        .map_err(Box::new)?;

    match output.credentials {
        None => Err(NoCredentials),
        Some(c) => Ok(c),
    }
}

async fn credentials(
    credentials: &mut BTreeMap<String, ByteString>,
    aws_credentials: &Credentials,
    assume_role: &AWSAssumeRole,
) -> Result<(), OperatorError> {
    match assume_role.spec.secret_type {
        SecretType::EcrDockerConfigJson => {
            let secret = docker_secret(
                aws_credentials,
                assume_role.spec.ecr_repository_url.as_ref(),
            )
            .await?;

            credentials.insert(".dockerconfigjson".to_string(), value(&secret));
        }
        SecretType::File => {
            credentials.insert("credentials".to_string(), value(&profile(aws_credentials)));
        }
        SecretType::Map => {
            credentials.insert(
                "awsAccessKeyId".to_string(),
                value(&aws_credentials.access_key_id),
            );
            credentials.insert(
                "awsSecretAccessKey".to_string(),
                value(&aws_credentials.secret_access_key),
            );
            credentials.insert(
                "awsSessionToken".to_string(),
                value(&aws_credentials.session_token),
            );
        }
    }

    Ok(())
}

async fn docker_secret(
    aws_credentials: &Credentials,
    repository_url: Option<&String>,
) -> Result<String, OperatorError> {
    match repository_url {
        None => Err(NoRepositoryUrl),
        Some(url) => {
            let token = ecr_token(&ecr_client(aws_credentials).await).await?;

            Ok(ecr_secret(&token, url)?)
        }
    }
}

async fn ecr_client(aws_credentials: &Credentials) -> aws_sdk_ecr::Client {
    let config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(aws_sdk_ecr::config::Credentials::new(
            &aws_credentials.access_key_id,
            &aws_credentials.secret_access_key,
            Option::from(aws_credentials.session_token.clone()),
            None,
            "",
        ))
        .load()
        .await;

    aws_sdk_ecr::Client::new(&config)
}

fn ecr_secret(token: &str, repository_url: &str) -> Result<String, OperatorError> {
    let tok = open_ecr_token(token)?;

    Ok(format!(
        "{{\"auths\":{{\"{0}\":{{\"username\":\"{1}\",\"password\":\"{2}\"}}}}}}",
        repository_url, tok.username, tok.password
    ))
}

async fn ecr_token(client: &aws_sdk_ecr::Client) -> Result<String, OperatorError> {
    let token = client
        .get_authorization_token()
        .send()
        .await
        .map_err(Box::new)?;

    match token
        .authorization_data
        .and_then(|d| d.first().and_then(|f| f.clone().authorization_token))
    {
        None => Err(NoEcrToken),
        Some(t) => Ok(t),
    }
}

fn error_policy(_object: Arc<AWSAssumeRole>, _err: &OperatorError, _ctx: Arc<Data>) -> Action {
    Action::requeue(Duration::from_secs(5))
}

#[tokio::main]
async fn main() -> Result<()> {
    const VERSION: &str = "1.0.1";

    env_logger::init();
    default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let client = Client::try_default().await?;
    let assume_roles = Api::<AWSAssumeRole>::all(client.clone());
    let secrets = Api::<Secret>::all(client.clone());
    let sts_client =
        aws_sdk_sts::Client::new(&aws_config::load_defaults(BehaviorVersion::latest()).await);
    let account_id = account_id(&sts_client).await?;

    info!("Version: {VERSION}");

    Controller::new(assume_roles, watcher::Config::default())
        .owns(secrets, watcher::Config::default())
        .with_config(Config::default().concurrency(1))
        .shutdown_on_signal()
        .run(
            reconcile,
            error_policy,
            Arc::new(Data {
                account_id,
                client,
                sts_client,
            }),
        )
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("Reconciled {o:?}"),
                Err(e) => error!("Reconciliation failed: {}", source_message(&e)),
            }
        })
        .await;

    Ok(())
}

fn name(s: &Option<String>) -> &str {
    s.as_ref().map_or("", |n| n)
}

fn open_ecr_token(token: &str) -> Result<EcrToken, OperatorError> {
    let decoded = BASE64_STANDARD.decode(token)?;
    let parts: Vec<&str> = str::from_utf8(decoded.as_slice())?.split(':').collect();

    if parts.len() == 2 {
        Ok(EcrToken {
            username: parts[0].to_string(),
            password: parts[1].to_string(),
        })
    } else {
        Err(EcrTokenFormat)
    }
}

async fn patch_secret(obj: &AWSAssumeRole, ctx: &Data) -> Result<Secret, OperatorError> {
    let api = Api::<Secret>::namespaced(ctx.client.clone(), name(&obj.metadata.namespace));
    let aws_credentials = aws_credentials(obj, ctx).await?;
    let mut map: BTreeMap<String, ByteString> = BTreeMap::new();

    credentials(&mut map, &aws_credentials, obj).await?;

    let secret = Secret {
        data: Some(map),
        metadata: ObjectMeta {
            name: Some(obj.spec.secret_name.clone()),
            namespace: obj.metadata.namespace.clone(),
            owner_references: Some(Vec::from(
                &*obj.owner_ref(&()).into_iter().collect::<Vec<_>>(),
            )),
            ..ObjectMeta::default()
        },
        type_: Some(secret_type(obj)),
        ..Default::default()
    };

    info!(
        "Updating secret {}",
        &secret.metadata.name.as_ref().unwrap()
    );

    api.patch(
        name(&secret.metadata.name),
        &PatchParams::apply("awsassumerole.pincette.net"),
        &Patch::Apply(&secret),
    )
    .await
    .map_err(|e| OperatorError::SecretCreation(source_message(&e)))
}

async fn patch_status(
    obj: &AWSAssumeRole,
    client: &Client,
) -> Result<AWSAssumeRole, OperatorError> {
    let api = Api::<AWSAssumeRole>::namespaced(client.clone(), name(&obj.metadata.namespace));
    let status = json!({"status": set_ready(obj.status.as_ref())});

    api.patch_status(
        &obj.name_any(),
        &PatchParams::default(),
        &Patch::Merge(&status),
    )
    .await
    .map_err(|e| OperatorError::StatusPatch(source_message(&e)))
}

fn profile(credentials: &Credentials) -> String {
    "[default]\naws_access_key_id=".to_string()
        + credentials.access_key_id()
        + "\naws_secret_access_key="
        + credentials.secret_access_key()
        + "\naws_session_token="
        + credentials.session_token()
}

async fn reconcile(obj: Arc<AWSAssumeRole>, ctx: Arc<Data>) -> Result<Action, OperatorError> {
    let secret_exists = secret_exists(&obj, &ctx.client).await?;

    if should_update(&obj, secret_exists) {
        patch_secret(&obj, &ctx).await?;
        patch_status(&obj, &ctx.client).await?;
    }

    Ok(Action::requeue(Duration::from_secs(60)))
}

fn role_arn(account_id: &str, role_name: &str) -> String {
    "arn:aws:iam::".to_string() + account_id + ":role/" + role_name
}

async fn secret_exists(obj: &AWSAssumeRole, client: &Client) -> Result<bool, OperatorError> {
    let api = Api::<Secret>::namespaced(client.clone(), name(&obj.metadata.namespace));
    let secret = api.get_metadata_opt(&obj.spec.secret_name).await?;

    Ok(secret.is_some())
}

fn secret_type(obj: &AWSAssumeRole) -> String {
    match obj.spec.secret_type {
        SecretType::EcrDockerConfigJson => "kubernetes.io/dockerconfigjson".to_string(),
        _ => "Opaque".to_string(),
    }
}

fn should_update(obj: &AWSAssumeRole, secret_exists: bool) -> bool {
    let last = obj.status.as_ref().and_then(|s| s.last_success());

    !secret_exists || last.is_none() || almost_expired(obj, &last.unwrap())
}

fn source_message(error: &dyn Error) -> String {
    error.source().map_or(error.to_string(), |s| s.to_string())
}

fn value(s: &str) -> ByteString {
    ByteString(s.as_bytes().to_vec())
}
