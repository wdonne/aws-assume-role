use k8s_openapi::serde::{Deserialize, Serialize};
use kube::CustomResource;
use kube_operator_util::status::Status;
use schemars::JsonSchema;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    kind = "AWSAssumeRole",
    group = "pincette.net",
    version = "v1",
    namespaced,
    category = "controllers",
    shortname = "aar",
    printcolumn = r#"{"name":"Health", "type":"string", "jsonPath":".status.health.status"}"#,
    printcolumn = r#"{"name":"Phase", "type":"string", "jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age", "type":"date", "jsonPath":".metadata.creationTimestamp"}"#
)]
#[kube(status = "Status")]
#[serde(rename_all = "camelCase")]
pub struct AWSAssumeRoleSpec {
    pub duration_seconds: Option<i32>,
    pub ecr_repository_url: Option<String>,
    pub role_name: String,
    pub secret_name: String,
    pub secret_type: SecretType,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub enum SecretType {
    EcrDockerConfigJson,
    File,
    Map,
}
