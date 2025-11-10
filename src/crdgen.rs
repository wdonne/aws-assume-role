use kube::CustomResourceExt;

fn main() {
    print!(
        "{}",
        serde_yaml::to_string(&resource::AWSAssumeRole::crd()).unwrap()
    )
}
