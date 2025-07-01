use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

///
/// Define a cluster-scoped tunnel class.
///
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "tlb.io",
    version = "v1alpha1",
    kind = "ClusterTunnelClass",
    namespaced
)]
pub struct ClusterTunnelClassSpec {
    pub netbird: Option<NetbirdConfig>,
}

///
/// Define a namespaced tunnel class.
///
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "tlb.io",
    version = "v1alpha1",
    kind = "TunnelClass",
    namespaced
)]
pub struct TunnelClassSpec {
    pub netbird: Option<NetbirdConfig>,
}

///
/// Configuration for creating Netbird tunnels.
///
#[derive(Deserialize, Serialize, Default, Clone, Debug, JsonSchema)]
pub struct NetbirdConfig {
    #[serde(rename = "managementURL")]
    pub management_url: String,

    #[serde(rename = "setupKeyRef")]
    pub setup_key_ref: SeretKeyRef,
}

///
/// Reference to a secret key. May be namespaced if used in a [`ClusterTunnelClassSpec`],
/// otherwise the namespace is ignored and the [`TunnelClassSpec`]'s namespace is used.
///
#[derive(Deserialize, Serialize, Default, Clone, Debug, JsonSchema)]
pub struct SeretKeyRef {
    pub name: String,
    pub namespace: Option<String>,
    pub key: String,
}
