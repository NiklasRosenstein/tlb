use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

///
/// Define a cluster-scoped tunnel class.
///
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(group = "tlb.io", version = "v1alpha1", kind = "ClusterTunnelClass")]
pub struct ClusterTunnelClassSpec {
    #[serde(flatten)]
    pub inner: TunnelClassInnerSpec,
}

///
/// Define a namespaced tunnel class.
///
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(group = "tlb.io", version = "v1alpha1", kind = "TunnelClass", namespaced)]
pub struct TunnelClassSpec {
    #[serde(flatten)]
    pub inner: TunnelClassInnerSpec,
}

///
/// The inner structure that is shared between [`TunnelClassSpec`] and [`ClusterTunnelClassSpec`].
///
#[derive(Deserialize, Serialize, Default, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TunnelClassInnerSpec {
    pub netbird: Option<NetbirdConfig>,
}

///
/// Configuration for creating Netbird tunnels.
///
#[derive(Deserialize, Serialize, Default, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetbirdConfig {
    pub management_url: String,
    /// The domain used for Netbird DNS, usually `netbird.selfhosted` or `netbird.cloud`. This is
    /// used so we can know the full domain name when using the `tlb.io/dns` annotation. If the
    /// name specified in the annotation is suffixed with this domain, it will be stripped as
    /// Netbird will automatically append it.
    pub netbird_dns_domain: Option<String>,
    pub setup_key_ref: SeretKeyRef,
}

///
/// Reference to a secret key. May be namespaced if used in a [`ClusterTunnelClassSpec`],
/// otherwise the namespace is ignored and the [`TunnelClassSpec`]'s namespace is used.
///
#[derive(Deserialize, Serialize, Default, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SeretKeyRef {
    pub name: String,
    pub namespace: Option<String>,
    pub key: String,
}
