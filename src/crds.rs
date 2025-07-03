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
    pub setup_key_ref: SeretKeyRef,
    /// The domain used for Netbird DNS, usually `netbird.selfhosted` or `netbird.cloud`. This is
    /// used so we can know the full domain name when using the `tlb.io/dns` annotation. If the
    /// name specified in the annotation is suffixed with this domain, it will be stripped as
    /// Netbird will automatically append it.
    pub netbird_dns_domain: Option<String>,
    /// The netbird image to use for the tunnel pods. Defaults to `netbirdio/netbird:latest`. Note that the image
    /// must have `nc` installed that is BusyBox compatible, as it is used to export the Netbird peer IP to the
    /// controller.
    pub image: Option<String>,
    /// The cluster interface that handles outgoing traffic into the target service. Defaults to `eth0`.
    pub cluster_interface: Option<String>,
    /// The netbird interface that is created by running `netbird up` in the container. Defaults to `wt0`.
    pub netbird_interface: Option<String>,
    /// The command to run alias to `netbird up` in the container. Defaults to `netbird up`.
    pub up_command: Option<String>,
    /// How to register the Netbird tunnel in the Service's `loadBalancerStatus`. Defaults to
    /// [`NetbirdAnnounceType::IP`].
    pub announce_type: Option<NetbirdAnnounceType>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
pub enum NetbirdAnnounceType {
    /// Expose the tunnel using the IP address(es) of the Netbird peers.
    IP,
    /// Expose the tunnel using the common hostname of the Netbird peers (requires that the `tlb.io/dns` annotation
    /// is set on the exposed service). Note that when using this in a `CNAME` entry, the hostname must be resolvable
    /// by your client's DNS server. This is because `CNAME` records are not resolved by the client, but by the DNS
    /// server. Hence, this option cannot usually be used with a public DNS server like Google DNS, Cloudflare DNS, etc.
    #[allow(clippy::upper_case_acronyms)]
    DNS,
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
