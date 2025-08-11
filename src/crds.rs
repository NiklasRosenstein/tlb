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
    pub cloudflare: Option<CloudflareConfig>,
}

///
/// Configuration for creating Cloudflare tunnels.
///
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CloudflareConfig {
    pub api_token_ref: SeretKeyRef,
    pub account_id: String,
    /// The cloudflared image to use for the tunnel pods. Defaults to `cloudflare/cloudflared:latest`.
    pub image: Option<String>,
    /// Prefix for the resources that are created for the Netbird tunnel. Defaults to `cf-`.
    pub resource_prefix: Option<String>,
    /// Prefix for the name of the Cloudflare tunnel. Defaults to `kube-`.
    pub tunnel_prefix: Option<String>,
    /// How to announce the tunnel DNS name in the Service's `loadBalancerStatus`. Defaults to
    /// [`CloudflareAnnounceType::External`].
    pub announce_type: Option<CloudflareAnnounceType>,
    /// Enable UDP buffer tuning by setting net.core.rmem_max and net.core.wmem_max sysctls.
    /// This resolves the "failed to sufficiently increase receive buffer size" error from cloudflared.
    /// Requires the cluster to allow these sysctls. Defaults to `false` for security reasons.
    pub enable_udp_buffer_tuning: Option<bool>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
pub enum CloudflareAnnounceType {
    /// Expose the tunnel using the internal Cloudflare tunnel name (e.g. `<uuid>.cfargotunnel.com`). This mode is
    /// automatically when no `tlb.io/dns` annotation is set on the Service, or when the Cloudflare API token does not
    /// have permissions to edit the DNS zone.
    ///
    /// This mode only works if something else sets the DNS records, such as external-dns with the Cloudflare provider.
    /// Note that the CNAME DNS record that points to the tunnel _must_ have proxying enabled to work with the
    /// Cloudflare tunnel.
    Internal,
    /// Announce the first DNS name in the `tlb.io/dns` annotation as a CNAME record pointing to the tunnel hostname.
    /// This works best in most cases, but requires that the Cloudflare API token has permissions to edit the DNS zone.
    /// If the DNS zone is not managed by the same Cloudflare account, this will not work. If the DNS zone cannot be
    /// edited, the provider will fall back to [`CloudflareAnnounceType::Internal`].
    External,
}

///
/// Configuration for creating Netbird tunnels.
///
/// Important: The special port [`crate::netbird::NETBIRD_PEER_IP_PORT`] is used to expose the Netbird peer IP in the
/// pod and can therefore not be used by the service that is exposed by the tunnel.
///
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
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
    /// The command to run alias to `netbird up` in the container. Defaults to
    /// [`crate::netbird::DEFAULT_NETBIRD_UP_COMMAND`].
    pub up_command: Option<String>,
    /// How to register the Netbird tunnel in the Service's `loadBalancerStatus`. Defaults to
    /// [`NetbirdAnnounceType::IP`].
    pub announce_type: Option<NetbirdAnnounceType>,
    /// Prefix for the resources that are created for the Netbird tunnel. Defaults to `tunnel-`.
    pub resource_prefix: Option<String>,
    /// The storage class to use for the persistent volume claim. If this is not set, an emptyDir
    /// will be used.
    pub storage_class: Option<String>,
    /// The size of the persistent volume claim. Defaults to `32Mi`. Note that some storage
    /// classes have a minimum size, so you might need to adjust this value.
    pub size: Option<String>,
    /// Enable eBPF capabilities (SYS_ADMIN and SYS_RESOURCE) for the NetBird container.
    /// When enabled, prevents fallback to user space proxy. Defaults to `true`.
    pub enable_ebpf_capabilities: Option<bool>,
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
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SeretKeyRef {
    pub name: String,
    pub namespace: Option<String>,
    pub key: String,
}
