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
    /// Reference to secret containing Cloudflare API token. Required for API mode, ignored for Quick mode.
    pub api_token_ref: Option<SeretKeyRef>,
    /// Cloudflare account ID. Required for API mode, ignored for Quick mode.
    pub account_id: Option<String>,
    /// The cloudflared image to use for the tunnel pods. Defaults to `cloudflare/cloudflared:latest`.
    /// An explicit value requires the controller unsafe-workload opt-in.
    pub image: Option<String>,
    /// Edge transport. Use HTTP/2 when outbound UDP is unavailable.
    #[serde(default)]
    pub transport_protocol: CloudflareTransportProtocol,
    /// Prefix for Cloudflare Kubernetes resources. Immutable while a Service is bound. Defaults to `cf-`.
    pub resource_prefix: Option<String>,
    /// Prefix for the name of the Cloudflare tunnel. Defaults to `kube-`. Only used in API mode.
    pub tunnel_prefix: Option<String>,
    /// How to announce the tunnel DNS name in the Service's `loadBalancerStatus`. Defaults to
    /// [`CloudflareAnnounceType::External`].
    pub announce_type: Option<CloudflareAnnounceType>,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CloudflareTransportProtocol {
    #[default]
    Auto,
    Quic,
    Http2,
}

impl AsRef<str> for CloudflareTransportProtocol {
    fn as_ref(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Quic => "quic",
            Self::Http2 => "http2",
        }
    }
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
    /// Reconcile Service hostnames in an existing NetBird custom DNS zone.
    pub custom_dns: Option<NetbirdCustomDnsConfig>,
    /// The domain used for Netbird DNS, usually `netbird.selfhosted` or `netbird.cloud`. This is
    /// used so we can know the full domain name when using the `tlb.io/dns` annotation. If the
    /// name specified in the annotation is suffixed with this domain, it will be stripped as
    /// Netbird will automatically append it.
    pub netbird_dns_domain: Option<String>,
    /// The netbird image to use for the tunnel pods. Defaults to `netbirdio/netbird:latest`.
    /// An explicit value requires the controller unsafe-workload opt-in. The image must have
    /// BusyBox-compatible `nc` installed to export the Netbird peer IP to the controller.
    pub image: Option<String>,
    /// The cluster interface that handles outgoing traffic into the target service. Defaults to `eth0`.
    pub cluster_interface: Option<String>,
    /// The netbird interface that is created by running `netbird up` in the container. Defaults to `wt0`.
    pub netbird_interface: Option<String>,
    /// The command to run alias to `netbird up` in the container. An explicit value requires
    /// the controller unsafe-workload opt-in. Defaults to
    /// [`crate::netbird::DEFAULT_NETBIRD_UP_COMMAND`].
    pub up_command: Option<String>,
    /// How to register the Netbird tunnel in the Service's `loadBalancerStatus`. Defaults to
    /// [`NetbirdAnnounceType::IP`].
    pub announce_type: Option<NetbirdAnnounceType>,
    /// Prefix for NetBird Kubernetes resources. Immutable while a Service is bound. Defaults to `tunnel-`.
    pub resource_prefix: Option<String>,
    /// The storage class to use for the persistent volume claim. If this is not set, an emptyDir
    /// will be used.
    pub storage_class: Option<String>,
    /// The size of the persistent volume claim. Defaults to `32Mi`. Note that some storage
    /// classes have a minimum size, so you might need to adjust this value.
    pub size: Option<String>,
    /// Enable eBPF capabilities (SYS_ADMIN and SYS_RESOURCE) for the NetBird container.
    /// Requires the controller unsafe-workload opt-in. Defaults to `false`.
    pub enable_ebpf_capabilities: Option<bool>,
}

/// DNS credentials remain private to the controller; Services reserve complete A-record sets.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetbirdCustomDnsConfig {
    /// REST API root. Defaults to managementUrl with /api appended.
    pub api_url: Option<String>,
    pub api_token_ref: SeretKeyRef,
    pub zone_id: String,
    #[serde(default = "default_dns_ttl")]
    #[schemars(range(min = 1, max = 2147483647))]
    pub ttl: u32,
}

pub fn default_dns_ttl() -> u32 {
    60
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
/// a [`TunnelClassSpec`] must reference its own namespace; foreign namespaces are rejected.
///
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SeretKeyRef {
    pub name: String,
    pub namespace: Option<String>,
    pub key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_transport_defaults_and_validates() {
        let default: CloudflareConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(default.transport_protocol.as_ref(), "auto");
        for protocol in ["auto", "quic", "http2"] {
            let config: CloudflareConfig =
                serde_json::from_value(serde_json::json!({ "transportProtocol": protocol })).unwrap();
            assert_eq!(config.transport_protocol.as_ref(), protocol);
            assert_eq!(serde_json::to_value(config).unwrap()["transportProtocol"], protocol);
        }
        assert!(
            serde_json::from_value::<CloudflareConfig>(serde_json::json!({
                "transportProtocol": "https"
            }))
            .is_err()
        );
    }
}
