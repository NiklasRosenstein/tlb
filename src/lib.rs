use std::collections::BTreeMap;

use anyhow::Context;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::{Secret, Service};
use kube::{Api, Client, runtime::controller::Action};

use crate::simpleevent::SimpleEventRecorder;

pub mod cloudflare;
pub mod crds;
pub mod netbird;
pub mod pangolin;
pub mod simpleevent;

pub const FOR_TUNNEL_CLASS_LABEL: &str = "controller.tlb.io/for-tunnel-class";
pub const FOR_SERVICE_LABEL: &str = "controller.tlb.io/for-service";
pub const PROVIDER_LABEL: &str = "controller.tlb.io/provider";

#[derive(Clone)]
pub struct ReconcileContext {
    pub client: Client,
    pub events: SimpleEventRecorder,
    pub metadata: kube::api::ObjectMeta,
    pub namespaced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderType {
    Cloudflare,
    Netbird,
    Pangolin,
}

impl ProviderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderType::Cloudflare => "cloudflare",
            ProviderType::Netbird => "netbird",
            ProviderType::Pangolin => "pangolin",
        }
    }
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[async_trait]
pub trait TunnelProvider {
    async fn reconcile_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<()>;
    async fn cleanup_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<()>;
    fn provider_type(&self) -> ProviderType;

    /// Legacy method for backward compatibility - delegates to provider_type()
    fn name(&self) -> &'static str {
        self.provider_type().as_str()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("SerializationError: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Kube Error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Finalizer Error: {0}")]
    FinalizerError(#[from] Box<kube::runtime::finalizer::Error<Error>>),

    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Cloudflare Error: {0}")]
    CloudflareError(String),

    #[error("Configuration Error: {0}")]
    ConfigError(String),

    #[error("An unexpected error occurred: {0}")]
    UnexpectedError(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[async_trait::async_trait]
pub trait Reconcile<C> {
    /// Reconcile the current state with the desired state.
    ///
    /// This method should implement the logic to ensure that the current state of the resource
    /// matches the desired state as defined in the spec.
    async fn reconcile(&self, ctx: &C) -> Result<Action>;
}

/// Represents a single port mapping configuration
#[derive(Debug, Clone, PartialEq)]
pub struct PortMapping {
    /// Port that socat should listen on
    pub listen_port: u16,
    /// Whether to use TLS termination on the listen side (OPENSSL-LISTEN vs TCP-LISTEN)
    pub listen_tls: bool,
    /// Service port (either port number or port name) to forward traffic to
    pub service_port: String,
    /// Whether the service port uses TLS (OPENSSL vs TCP)
    pub service_tls: bool,
    /// Whether to verify TLS certificates when connecting to service (only relevant if service_tls is true)
    pub service_tls_verify: bool,
}

impl PortMapping {
    /// Parse a single port mapping from a string
    /// Format: "(listen-port)[/tls]:(service-port)[/tls[-no-verify]]"
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid port mapping format: '{s}'. Expected 'listen-port:service-port'"
            ));
        }

        let (listen_port, listen_tls) = Self::parse_listen_part(parts[0])?;
        let (service_port, service_tls, service_tls_verify) = Self::parse_service_part(parts[1])?;

        Ok(PortMapping {
            listen_port,
            listen_tls,
            service_port,
            service_tls,
            service_tls_verify,
        })
    }

    fn parse_listen_part(s: &str) -> Result<(u16, bool), String> {
        if let Some(port_str) = s.strip_suffix("/tls") {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("Invalid listen port: '{port_str}'"))?;
            Ok((port, true))
        } else {
            let port = s.parse::<u16>().map_err(|_| format!("Invalid listen port: '{s}'"))?;
            Ok((port, false))
        }
    }

    fn parse_service_part(s: &str) -> Result<(String, bool, bool), String> {
        if let Some(port_str) = s.strip_suffix("/tls-no-verify") {
            Ok((port_str.to_string(), true, false))
        } else if let Some(port_str) = s.strip_suffix("/tls") {
            Ok((port_str.to_string(), true, true))
        } else {
            Ok((s.to_string(), false, true))
        }
    }

    /// Parse multiple port mappings from a comma-separated string
    pub fn parse_multiple(s: &str) -> Result<Vec<Self>, String> {
        s.split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(Self::parse)
            .collect()
    }
}

///
/// Configuration that can be specified as annotations on the Service object.
///
#[derive(Default, Clone, Debug)]
pub struct ServiceAnnotations {
    /// A comma-separated list of DNS names that should be assigned to the tunnel. The behaviour
    /// of this annotation may vary slightly based on the implementation of the tunnel class.
    pub dns: Option<String>,

    /// The number of tunnel replicas to deploy. Defaults to 1.
    pub replicas: i32,

    /// A topology key that can be used to spread the tunnel replicas across different nodes.
    /// Defaults to `kubernetes.io/hostname`.
    pub topology_key: Option<String>,

    /// A comma-separated list of node labels to use as node selectors for the tunnel pods.
    pub node_selector: Option<String>,

    /// Port mapping configuration for advanced forwarding and TLS termination.
    /// Format: "(listen-port)[/tls]:(service-port)[/tls[-no-verify]]"
    /// Multiple mappings can be comma-separated.
    /// Examples: "80:http", "443/tls:http", "443/tls:5001/tls-no-verify"
    pub map_ports: Option<String>,

    /// Name of the Kubernetes secret containing TLS certificate for termination.
    /// Used when any port mapping specifies TLS termination.
    pub tls_secret_name: Option<String>,
}

impl From<BTreeMap<String, String>> for ServiceAnnotations {
    fn from(annotations: BTreeMap<String, String>) -> Self {
        // TODO: Can we use serde?
        let dns = annotations.get("tlb.io/dns").cloned();
        let replicas = annotations
            .get("tlb.io/replicas")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let topology_key = annotations.get("tlb.io/topology-key").cloned();
        let node_selector = annotations.get("tlb.io/node-selector").cloned();
        let map_ports = annotations.get("tlb.io/map-ports").cloned();
        let tls_secret_name = annotations.get("tlb.io/tls-secret-name").cloned();

        ServiceAnnotations {
            dns,
            replicas,
            topology_key,
            node_selector,
            map_ports,
            tls_secret_name,
        }
    }
}

/// Fetches a secret from the Kubernetes API. This is a shared function used by multiple providers.
pub async fn get_secret(
    client: &Client,
    secret_ref: &crate::crds::SeretKeyRef,
    fallback_ns: &str,
) -> anyhow::Result<Secret> {
    let ns = secret_ref.namespace.as_deref().unwrap_or(fallback_ns);
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), ns);
    secret_api.get(&secret_ref.name).await.context(format!(
        "Failed to get secret '{}' in namespace '{}'",
        secret_ref.name, ns
    ))
}

/// Fetches a secret value from the Kubernetes API. This is a shared function used by multiple providers.
/// Returns the decoded string value from the specified key in the secret.
pub async fn get_secret_value(
    client: &Client,
    secret_ref: &crate::crds::SeretKeyRef,
    fallback_ns: &str,
) -> anyhow::Result<String> {
    let secret = get_secret(client, secret_ref, fallback_ns).await?;

    let data = secret
        .data
        .ok_or_else(|| anyhow::anyhow!("Secret '{}' has no data", secret_ref.name))?;
    let value_bytes = data
        .get(&secret_ref.key)
        .ok_or_else(|| anyhow::anyhow!("Secret '{}' does not contain key '{}'", secret_ref.name, secret_ref.key))?;

    String::from_utf8(value_bytes.0.clone()).context(format!(
        "Secret '{}' key '{}' contains invalid UTF-8",
        secret_ref.name, secret_ref.key
    ))
}

/// Creates pod affinity rules to prefer scheduling tunnel pods on nodes where target service pods are running.
/// This improves locality between tunnel pods and the services they proxy to.
pub fn build_pod_affinity_for_service(service: &Service) -> Option<k8s_openapi::api::core::v1::PodAffinity> {
    use k8s_openapi::api::core::v1::{PodAffinity, PodAffinityTerm, WeightedPodAffinityTerm};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;

    // Extract the selector from the service spec
    let selector = service.spec.as_ref()?.selector.as_ref()?;

    if selector.is_empty() {
        return None;
    }

    // Create a pod affinity term to prefer nodes where target service pods are running
    let affinity_term = PodAffinityTerm {
        label_selector: Some(LabelSelector {
            match_labels: Some(selector.clone()),
            match_expressions: None,
        }),
        topology_key: "kubernetes.io/hostname".to_string(),
        namespace_selector: None,
        namespaces: None,
        match_label_keys: None,
        mismatch_label_keys: None,
    };

    // Use preferred affinity so it's a preference, not a hard requirement
    // This allows tunnel pods to still be scheduled even if target pods are not available
    Some(PodAffinity {
        preferred_during_scheduling_ignored_during_execution: Some(vec![WeightedPodAffinityTerm {
            weight: 100, // High weight to strongly prefer co-location
            pod_affinity_term: affinity_term,
        }]),
        required_during_scheduling_ignored_during_execution: None,
    })
}
