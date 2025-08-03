use std::collections::BTreeMap;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Service;
use kube::{Client, runtime::controller::Action};

use crate::simpleevent::SimpleEventRecorder;

pub mod cloudflare;
pub mod crds;
pub mod netbird;
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

#[async_trait]
pub trait TunnelProvider {
    async fn reconcile_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<()>;
    async fn cleanup_service(&self, ctx: &ReconcileContext, service: &Service) -> Result<()>;
    fn name(&self) -> &'static str;
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

        ServiceAnnotations {
            dns,
            replicas,
            topology_key,
            node_selector,
        }
    }
}
