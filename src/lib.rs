use kube::runtime::controller::Action;

pub mod crds;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("SerializationError: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Kube Error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Finalizer Error: {0}")]
    FinalizerError(#[from] Box<kube::runtime::finalizer::Error<Error>>),

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
