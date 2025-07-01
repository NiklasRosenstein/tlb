//! Simplification of the event publishing API.

use std::sync::Arc;

use k8s_openapi::api::core::v1::ObjectReference;
use kube::runtime::events::{Event, EventType, Recorder, Reporter};

///
/// A simplified API for publishing events in a Kubernetes controller.
///
#[derive(Clone)]
pub struct SimpleEventRecorder {
    recorder: Arc<Recorder>,
}

impl SimpleEventRecorder {
    pub fn new(recorder: Recorder) -> Self {
        Self {
            recorder: Arc::new(recorder),
        }
    }

    /// Creates a new `SimpleEventRecorder` from a Kubernetes client and a reporter.
    ///
    /// # Example
    /// ```rust
    /// #[tokio::main]
    /// async fn main() {
    ///     use tlb::simpleevent::SimpleEventRecorder;
    ///     let client = kube::Client::try_default().await.unwrap();
    ///     let events = SimpleEventRecorder::from_client(client, "my-controller");
    /// }
    /// ```
    pub fn from_client<R: Into<Reporter>>(client: kube::Client, reporter: R) -> Self {
        let recorder = Recorder::new(client, reporter.into());
        Self {
            recorder: Arc::new(recorder),
        }
    }

    pub async fn publish(
        &self,
        object_ref: &ObjectReference,
        event_type: EventType,
        reason: String,
        note: Option<String>,
        action: String,
    ) -> Result<(), kube_client::Error> {
        self.recorder
            .publish(
                &Event {
                    type_: event_type,
                    reason,
                    note,
                    action,
                    secondary: None,
                },
                object_ref,
            )
            .await
    }
}
