use crate::{
    ReconcileContext,
    simpleevent::SimpleEventRecorder,
    state::{Binding, BindingData, ClassSnapshot},
};
use kube::{Client, client::Body};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

pub struct Exchange {
    pub method: &'static str,
    pub path: &'static str,
    pub status: u16,
    pub response: Value,
    pub check: fn(&Value),
}

pub fn mock(exchanges: Vec<Exchange>) -> (Client, Arc<Mutex<VecDeque<Exchange>>>) {
    let pending = Arc::new(Mutex::new(VecDeque::from(exchanges)));
    let queue = pending.clone();
    let service = tower::service_fn(move |request: http::Request<Body>| {
        let queue = queue.clone();
        async move {
            let expected = queue.lock().unwrap().pop_front().expect("unexpected API request");
            assert_eq!(request.method().as_str(), expected.method);
            assert_eq!(request.uri().path(), expected.path);
            let bytes = request.into_body().collect_bytes().await.unwrap();
            (expected.check)(&if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            });
            Ok::<_, std::io::Error>(
                http::Response::builder()
                    .status(expected.status)
                    .body(Body::from(if expected.path.ends_with("/log") {
                        expected
                            .response
                            .as_str()
                            .expect("log response must be text")
                            .as_bytes()
                            .to_vec()
                    } else {
                        serde_json::to_vec(&expected.response).unwrap()
                    }))
                    .unwrap(),
            )
        }
    });
    (Client::new(service, "default"), pending)
}

pub fn context(client: Client) -> ReconcileContext {
    let class: ClassSnapshot = serde_json::from_value(json!({
        "metadata": {"name":"public", "namespace":"apps", "uid":"class-uid"},
        "namespaced":true, "spec":{"cloudflare":{}}
    }))
    .unwrap();
    ReconcileContext {
        dns_lock: Default::default(),
        external_refresh: std::time::Duration::from_secs(300),
        events: SimpleEventRecorder::from_client(client.clone(), "test"),
        client,
        metadata: class.metadata.clone(),
        namespaced: true,
        binding: Binding {
            secret: serde_json::from_value(json!({"metadata":{"name":"tlb-service-uid", "namespace":"tlb-system",
                "uid":"12345678-1234-1234-1234-123456789012", "resourceVersion":"1"}}))
            .unwrap(),
            data: BindingData {
                workload_namespace: "apps".into(),
                workload_owner: Some(serde_json::from_value(json!({"apiVersion":"v1","kind":"ConfigMap","name":"owner","uid":"owner-uid","controller":true,"blockOwnerDeletion":true})).unwrap()),
                service: serde_json::from_value(json!({"metadata":{"name":"api", "namespace":"apps",
                    "uid":"service-uid", "resourceVersion":"1"}, "spec":{"type":"LoadBalancer",
                    "clusterIP":"10.0.0.1", "loadBalancerClass":"tlb.io/public", "ports":[{"port":80}]}}))
                .unwrap(),
                class,
                credentials: Default::default(),
                cleaning: false,
                cloudflare: Default::default(),
                netbird_dns: Default::default(),
            },
        },
    }
}
