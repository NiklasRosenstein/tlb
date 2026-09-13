use super::*;
use crate::test_support::context;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Remote {
    records: BTreeMap<String, Vec<Value>>,
    disabled: BTreeSet<String>,
    missing: BTreeSet<String>,
    calls: Vec<(String, String)>,
    drop_post: bool,
    fail_delete: bool,
    status: Option<u16>,
    next_id: usize,
}
struct Kubernetes {
    journal: Secret,
    others: Vec<Secret>,
    service: Service,
    token: Option<String>,
    fail_id_save: bool,
    writes: usize,
}
struct Harness {
    base: ReconcileContext,
    kube: Arc<Mutex<Kubernetes>>,
    remote: Arc<Mutex<Remote>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Harness {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let root = format!("http://{}/api", listener.local_addr().unwrap());
        let remote = Arc::new(Mutex::new(Remote::default()));
        let state = remote.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(
                        tokio::time::timeout(Duration::from_secs(2), socket.read_u8())
                            .await
                            .unwrap()
                            .unwrap(),
                    );
                    assert!(headers.len() < 16384);
                }
                let headers = String::from_utf8(headers).unwrap();
                assert!(headers.to_lowercase().contains("authorization: token "));
                let mut line = headers.lines().next().unwrap().split_whitespace();
                let method = line.next().unwrap().to_owned();
                let path = line.next().unwrap().to_owned();
                let length = headers
                    .lines()
                    .find_map(|l| {
                        l.to_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|n| n.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut body = vec![0; length];
                tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut body))
                    .await
                    .unwrap()
                    .unwrap();
                let body: Value = if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&body).unwrap()
                };
                let (status, response, drop_response) = {
                    let mut remote = state.lock().unwrap();
                    remote.calls.push((method.clone(), path.clone()));
                    let parts: Vec<_> = path.split('/').collect();
                    assert_eq!(&parts[..4], &["", "api", "dns", "zones"]);
                    let zone = parts[4].to_owned();
                    if let Some(status) = remote.status {
                        (status, json!({}), false)
                    } else if remote.missing.contains(&zone) {
                        (404, json!({}), false)
                    } else if parts.len() == 5 {
                        (
                            200,
                            json!({"domain":"private.example.com", "enabled":!remote.disabled.contains(&zone)}),
                            false,
                        )
                    } else {
                        let id = parts.get(6).copied();
                        match method.as_str() {
                            "GET" => (200, json!(remote.records.entry(zone).or_default()), false),
                            "POST" => {
                                remote.next_id += 1;
                                let mut record = body;
                                record["id"] = json!(format!("record-{}", remote.next_id));
                                remote.records.entry(zone).or_default().push(record.clone());
                                let dropped = std::mem::take(&mut remote.drop_post);
                                (200, record, dropped)
                            }
                            "PUT" => {
                                let record = remote
                                    .records
                                    .entry(zone)
                                    .or_default()
                                    .iter_mut()
                                    .find(|r| r["id"] == id.unwrap())
                                    .unwrap();
                                *record = body;
                                record["id"] = json!(id.unwrap());
                                (200, record.clone(), false)
                            }
                            "DELETE" if remote.fail_delete => (503, json!({}), false),
                            "DELETE" => {
                                remote
                                    .records
                                    .entry(zone)
                                    .or_default()
                                    .retain(|r| r["id"] != id.unwrap());
                                (204, Value::Null, false)
                            }
                            _ => panic!("unexpected request {method} {path}"),
                        }
                    }
                };
                if drop_response {
                    continue;
                }
                let response = response.to_string();
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                            response.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let (placeholder, _) = crate::test_support::mock(vec![]);
        let mut base = context(placeholder);
        base.binding.data.class.spec = serde_json::from_value(json!({"netbird":{
            "managementUrl":"https://management.example.com", "setupKeyRef":{"name":"enrollment","key":"key"},
            "customDns":{"apiUrl":root,"apiTokenRef":{"name":"dns-token","key":"token"},"zoneId":"zone","ttl":60}
        }}))
        .unwrap();
        base.binding.data.service.metadata.annotations =
            Some(BTreeMap::from([(HOSTNAMES.into(), "app.private.example.com".into())]));
        base.binding.secret.metadata.labels = Some(BTreeMap::from([
            (JOURNAL_LABEL.into(), "true".into()),
            (crate::state::SERVICE_UID_LABEL.into(), "service-uid".into()),
            (crate::state::CLASS_UID_LABEL.into(), "class-uid".into()),
        ]));
        base.binding.secret.data = Some(BTreeMap::from([(
            "binding.json".into(),
            k8s_openapi::ByteString(serde_json::to_vec(&base.binding.data).unwrap()),
        )]));
        let kube = Arc::new(Mutex::new(Kubernetes {
            journal: base.binding.secret.clone(),
            others: vec![],
            service: base.binding.data.service.clone(),
            token: Some("secret-token".into()),
            fail_id_save: false,
            writes: 0,
        }));
        let state = kube.clone();
        base.client = kube::Client::new(
            tower::service_fn(move |request: http::Request<kube::client::Body>| {
                let state = state.clone();
                async move {
                    let method = request.method().to_string();
                    let path = request.uri().path().to_owned();
                    let body = request.into_body().collect_bytes().await.unwrap();
                    let body: Value = if body.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(&body).unwrap()
                    };
                    let mut state = state.lock().unwrap();
                    let mut status = 200;
                    let response = match (method.as_str(), path.as_str()) {
                        ("GET", "/api/v1/namespaces/apps/secrets/dns-token") => match &state.token {
                            Some(token) => {
                                json!({"data":{"token":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,token)}})
                            }
                            None => {
                                status = 404;
                                json!({"kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"missing"})
                            }
                        },
                        ("GET", "/api/v1/namespaces/tlb-system/secrets") => {
                            let mut items = state.others.clone();
                            items.push(state.journal.clone());
                            json!({"items":items})
                        }
                        ("PUT", path) if path.starts_with("/api/v1/namespaces/tlb-system/secrets/") => {
                            let mut secret: Secret = serde_json::from_value(body).unwrap();
                            let binding = Binding::from_secret(secret.clone()).unwrap();
                            let has_ids = binding
                                .data
                                .netbird_dns
                                .targets
                                .iter()
                                .any(|t| t.names.values().any(|ids| !ids.is_empty()));
                            if state.fail_id_save && has_ids {
                                state.fail_id_save = false;
                                status = 409;
                                json!({"kind":"Status","status":"Failure","reason":"Conflict","code":409,"message":"interrupted save"})
                            } else {
                                let current = if secret.name_any() == state.journal.name_any() {
                                    &state.journal
                                } else {
                                    state.others.iter().find(|s| s.name_any() == secret.name_any()).unwrap()
                                };
                                assert_eq!(secret.resource_version(), current.resource_version());
                                state.writes += 1;
                                secret.metadata.resource_version = Some((state.writes + 1).to_string());
                                if secret.name_any() == state.journal.name_any() {
                                    state.journal = secret.clone();
                                } else {
                                    *state
                                        .others
                                        .iter_mut()
                                        .find(|s| s.name_any() == secret.name_any())
                                        .unwrap() = secret.clone();
                                }
                                json!(secret)
                            }
                        }
                        ("GET", "/api/v1/namespaces/apps/services/api") => json!(state.service),
                        ("PATCH", "/api/v1/namespaces/apps/services/api/status") => {
                            let conditions = serde_json::from_value(body["status"]["conditions"].clone()).unwrap();
                            state.service.status.get_or_insert_default().conditions = Some(conditions);
                            json!(state.service)
                        }
                        _ => panic!("unexpected Kubernetes request {method} {path}"),
                    };
                    Ok::<_, std::io::Error>(
                        http::Response::builder()
                            .status(status)
                            .body(kube::client::Body::from(response.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "apps",
        );
        Self {
            base,
            kube,
            remote,
            task,
        }
    }
    fn ctx(&self) -> ReconcileContext {
        let mut ctx = self.base.clone();
        ctx.binding = Binding::from_secret(self.kube.lock().unwrap().journal.clone()).unwrap();
        ctx
    }
    async fn run(&self, ctx: &ReconcileContext, observations: PeerObservations) -> Result<()> {
        reconcile(
            ctx,
            ctx.binding.data.class.spec.netbird.as_ref().unwrap(),
            &ctx.binding.data.service,
            &observations,
        )
        .await
    }
    fn records(&self, zone: &str) -> Vec<Value> {
        self.remote
            .lock()
            .unwrap()
            .records
            .get(zone)
            .cloned()
            .unwrap_or_default()
    }
    fn mutations(&self) -> usize {
        self.remote
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|(m, _)| m != "GET")
            .count()
    }
}
fn peers(values: &[(&str, Option<&str>)]) -> PeerObservations {
    PeerObservations {
        eligible: values
            .iter()
            .map(|(uid, ip)| (uid.to_string(), ip.map(str::to_owned)))
            .collect(),
    }
}
fn a(id: &str, name: &str, content: &str, ttl: u32) -> Value {
    json!({"id":id,"name":name,"type":"A","content":content,"ttl":ttl})
}

#[test]
fn urls_and_names_are_explicit_and_bounded() {
    assert_eq!(
        api_root("https://nb.example.com/", None).unwrap(),
        "https://nb.example.com/api"
    );
    assert_eq!(
        api_root("https://nb.example.com:8443/manage///", None).unwrap(),
        "https://nb.example.com:8443/manage/api"
    );
    assert_eq!(
        api_root("https://nb.example.com", Some("https://rest.example.com/v1/")).unwrap(),
        "https://rest.example.com/v1"
    );
    for url in [
        "ftp://nb.example.com",
        "https://user:pass@nb.example.com",
        "https://nb.example.com?x=1",
        "https://nb.example.com#x",
    ] {
        assert!(api_root(url, None).is_err());
    }
    let mut service = Service::default();
    service.metadata.annotations = Some(BTreeMap::from([(
        HOSTNAMES.into(),
        " APP.Private.Example.COM.,app.private.example.com ".into(),
    )]));
    assert_eq!(
        hostnames(&service).unwrap(),
        BTreeSet::from(["app.private.example.com".into()])
    );
    for value in [
        "*.private.example.com",
        "a.private.example.com,",
        "a.private.example.com..",
        "short",
        "bad_name.private.example.com",
    ] {
        service
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert(HOSTNAMES.into(), value.into());
        assert!(hostnames(&service).is_err());
    }
}

#[tokio::test]
async fn adopts_repairs_and_removes_only_reserved_a_records_idempotently() {
    let h = Harness::new().await;
    h.remote.lock().unwrap().records.insert(
        "zone".into(),
        vec![
            a("adopt", "app.private.example.com", "100.64.0.1", 300),
            a("stale", "app.private.example.com", "100.64.0.9", 60),
            a("unrelated", "other.private.example.com", "100.64.0.9", 60),
        ],
    );
    let observed = || peers(&[("p1", Some("100.64.0.1")), ("p2", Some("100.64.0.2"))]);
    h.run(&h.ctx(), observed()).await.unwrap();
    let records = h.records("zone");
    assert_eq!(records.len(), 3);
    assert!(records.iter().any(|r| r["id"] == "adopt" && r["ttl"] == 60));
    assert!(records.iter().any(|r| r["id"] == "unrelated"));
    let mutations = h.mutations();
    let writes = h.kube.lock().unwrap().writes;
    h.run(&h.ctx(), observed()).await.unwrap();
    assert_eq!(h.mutations(), mutations);
    assert_eq!(h.kube.lock().unwrap().writes, writes);
    cleanup(&h.ctx()).await.unwrap();
    assert_eq!(
        h.records("zone"),
        vec![a("unrelated", "other.private.example.com", "100.64.0.9", 60)]
    );
    assert!(h.ctx().binding.data.netbird_dns.targets.is_empty());
}

#[tokio::test]
async fn partial_discovery_retains_only_eligible_cached_peers_and_zero_peers_clears_records() {
    let h = Harness::new().await;
    h.run(
        &h.ctx(),
        peers(&[("p1", Some("100.64.0.1")), ("p2", Some("100.64.0.2"))]),
    )
    .await
    .unwrap();
    assert!(h.run(&h.ctx(), peers(&[("p1", None)])).await.is_err());
    assert_eq!(h.records("zone").len(), 1);
    assert_eq!(h.records("zone")[0]["content"], "100.64.0.1");
    h.run(&h.ctx(), peers(&[])).await.unwrap();
    assert!(h.records("zone").is_empty());
    assert_eq!(
        h.kube
            .lock()
            .unwrap()
            .service
            .status
            .as_ref()
            .unwrap()
            .conditions
            .as_ref()
            .unwrap()[0]
            .reason,
        "NoReadyPeers"
    );
}

#[tokio::test]
async fn lost_creation_response_and_failed_journal_save_recover_without_duplicate_posts() {
    for lose_response in [true, false] {
        let h = Harness::new().await;
        h.remote.lock().unwrap().drop_post = lose_response;
        h.kube.lock().unwrap().fail_id_save = !lose_response;
        assert!(h.run(&h.ctx(), peers(&[("p", Some("100.64.0.1"))])).await.is_err());
        assert_eq!(h.records("zone").len(), 1);
        assert!(
            h.ctx().binding.data.netbird_dns.targets[0]
                .names
                .contains_key("app.private.example.com")
        );
        h.run(&h.ctx(), peers(&[("p", Some("100.64.0.1"))])).await.unwrap();
        assert_eq!(h.records("zone").len(), 1);
        assert_eq!(
            h.remote
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|(m, _)| m == "POST")
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn destination_failure_preserves_previous_target_and_repeated_migration_cleans_all_history() {
    let h = Harness::new().await;
    h.run(&h.ctx(), peers(&[("p", Some("100.64.0.1"))])).await.unwrap();
    let mut ctx = h.ctx();
    ctx.binding
        .data
        .class
        .spec
        .netbird
        .as_mut()
        .unwrap()
        .custom_dns
        .as_mut()
        .unwrap()
        .zone_id = "second".into();
    h.remote.lock().unwrap().disabled.insert("second".into());
    assert!(h.run(&ctx, peers(&[("p", Some("100.64.0.1"))])).await.is_err());
    assert_eq!(h.records("zone").len(), 1);
    h.remote.lock().unwrap().disabled.clear();
    h.remote.lock().unwrap().fail_delete = true;
    assert!(h.run(&ctx, peers(&[("p", Some("100.64.0.1"))])).await.is_err());
    assert_eq!(h.ctx().binding.data.netbird_dns.targets.len(), 2);
    let mut ctx = h.ctx();
    ctx.binding
        .data
        .class
        .spec
        .netbird
        .as_mut()
        .unwrap()
        .custom_dns
        .as_mut()
        .unwrap()
        .zone_id = "third".into();
    h.remote.lock().unwrap().fail_delete = false;
    h.run(&ctx, peers(&[("p", Some("100.64.0.1"))])).await.unwrap();
    assert!(h.records("zone").is_empty());
    assert!(h.records("second").is_empty());
    assert_eq!(h.records("third").len(), 1);
    assert_eq!(h.ctx().binding.data.netbird_dns.targets.len(), 1);
}

#[tokio::test]
async fn conflicting_types_and_competing_reservations_are_preserved() {
    let h = Harness::new().await;
    let cname =
        json!({"id":"foreign","name":"app.private.example.com","type":"CNAME","content":"other.example.com","ttl":60});
    h.remote
        .lock()
        .unwrap()
        .records
        .insert("zone".into(), vec![cname.clone()]);
    assert!(matches!(
        h.run(&h.ctx(), peers(&[("p", Some("100.64.0.1"))])).await,
        Err(Error::NetbirdDnsError { reason: "Conflict", .. })
    ));
    assert_eq!(h.mutations(), 0);
    assert_eq!(h.records("zone"), vec![cname]);
    let mut other = h.ctx().binding;
    other.secret.metadata.uid = Some("other-binding".into());
    other.secret.metadata.name = Some("tlb-other-service".into());
    other.data.service.metadata.uid = Some("other-service".into());
    other
        .secret
        .metadata
        .labels
        .as_mut()
        .unwrap()
        .insert(crate::state::SERVICE_UID_LABEL.into(), "other-service".into());
    other.secret.data.as_mut().unwrap().insert(
        "binding.json".into(),
        k8s_openapi::ByteString(serde_json::to_vec(&other.data).unwrap()),
    );
    h.kube.lock().unwrap().others.push(other.secret);
    h.remote.lock().unwrap().records.clear();
    assert!(matches!(
        h.run(&h.ctx(), peers(&[("p", Some("100.64.0.1"))])).await,
        Err(Error::NetbirdDnsError { reason: "Conflict", .. })
    ));
    assert_eq!(h.mutations(), 0);
}

#[tokio::test]
async fn disabled_configuration_cleans_with_snapshotted_credentials_after_secret_deletion() {
    let h = Harness::new().await;
    h.run(&h.ctx(), peers(&[("p", Some("100.64.0.1"))])).await.unwrap();
    h.kube.lock().unwrap().token = None;
    let mut ctx = h.ctx();
    ctx.binding.data.class.spec.netbird.as_mut().unwrap().custom_dns = None;
    assert!(h.run(&ctx, peers(&[])).await.is_err()); // Declarations without DNS configuration are invalid.
    assert!(h.records("zone").is_empty());
    assert!(h.ctx().binding.data.netbird_dns.targets.is_empty());
}

#[tokio::test]
async fn missing_zone_is_cleanup_success_and_invalid_zone_names_do_not_reserve() {
    let h = Harness::new().await;
    let mut ctx = h.ctx();
    ctx.binding
        .data
        .service
        .metadata
        .annotations
        .as_mut()
        .unwrap()
        .insert(HOSTNAMES.into(), "outside.example.org".into());
    assert!(h.run(&ctx, peers(&[])).await.is_err());
    assert!(h.ctx().binding.data.netbird_dns.targets.is_empty());
    h.run(&h.ctx(), peers(&[("p", Some("100.64.0.1"))])).await.unwrap();
    h.remote.lock().unwrap().missing.insert("zone".into());
    cleanup(&h.ctx()).await.unwrap();
    assert!(h.ctx().binding.data.netbird_dns.targets.is_empty());
}

#[tokio::test]
async fn simultaneous_services_cannot_claim_the_same_name() {
    let h = Harness::new().await;
    let first = h.ctx();
    let mut second = first.clone();
    second.binding.secret.metadata.uid = Some("other-binding".into());
    second.binding.secret.metadata.name = Some("tlb-other-service".into());
    second.binding.data.service.metadata.uid = Some("other-service".into());
    second
        .binding
        .secret
        .metadata
        .labels
        .as_mut()
        .unwrap()
        .insert(crate::state::SERVICE_UID_LABEL.into(), "other-service".into());
    second.binding.secret.data.as_mut().unwrap().insert(
        "binding.json".into(),
        k8s_openapi::ByteString(serde_json::to_vec(&second.binding.data).unwrap()),
    );
    h.kube.lock().unwrap().others.push(second.binding.secret.clone());
    let (a, b) = tokio::join!(
        h.run(&first, peers(&[("p1", Some("100.64.0.1"))])),
        h.run(&second, peers(&[("p2", Some("100.64.0.2"))]))
    );
    assert!(a.is_ok());
    assert!(matches!(b, Err(Error::NetbirdDnsError { reason: "Conflict", .. })));
    assert_eq!(h.records("zone").len(), 1);
    assert_eq!(h.records("zone")[0]["content"], "100.64.0.1");
}

#[tokio::test]
async fn multiple_names_rotate_credentials_and_migrate_api_endpoint_without_touching_other_conditions() {
    let h = Harness::new().await;
    let destination = Harness::new().await;
    h.kube.lock().unwrap().service.status = Some(
        serde_json::from_value(json!({"conditions":[{
            "type":"example.com/Healthy","status":"True","reason":"Healthy","message":"other controller",
            "lastTransitionTime":"2026-01-01T00:00:00Z"
        }]}))
        .unwrap(),
    );
    let mut ctx = h.ctx();
    ctx.binding
        .data
        .service
        .metadata
        .annotations
        .as_mut()
        .unwrap()
        .insert(HOSTNAMES.into(), "app.private.example.com,private.example.com".into());
    h.run(&ctx, peers(&[("p1", Some("100.64.0.1")), ("p2", Some("100.64.0.2"))]))
        .await
        .unwrap();
    assert_eq!(h.records("zone").len(), 4);
    h.kube.lock().unwrap().token = Some("rotated-token".into());
    let mut ctx = h.ctx();
    ctx.binding
        .data
        .class
        .spec
        .netbird
        .as_mut()
        .unwrap()
        .custom_dns
        .as_mut()
        .unwrap()
        .api_url = destination
        .base
        .binding
        .data
        .class
        .spec
        .netbird
        .as_ref()
        .unwrap()
        .custom_dns
        .as_ref()
        .unwrap()
        .api_url
        .clone();
    h.run(&ctx, peers(&[("p1", Some("100.64.0.1")), ("p2", Some("100.64.0.2"))]))
        .await
        .unwrap();
    assert!(h.records("zone").is_empty());
    assert_eq!(destination.records("zone").len(), 4);
    assert_eq!(h.ctx().binding.data.netbird_dns.targets[0].token, "rotated-token");
    let state = h.kube.lock().unwrap();
    let conditions = state.service.status.as_ref().unwrap().conditions.as_ref().unwrap();
    assert_eq!(conditions.len(), 2);
    assert_eq!(conditions[0].type_, "example.com/Healthy");
}

#[tokio::test]
async fn api_failures_preserve_records_and_reservations_until_cleanup_succeeds() {
    let h = Harness::new().await;
    h.run(&h.ctx(), peers(&[("p", Some("100.64.0.1"))])).await.unwrap();
    for status in [401, 403, 429, 503] {
        h.remote.lock().unwrap().status = Some(status);
        assert!(h.run(&h.ctx(), peers(&[])).await.is_err());
        assert!(cleanup(&h.ctx()).await.is_err());
        assert_eq!(h.records("zone").len(), 1);
        assert_eq!(h.ctx().binding.data.netbird_dns.targets.len(), 1);
    }
    h.remote.lock().unwrap().status = None;
    let mut ctx = h.ctx();
    ctx.binding
        .data
        .service
        .metadata
        .annotations
        .as_mut()
        .unwrap()
        .remove(HOSTNAMES);
    h.run(&ctx, peers(&[])).await.unwrap();
    assert!(h.records("zone").is_empty());
    assert!(h.ctx().binding.data.netbird_dns.targets.is_empty());
    assert!(
        h.kube
            .lock()
            .unwrap()
            .service
            .status
            .as_ref()
            .unwrap()
            .conditions
            .as_ref()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn dns_configuration_defaults_and_secret_namespace_boundaries() {
    let (client, _) = crate::test_support::mock(vec![]);
    let mut class = context(client).binding.data.class;
    class.spec = serde_json::from_value(json!({"netbird":{
        "managementUrl":"https://netbird.example.com", "setupKeyRef":{"name":"setup","key":"key"},
        "customDns":{"zoneId":"zone","apiTokenRef":{"name":"token","key":"token","namespace":"foreign"}}
    }}))
    .unwrap();
    assert_eq!(
        class.spec.netbird.as_ref().unwrap().custom_dns.as_ref().unwrap().ttl,
        60
    );
    assert!(crate::config::validate_class(&class).is_err());
    class.namespaced = false;
    crate::config::validate_class(&class).unwrap();
    for ttl in [0, 2147483648] {
        class.spec.netbird.as_mut().unwrap().custom_dns.as_mut().unwrap().ttl = ttl;
        assert!(crate::config::validate_class(&class).is_err());
    }
    let data: crate::state::BindingData = serde_json::from_value(json!({
        "service":{}, "class":class, "credentials":{}
    }))
    .unwrap();
    assert!(data.netbird_dns.targets.is_empty());
}

#[tokio::test]
async fn cleanup_removes_failure_condition_even_when_no_records_were_provisioned() {
    let h = Harness::new().await;
    h.kube.lock().unwrap().token = None;
    assert!(h.run(&h.ctx(), peers(&[])).await.is_err());
    assert!(h.ctx().binding.data.netbird_dns.targets.is_empty());
    cleanup(&h.ctx()).await.unwrap();
    assert!(
        h.kube
            .lock()
            .unwrap()
            .service
            .status
            .as_ref()
            .unwrap()
            .conditions
            .as_ref()
            .unwrap()
            .is_empty()
    );
    assert_eq!(h.mutations(), 0);
}
