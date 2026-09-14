//! Real API watches against a controlled DNS provider and fixture peers.
use crate::{cluster::Cluster, kubernetes::*};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
const NS: &str = "dns-audit";
const OTHER: &str = "dns-other";
const WORK: &str = "dns-tunnels";
const CLASS: &str = "tlb.io/netbird-custom-dns-ingress-class";
const SCOPE: &str = "tlb.io/netbird-custom-dns-ingress-namespaces";
const HOSTS: &str = "tlb.io/netbird-custom-dns-hostnames";
const ZONE: &str = "private.example.com";
const BOTH: &[&str] = &["100.64.0.10", "100.64.0.11"];
async fn api(c: &Cluster, path: &str, data: Option<Value>) -> Result<Value> {
    let payload = data
        .map(|v| format!("{:?}.encode()", v.to_string()))
        .unwrap_or("None".into());
    let code = format!(
        "import urllib.request; r=urllib.request.Request('http://127.0.0.1:8080{path}',data={payload}); print(urllib.request.urlopen(r,timeout=5).read().decode())"
    );
    Ok(serde_json::from_str(
        &c.exec(NS, "dns-api", "api", &["python3", "-c", &code]).await?,
    )?)
}
async fn records(c: &Cluster) -> Result<Vec<(String, String)>> {
    let state = api(c, "/__state", None).await?;
    let mut records: Vec<_> = entries(&state["records"])
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap_or_default().into(),
                r["content"].as_str().unwrap_or_default().into(),
            )
        })
        .collect();
    records.sort();
    Ok(records)
}
fn expected(names: &[&str], addresses: &[&str]) -> Vec<(String, String)> {
    let mut records = vec![(format!("untouched.{ZONE}"), "100.64.0.99".into())];
    for n in names {
        for a in addresses {
            records.push((format!("{n}.{ZONE}"), (*a).into()));
        }
    }
    records.sort();
    records
}
async fn dns(c: &Cluster, names: &[&str], addresses: &[&str], message: &str, seconds: u64) -> Result<()> {
    let expected = expected(names, addresses);
    let result = wait(message, seconds, async || Ok(records(c).await? == expected)).await;
    if result.is_err() {
        eprintln!("DNS expected {expected:?}, observed {:?}", records(c).await?);
    }
    result
}
async fn condition(k: &Kubernetes, service: &str, reason: &str) -> Result<()> {
    wait(reason, 60, async || {
        Ok(entries(&k.get("Service", NS, service).await?["status"]["conditions"])
            .iter()
            .any(|c| c["type"] == "tlb.io/CustomDNSReady" && c["reason"] == reason))
    })
    .await
}
async fn ingress(k: &Kubernetes, ns: &str, name: &str, host: &str, class: Option<&str>) -> Result<()> {
    let mut spec = json!({"rules":[{"host":host,"http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"unused","port":{"number":80}}}}]}}]});
    if let Some(class) = class {
        spec["ingressClassName"] = class.into();
    }
    k.apply(object("Ingress", ns, name, json!({"spec":spec}))).await?;
    Ok(())
}
async fn settled(c: &Cluster) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut last = None;
    let mut since = Instant::now();
    while Instant::now() < deadline {
        let count = entries(&api(c, "/__state", None).await?["calls"]).len();
        if Some(count) != last {
            last = Some(count);
            since = Instant::now();
        } else if since.elapsed() >= Duration::from_secs(5) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    anyhow::bail!("DNS reconciliation did not become idle before watch-only mutation")
}
pub async fn run(c: &Cluster, image: &str) -> Result<()> {
    let k = c.client()?;
    let deployment = k.get("Deployment", SYSTEM, "tlb-controller").await?;
    ensure!(
        entries(&deployment["spec"]["template"]["spec"]["containers"][0]["env"])
            .iter()
            .any(|e| e["name"] == "TLB_EXTERNAL_REFRESH_INTERVAL_SECONDS" && e["value"] == "7200"),
        "watch checks require a two-hour refresh interval"
    );
    for ns in [NS, OTHER, WORK] {
        k.namespace(ns).await?;
    }
    k.configure(WORK, true).await?;
    k.apply(object("Pod",NS,"dns-api",json!({"metadata":{"labels":{"app":"dns-api"}},"spec":{"containers":[{"name":"api","image":image,"imagePullPolicy":"Never","readinessProbe":{"httpGet":{"path":"/__state","port":8080},"periodSeconds":1}}]}}))).await?;
    k.apply(object(
        "Service",
        NS,
        "dns-api",
        json!({"spec":{"selector":{"app":"dns-api"},"ports":[{"port":8080}]}}),
    ))
    .await?;
    wait("DNS fixture ready", 90, async || {
        Ok(ready(&k.get("Pod", NS, "dns-api").await?))
    })
    .await?;
    k.apply(object(
        "Secret",
        NS,
        "credentials",
        json!({"stringData":{"key":"test-setup-key","token":"test-api-token"}}),
    ))
    .await?;
    // Keep the interface unaddressed long enough to exercise peer-IP startup ordering.
    let up = r#"peer_name=$(hostname); ip link add wt0 type dummy; sleep 3; ip addr add "100.64.0.$(( ${peer_name##*-} + 10 ))/32" dev wt0; ip link set wt0 up; exec sleep infinity"#;
    k.apply(object("TunnelClass",NS,"dns-audit",json!({"spec":{"netbird":{"managementUrl":format!("http://dns-api.{NS}.svc:8080"),"setupKeyRef":{"name":"credentials","key":"key"},"image":image,"enableEbpfCapabilities":false,"storageClass":"standard","upCommand":up,"customDns":{"zoneId":"zone","apiTokenRef":{"name":"credentials","key":"token"},"ttl":60}}}}))).await?;
    k.service(
        NS,
        "ingress",
        "dns-audit",
        json!({CLASS:"private","tlb.io/replicas":"2"}),
    )
    .await?;
    ingress(k, NS, "first", &format!("first.{ZONE}"), Some("private")).await?;
    dns(
        c,
        &["first"],
        BOTH,
        "Ingress creation publishes both ready-Pod addresses",
        180,
    )
    .await?;
    condition(k, "ingress", "Reconciled").await?;
    ensure!(
        k.get("Service", NS, "ingress").await?["metadata"]["annotations"][HOSTS].is_null(),
        "discovery modified explicit hostname annotation"
    );
    settled(c).await?;
    ingress(k, NS, "new", &format!("new.{ZONE}"), Some("private")).await?;
    dns(c, &["first", "new"], BOTH, "Ingress creation alone adds hostname", 45).await?;
    settled(c).await?;
    k.delete("Ingress", NS, "new").await?;
    dns(c, &["first"], BOTH, "last Ingress source deletion removes hostname", 45).await?;
    settled(c).await?;
    ingress(k, NS, "first", &format!("edited.{ZONE}"), Some("private")).await?;
    dns(
        c,
        &["edited"],
        BOTH,
        "Ingress edit alone updates DNS before refresh",
        45,
    )
    .await?;
    settled(c).await?;
    ingress(k, NS, "duplicate", &format!("edited.{ZONE}"), Some("private")).await?;
    settled(c).await?;
    k.delete("Ingress", NS, "first").await?;
    settled(c).await?;
    ensure!(
        records(c).await? == expected(&["edited"], BOTH),
        "shared hostname removed with one remaining source"
    );
    ingress(k, NS, "duplicate", &format!("edited.{ZONE}"), Some("public")).await?;
    dns(c, &[], BOTH, "class change removes prior contribution", 45).await?;
    for (name, host, class, ns) in [
        ("public", format!("public.{ZONE}"), Some("public"), NS),
        ("classless", format!("classless.{ZONE}"), None, NS),
        ("wildcard", format!("*.{ZONE}"), Some("private"), NS),
        ("outside", "outside.example.org".into(), Some("private"), NS),
        ("other", format!("other.{ZONE}"), Some("private"), OTHER),
    ] {
        ingress(k, ns, name, &host, class).await?;
    }
    k.apply(object("Ingress",NS,"tls-only",json!({"spec":{"ingressClassName":"private","tls":[{"hosts":[format!("tls.{ZONE}")]}],"defaultBackend":{"service":{"name":"unused","port":{"number":80}}}}}))).await?;
    ingress(k, NS, "included", &format!("included.{ZONE}"), Some("private")).await?;
    dns(
        c,
        &["included"],
        BOTH,
        "class, zone, wildcard, TLS and namespace filters",
        45,
    )
    .await?;
    k.annotations(NS, "ingress", json!({SCOPE:format!("{NS},{OTHER}")}))
        .await?;
    dns(
        c,
        &["included", "other"],
        BOTH,
        "explicit namespace allowlist includes cross-namespace Ingress",
        45,
    )
    .await?;
    k.annotations(NS, "ingress", json!({SCOPE:"*"})).await?;
    settled(c).await?;
    ingress(k, OTHER, "other", &format!("changed.{ZONE}"), Some("private")).await?;
    dns(
        c,
        &["included", "changed"],
        BOTH,
        "all-namespace discovery watches cross-namespace edits",
        45,
    )
    .await?;
    k.annotations(
        NS,
        "ingress",
        json!({SCOPE:null,HOSTS:format!("included.{ZONE},explicit.{ZONE}")}),
    )
    .await?;
    dns(
        c,
        &["included", "explicit"],
        BOTH,
        "explicit and discovered hostnames form a union",
        45,
    )
    .await?;
    k.delete("Ingress", NS, "included").await?;
    settled(c).await?;
    ensure!(
        records(c).await? == expected(&["included", "explicit"], BOTH),
        "explicit source did not preserve hostname"
    );
    k.annotations(NS, "ingress", json!({HOSTS:format!("explicit.{ZONE}")}))
        .await?;
    dns(c, &["explicit"], BOTH, "removing last source removes records", 45).await?;
    let mut peers = k.list("Pod", WORK, BINDING).await?;
    peers.sort_by(|a, b| name(a).cmp(name(b)));
    ensure!(peers.len() == 2, "expected two fixture peers");
    let peer = name(&peers[1]);
    c.exec(WORK, peer, "netbird", &["ip", "link", "delete", "wt0"]).await?;
    dns(
        c,
        &["explicit"],
        &["100.64.0.10"],
        "Pod watch withdraws unready peer",
        120,
    )
    .await?;
    c.exec(
        WORK,
        peer,
        "netbird",
        &[
            "sh",
            "-c",
            "ip link add wt0 type dummy; ip addr add 100.64.0.42/32 dev wt0; ip link set wt0 up",
        ],
    )
    .await?;
    dns(
        c,
        &["explicit"],
        &["100.64.0.10", "100.64.0.42"],
        "readiness recovery publishes the changed peer address",
        120,
    )
    .await?;
    k.annotations(NS, "ingress", json!({"tlb.io/replicas":"1"})).await?;
    dns(
        c,
        &["explicit"],
        &["100.64.0.10"],
        "scale down removes retired peer",
        45,
    )
    .await?;
    k.annotations(NS, "ingress", json!({"tlb.io/replicas":"0"})).await?;
    dns(c, &[], &[], "scale to zero empties managed A records", 45).await?;
    k.annotations(NS, "ingress", json!({"tlb.io/replicas":"2"})).await?;
    dns(c, &["explicit"], BOTH, "scale up restores ready peers", 180).await?;
    k.service(
        NS,
        "conflicting",
        "dns-audit",
        json!({HOSTS:format!("explicit.{ZONE}"),"tlb.io/replicas":"0"}),
    )
    .await?;
    condition(k, "conflicting", "Conflict").await?;
    ensure!(
        records(c).await? == expected(&["explicit"], BOTH),
        "conflicting Service changed owner records"
    );
    k.delete("Service", NS, "conflicting").await?;
    k.gone("Service", NS, "conflicting").await?;
    ensure!(
        records(c).await? == expected(&["explicit"], BOTH),
        "conflict cleanup deleted owner records"
    );
    api(c, "/__control", Some(json!({"failure":503}))).await?;
    ingress(k, NS, "recover", &format!("recover.{ZONE}"), Some("private")).await?;
    condition(k, "ingress", "APIError").await?;
    ensure!(
        records(c).await? == expected(&["explicit"], BOTH),
        "API failure lost records"
    );
    api(c, "/__control", Some(json!({"failure":0}))).await?;
    dns(
        c,
        &["explicit", "recover"],
        BOTH,
        "provider recovery reconciles pending changes",
        60,
    )
    .await?;
    let role = k.get("ClusterRole", "", "tlb-controller").await?;
    let mut rules = role["rules"].clone();
    for rule in rules.as_array_mut().unwrap() {
        if entries(&rule["resources"]).contains(&json!("ingresses")) {
            rule["verbs"].as_array_mut().unwrap().retain(|v| v != "list");
        }
    }
    k.patch("ClusterRole", "", "tlb-controller", json!({"rules":rules}))
        .await?;
    let denied = async {
        ingress(k, NS, "recover", &format!("renamed.{ZONE}"), Some("private")).await?;
        condition(k, "ingress", "IngressDiscoveryFailed").await?;
        ensure!(
            records(c).await? == expected(&["explicit", "recover"], BOTH),
            "failed discovery lost records"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    k.patch("ClusterRole", "", "tlb-controller", json!({"rules":role["rules"]}))
        .await?;
    denied?;
    dns(
        c,
        &["explicit", "renamed"],
        BOTH,
        "restored list permission reconciles complete hostname set",
        60,
    )
    .await?;
    k.failover().await?;
    settled(c).await?;
    ingress(k, NS, "recover", &format!("after-restart.{ZONE}"), Some("private")).await?;
    dns(
        c,
        &["explicit", "after-restart"],
        BOTH,
        "new leader reconciles persisted DNS ownership",
        45,
    )
    .await?;
    k.annotations(NS, "ingress", json!({CLASS:null})).await?;
    dns(c, &["explicit"], BOTH, "disabling discovery retains explicit names", 45).await?;
    api(c, "/__control", Some(json!({"failure":503}))).await?;
    let before = entries(&api(c, "/__state", None).await?["calls"]).len();
    k.delete("Service", NS, "ingress").await?;
    wait("cleanup attempts unavailable provider", 60, async || {
        Ok(entries(&api(c, "/__state", None).await?["calls"]).len() > before)
    })
    .await?;
    let remaining = k.get("Service", NS, "ingress").await?;
    ensure!(
        !remaining["metadata"]["deletionTimestamp"].is_null()
            && entries(&remaining["metadata"]["finalizers"]).contains(&json!("tlb.io/tunnel-cleanup")),
        "failed cleanup lost finalizer"
    );
    ensure!(
        records(c).await? == expected(&["explicit"], BOTH),
        "failed cleanup lost records"
    );
    api(c, "/__control", Some(json!({"failure":0}))).await?;
    dns(c, &[], BOTH, "Service cleanup preserves unrelated DNS record", 90).await?;
    k.gone("Service", NS, "ingress").await?;
    wait("DNS journal finalized", 90, async || {
        Ok(k.list("Secret", SYSTEM, "controller.tlb.io/journal=true")
            .await?
            .is_empty())
    })
    .await?;
    Ok(())
}
