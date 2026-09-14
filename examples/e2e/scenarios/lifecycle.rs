use crate::kubernetes::*;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
const A: &str = "audit-a";
const B: &str = "audit-b";
fn scope(ns: &str) -> String {
    format!("{BINDING},controller.tlb.io/service-namespace={ns}")
}
async fn zero(k: &Kubernetes, ns: &str, n: &str, class: &str) -> Result<Value> {
    k.service(ns, n, class, json!({"tlb.io/replicas":"0"})).await
}
async fn warning(k: &Kubernetes, ns: &str, service: &Value, message: &str) -> Result<()> {
    wait(message, 60, async || {
        Ok(k.list("Event", ns, "").await?.iter().any(|e| {
            e["regarding"]["uid"] == service["metadata"]["uid"]
                && e["type"] == "Warning"
                && e["reason"] == "ReconcileFailed"
                && e["note"].as_str().unwrap_or_default().contains(message)
        }))
    })
    .await
}
pub async fn run(k: &Kubernetes) -> Result<()> {
    for ns in [A, B] {
        k.namespace(ns).await?;
    }
    k.apply(object(
        "Secret",
        SYSTEM,
        "audit-key",
        json!({"stringData":{"key":"test-only-not-a-provider-key"}}),
    ))
    .await?;
    let nb = json!({"netbird":{"managementUrl":"https://netbird.example.com","setupKeyRef":{"name":"audit-key","key":"key","namespace":SYSTEM},"storageClass":"standard"}});
    k.apply(object("ClusterTunnelClass", "", "audit-public", json!({"spec":nb})))
        .await?;
    k.apply(object(
        "TunnelClass",
        A,
        "audit-public",
        json!({"spec":{"cloudflare":{}}}),
    ))
    .await?;
    k.apply(object("Secret",B,"unrelated-labels",json!({"metadata":{"labels":{"controller.tlb.io/for-tunnel-class":"audit-public","controller.tlb.io/for-service":"api"}}}))).await?;
    k.apply(object("Service", A, "api", json!({"metadata":{"finalizers":["other.example/keep"],"annotations":{"tlb.io/replicas":"0"}},"spec":{"type":"LoadBalancer","loadBalancerClass":"tlb.io/audit-public","ports":[{"port":80}]}}))).await?;
    zero(k, B, "api", "audit-public").await?;
    let a = k
        .present(
            "Deployment",
            SYSTEM,
            &scope(A),
            "namespaced class wins over cluster class",
        )
        .await?;
    let b = k
        .present(
            "StatefulSet",
            SYSTEM,
            &scope(B),
            "cluster class provisions in controller namespace",
        )
        .await?;
    ensure!(
        k.list("StatefulSet", SYSTEM, &scope(A)).await?.is_empty(),
        "wrong provider for local class"
    );
    k.patch(
        "Service",
        A,
        "api",
        json!({"metadata":{"finalizers":["other.example/keep"]}}),
    )
    .await?;
    wait("journal restores missing Service finalizer", 60, async || {
        Ok(entries(&k.get("Service", A, "api").await?["metadata"]["finalizers"])
            .contains(&json!("tlb.io/tunnel-cleanup")))
    })
    .await?;
    k.apply(object("TunnelClass", B, "legacy", json!({"spec":{"cloudflare":{}}})))
        .await?;
    wait("legacy class receives finalizer", 60, async || {
        Ok(
            entries(&k.get("TunnelClass", B, "legacy").await?["metadata"]["finalizers"])
                .contains(&json!("tlb.io/finalizer")),
        )
    })
    .await?;
    let legacy=k.apply(object("Service",B,"legacy",json!({"metadata":{"finalizers":["tlb.io/tunnel-cleanup"],"annotations":{"tlb.io/replicas":"0"}},"spec":{"type":"LoadBalancer","loadBalancerClass":"tlb.io/legacy","ports":[{"port":80}]}}))).await?;
    warning(k, B, &legacy, "no private binding journal").await?;
    ensure!(
        k.list("Secret", SYSTEM, &selector(&legacy)).await?.is_empty(),
        "legacy service created a journal"
    );
    k.delete("TunnelClass", B, "legacy").await?;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    ensure!(
        k.exists("TunnelClass", B, "legacy").await?,
        "class bypassed unresolved binding"
    );
    k.patch("Service", B, "legacy", json!({"metadata":{"finalizers":[]}}))
        .await?;
    k.delete("Service", B, "legacy").await?;
    k.gone("TunnelClass", B, "legacy").await?;
    ensure!(
        k.list("Deployment", SYSTEM, &scope(B)).await?.is_empty(),
        "legacy workload created"
    );
    ensure!(
        a["metadata"]["labels"][BINDING] != b["metadata"]["labels"][BINDING],
        "binding identity collision"
    );
    ensure!(
        k.list("Secret", SYSTEM, &scope(B))
            .await?
            .iter()
            .any(|s| s["data"]["setup-key"] == "dGVzdC1vbmx5LW5vdC1hLXByb3ZpZGVyLWtleQ=="),
        "central credential copy missing"
    );
    pass("namespace isolation and central credential copy");
    let invalid = k
        .service(
            A,
            "invalid-mapping",
            "audit-public",
            json!({"tlb.io/replicas":"0","tlb.io/map-ports":"https:80,ssh:22"}),
        )
        .await?;
    warning(k, A, &invalid, "Cloudflare accepts one port mapping").await?;
    ensure!(
        k.list("Secret", SYSTEM, &selector(&invalid)).await?.is_empty(),
        "invalid mapping created journal"
    );
    k.delete("Service", A, "invalid-mapping").await?;
    k.apply(object(
        "Secret",
        B,
        "invalid-tls",
        json!({"stringData":{"tls.crt":"incomplete"}}),
    ))
    .await?;
    let invalid = k
        .service(
            B,
            "invalid-tls",
            "audit-public",
            json!({"tlb.io/replicas":"0","tlb.io/map-ports":"443/tls:80","tlb.io/tls-secret-name":"invalid-tls"}),
        )
        .await?;
    warning(k, B, &invalid, "tls.key").await?;
    ensure!(
        k.list("Secret", SYSTEM, &selector(&invalid)).await?.is_empty(),
        "invalid TLS created journal"
    );
    k.delete("Service", B, "invalid-tls").await?;
    k.delete("Secret", B, "invalid-tls").await?;
    let long = "a".repeat(63);
    let service = k
        .service(
            B,
            &long,
            "audit-public",
            json!({"tlb.io/replicas":"1","tlb.io/node-selector":"audit.example/unschedulable=true"}),
        )
        .await?;
    let sel = selector(&service);
    let pod = k
        .present("Pod", SYSTEM, &sel, "long Service name produces valid StatefulSet Pod")
        .await?;
    ensure!(name(&pod).len() <= 63, "Pod name too long");
    k.delete("Service", B, &long).await?;
    wait("long-name workload cleanup completes", 90, async || {
        k.clean(SYSTEM, &sel).await
    })
    .await?;
    let mut claim = b["spec"]["volumeClaimTemplates"][0].clone();
    claim["metadata"]["name"] = "audit-retained".into();
    claim["metadata"]["namespace"] = SYSTEM.into();
    claim["apiVersion"] = "v1".into();
    claim["kind"] = "PersistentVolumeClaim".into();
    let claim = k.apply(claim).await?;
    k.patch(
        "ClusterTunnelClass",
        "",
        "audit-public",
        json!({"spec":{"netbird":{"netbirdInterface":"wt-test"}}}),
    )
    .await?;
    wait("mutable class interface reaches existing StatefulSet", 60, async || {
        Ok(entries(
            &k.first("StatefulSet", SYSTEM, &scope(B)).await?["spec"]["template"]["spec"]["containers"][0]["command"],
        )
        .iter()
        .any(|v| v.as_str().unwrap_or_default().contains("wt-test")))
    })
    .await?;
    for patch in [
        json!({}),
        json!({"managementUrl":"invalid"}),
        json!({"managementUrl":"https://netbird.example.com","size":"64Mi"}),
    ] {
        k.patch(
            "ClusterTunnelClass",
            "",
            "audit-public",
            json!({"spec":{"netbird":patch}}),
        )
        .await?;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        ensure!(
            uid(&k.first("StatefulSet", SYSTEM, &scope(B)).await?) == uid(&b),
            "class update replaced StatefulSet"
        );
        ensure!(
            uid(&k.get("PersistentVolumeClaim", SYSTEM, name(&claim)).await?) == uid(&claim),
            "class update replaced PVC"
        );
    }
    pass("mutable, invalid and immutable class changes preserve workload and storage identities");
    k.patch(
        "ClusterTunnelClass",
        "",
        "audit-public",
        json!({"spec":{"netbird":{"size":null}}}),
    )
    .await?;
    k.delete("TunnelClass", A, "audit-public").await?;
    k.gone("TunnelClass", A, "audit-public").await?;
    ensure!(
        k.list("Deployment", SYSTEM, &scope(A)).await?.is_empty(),
        "local class workload remains"
    );
    ensure!(
        k.exists("Secret", B, "unrelated-labels").await?,
        "foreign labels triggered deletion"
    );
    ensure!(
        uid(&k.first("StatefulSet", SYSTEM, &scope(B)).await?) == uid(&b),
        "class deletion touched another namespace"
    );
    k.present("StatefulSet", SYSTEM, &scope(A), "Service falls back to cluster class")
        .await?;
    ensure!(
        entries(&k.get("Service", A, "api").await?["metadata"]["finalizers"]).contains(&json!("other.example/keep")),
        "foreign finalizer removed"
    );
    k.delete("Service", B, "api").await?;
    k.gone("Service", B, "api").await?;
    wait(
        "Service deletion cleans copied credentials and retained PVC",
        90,
        async || k.clean(SYSTEM, &scope(B)).await,
    )
    .await?;
    zero(k, B, "api", "audit-public").await?;
    let recreated = k
        .present(
            "StatefulSet",
            SYSTEM,
            &scope(B),
            "same-name Service recreation provisions",
        )
        .await?;
    ensure!(
        uid(&recreated) != uid(&b) && name(&recreated) != name(&b),
        "recreated Service reused workload identity"
    );
    k.apply(object("TunnelClass", B, "audit-public", json!({"spec":nb})))
        .await?;
    let foreign = zero(k, B, "blocked", "audit-public").await?;
    warning(k, B, &foreign, "another namespace").await?;
    ensure!(
        k.list("Secret", SYSTEM, &selector(&foreign)).await?.is_empty(),
        "namespaced Secret escape created journal"
    );
    k.patch(
        "Service",
        A,
        "api",
        json!({"metadata":{"finalizers":["tlb.io/tunnel-cleanup"]}}),
    )
    .await?;
    for ns in [A, B] {
        k.delete("Namespace", "", ns).await?;
    }
    wait("namespace deletion leaves no private journals", 120, async || {
        Ok(k.list("Secret", SYSTEM, "controller.tlb.io/journal=true")
            .await?
            .is_empty())
    })
    .await?;
    k.delete("ClusterTunnelClass", "", "audit-public").await?;
    k.gone("ClusterTunnelClass", "", "audit-public").await?;
    k.delete("Secret", SYSTEM, "audit-key").await?;
    Ok(())
}
