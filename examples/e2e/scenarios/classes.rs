//! Class identity is independent of the common workload namespace.
use crate::kubernetes::*;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
async fn class(k: &Kubernetes, kind: &str, ns: &str, key_ns: &str, key: &str) -> Result<Value> {
    k.apply(object(kind,ns,"shared",json!({"spec":{"netbird":{"managementUrl":"https://netbird.example.com","setupKeyRef":{"name":key,"key":"key","namespace":key_ns}}}}))).await
}
async fn copies(k: &Kubernetes, sel: &str, value: &str) -> Result<()> {
    use base64::Engine;
    let expected = base64::prelude::BASE64_STANDARD.encode(value);
    wait("binding receives only its class credential", 90, async || {
        Ok(k.list("Secret", SYSTEM, sel)
            .await?
            .iter()
            .any(|s| s["data"]["setup-key"] == expected))
    })
    .await
}
pub async fn run(k: &Kubernetes) -> Result<()> {
    for ns in ["class-a", "class-b", "class-c", "class-d", "credentials"] {
        k.namespace(ns).await?;
    }
    for (ns, value) in [
        ("class-a", "a"),
        ("class-b", "b"),
        ("class-c", "c"),
        ("credentials", "cluster"),
    ] {
        k.apply(object("Secret", ns, "key", json!({"stringData":{"key":value}})))
            .await?;
    }
    let cluster = class(k, "ClusterTunnelClass", "", "credentials", "key").await?;
    let local_a = class(k, "TunnelClass", "class-a", "class-a", "key").await?;
    class(k, "TunnelClass", "class-b", "class-b", "key").await?;
    let mut bindings = Vec::new();
    for (ns, value) in [
        ("class-a", "a"),
        ("class-b", "b"),
        ("class-c", "cluster"),
        ("class-d", "cluster"),
    ] {
        let service = k
            .service(ns, "same-name", "shared", json!({"tlb.io/replicas":"0"}))
            .await?;
        let sel = selector(&service);
        let workload = k
            .present(
                "StatefulSet",
                SYSTEM,
                &sel,
                "same-name Services have independent workloads",
            )
            .await?;
        copies(k, &sel, value).await?;
        bindings.push((service, workload, sel));
    }
    for i in 0..bindings.len() {
        for j in i + 1..bindings.len() {
            ensure!(
                uid(&bindings[i].1) != uid(&bindings[j].1) && name(&bindings[i].1) != name(&bindings[j].1),
                "shared-namespace workload collision"
            );
        }
    }
    // A newly created local class must supersede a live cluster-class binding.
    class(k, "TunnelClass", "class-c", "class-c", "key").await?;
    wait("adding local class replaces cluster-class binding", 90, async || {
        Ok(k.list("StatefulSet", SYSTEM, &bindings[2].2)
            .await?
            .iter()
            .any(|w| w["metadata"]["labels"]["controller.tlb.io/class-uid"] != uid(&cluster)))
    })
    .await?;
    copies(k, &bindings[2].2, "c").await?;
    ensure!(
        uid(&k.first("StatefulSet", SYSTEM, &bindings[3].2).await?) == uid(&bindings[3].1),
        "local override touched another cluster binding"
    );
    // Two live cluster users must both drain, without touching either local class.
    k.delete("TunnelClass", "class-c", "shared").await?;
    k.gone("TunnelClass", "class-c", "shared").await?;
    copies(k, &bindings[2].2, "cluster").await?;
    k.delete("ClusterTunnelClass", "", "shared").await?;
    k.gone("ClusterTunnelClass", "", "shared").await?;
    for i in [2, 3] {
        wait("cluster-class deletion cleans live binding", 90, async || {
            k.clean(SYSTEM, &bindings[i].2).await
        })
        .await?;
    }
    for i in [0, 1] {
        ensure!(
            uid(&k.first("StatefulSet", SYSTEM, &bindings[i].2).await?) == uid(&bindings[i].1),
            "cluster-class deletion removed local workload"
        );
    }
    // Same-name local classes and recreated UIDs must never share ownership.
    k.delete("TunnelClass", "class-a", "shared").await?;
    k.gone("TunnelClass", "class-a", "shared").await?;
    wait("local class deletion cleans only its binding", 90, async || {
        k.clean(SYSTEM, &bindings[0].2).await
    })
    .await?;
    ensure!(
        uid(&k.first("StatefulSet", SYSTEM, &bindings[1].2).await?) == uid(&bindings[1].1),
        "same-name local class was affected"
    );
    let recreated = class(k, "TunnelClass", "class-a", "class-a", "key").await?;
    ensure!(uid(&recreated) != uid(&local_a), "class UID was reused");
    let workload = k
        .present(
            "StatefulSet",
            SYSTEM,
            &bindings[0].2,
            "recreated local class provisions new binding",
        )
        .await?;
    ensure!(
        uid(&workload) != uid(&bindings[0].1)
            && workload["metadata"]["labels"]["controller.tlb.io/class-uid"] == uid(&recreated),
        "recreated class adopted stale binding"
    );
    for ns in ["class-a", "class-b", "class-c", "class-d"] {
        k.delete("Namespace", "", ns).await?;
    }
    wait("all class journals and workloads cleaned", 120, async || {
        k.clean(SYSTEM, BINDING).await
    })
    .await?;
    ensure!(
        k.exists("Secret", "credentials", "key").await?,
        "cluster credential source deleted"
    );
    Ok(())
}
