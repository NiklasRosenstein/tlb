use crate::kubernetes::*;
use anyhow::{Result, ensure};
use base64::{Engine, prelude::BASE64_STANDARD};
use serde_json::{Value, json};
fn encoded(s: &str) -> String {
    BASE64_STANDARD.encode(s)
}
async fn secret(k: &Kubernetes, ns: &str, name: &str, data: Value) -> Result<()> {
    k.apply(object("Secret", ns, name, json!({"stringData":data}))).await?;
    Ok(())
}
async fn copy_has(k: &Kubernetes, ns: &str, sel: &str, key: &str, value: &str) -> Result<bool> {
    Ok(k.list("Secret", ns, sel)
        .await?
        .iter()
        .any(|s| s["data"][key] == encoded(value)))
}
pub async fn run(k: &Kubernetes) -> Result<()> {
    for ns in [SYSTEM, "tlb-tunnels"] {
        if ns != SYSTEM {
            k.namespace(ns).await?;
        }
        k.configure(ns, false).await?;
        let app = "runtime-app";
        k.namespace(app).await?;
        secret(k, app, "source-key", json!({"key":"first","unneeded":"never-copy"})).await?;
        secret(
            k,
            app,
            "source-tls",
            json!({"tls.crt":"cert-one","tls.key":"private-one","unneeded":"never-copy"}),
        )
        .await?;
        k.apply(object("TunnelClass",app,"runtime",json!({"spec":{"netbird":{"managementUrl":"https://netbird.example.com","setupKeyRef":{"name":"source-key","key":"key"},"storageClass":"standard"}}}))).await?;
        let service = k
            .service(
                app,
                "runtime",
                "runtime",
                json!({"tlb.io/replicas":"0","tlb.io/map-ports":"443/tls:80","tlb.io/tls-secret-name":"source-tls"}),
            )
            .await?;
        let sel = selector(&service);
        let sts = k.present("StatefulSet", ns, &sel, "runtime workload placement").await?;
        wait("journal and runtime copies present", 90, async || {
            Ok(k.list("Secret", ns, &sel).await?.len() == if ns == SYSTEM { 3 } else { 2 })
        })
        .await?;
        let copies: Vec<_> = k
            .list("Secret", ns, &sel)
            .await?
            .into_iter()
            .filter(|s| s["metadata"]["labels"]["controller.tlb.io/journal"] != "true")
            .collect();
        ensure!(copies.len() == 2, "expected two runtime copies");
        let tls = copies
            .iter()
            .find(|s| s["type"] == "kubernetes.io/tls")
            .expect("TLS copy");
        ensure!(
            tls["data"]
                .as_object()
                .is_some_and(|d| d.len() == 2 && d.contains_key("tls.crt") && d.contains_key("tls.key")),
            "TLS copy includes unrelated keys"
        );
        ensure!(
            copies
                .iter()
                .any(|s| s["data"] == json!({"setup-key":encoded("first")})),
            "credential key filtering failed"
        );
        let owner = sts["metadata"]["ownerReferences"][0].clone();
        ensure!(
            owner["kind"] == if ns == SYSTEM { "Secret" } else { "ConfigMap" },
            "invalid namespace-local owner"
        );
        ensure!(
            copies
                .iter()
                .all(|s| s["metadata"]["ownerReferences"] == json!([owner])),
            "copy owner mismatch"
        );
        let pod = &sts["spec"]["template"]["spec"];
        ensure!(
            pod["automountServiceAccountToken"] == false,
            "runtime service account token mounted"
        );
        ensure!(
            pod["containers"][0]["securityContext"]["capabilities"]["add"] == json!(["NET_ADMIN"]),
            "extra capabilities enabled by default"
        );
        ensure!(
            entries(&pod["containers"][0]["env"])
                .iter()
                .any(|e| e["name"] == "NB_DISABLE_EBPF_WG_PROXY" && e["value"] == "true"),
            "userspace proxy not enabled"
        );
        ensure!(
            k.list("Secret", app, BINDING).await?.is_empty(),
            "runtime copies appeared in application namespace"
        );
        secret(
            k,
            app,
            "source-tls",
            json!({"tls.crt":"cert-two","tls.key":"private-two"}),
        )
        .await?;
        secret(k, app, "source-key", json!({"key":"second"})).await?;
        wait("TLS source rotation reaches runtime", 90, async || {
            copy_has(k, ns, &sel, "tls.crt", "cert-two").await
        })
        .await?;
        wait("credential rotation reaches runtime", 90, async || {
            copy_has(k, ns, &sel, "setup-key", "second").await
        })
        .await?;
        wait("TLS rotation changes Pod template",90,async || Ok(k.first("StatefulSet",ns,&sel).await?["spec"]["template"]["metadata"]["annotations"]["controller.tlb.io/tls-secret-version"]!=sts["spec"]["template"]["metadata"]["annotations"]["controller.tlb.io/tls-secret-version"])).await?;
        k.create(object("Pod",ns,"tls-reader",json!({"metadata":{"labels":sts["metadata"]["labels"],"ownerReferences":[owner]},"spec":{"nodeSelector":{"test.tlb.io/unschedulable":"true"},"containers":[{"name":"reader","image":"busybox:1.37"}],"volumes":[{"name":"tls","secret":{"secretName":name(tls)}}]}}))).await?;
        k.annotations(app, "runtime", json!({"tlb.io/map-ports":"18080:80"}))
            .await?;
        wait("plaintext template drops TLS reference", 90, async || {
            Ok(
                !entries(&k.first("StatefulSet", ns, &sel).await?["spec"]["template"]["spec"]["volumes"])
                    .iter()
                    .any(|v| v["secret"]["secretName"] == name(tls)),
            )
        })
        .await?;
        ensure!(
            k.exists("Secret", ns, name(tls)).await?,
            "TLS copy deleted while consumed"
        );
        k.delete("Pod", ns, "tls-reader").await?;
        k.gone("Pod", ns, "tls-reader").await?;
        wait("unused TLS copy pruned after last consumer", 90, async || {
            Ok(!k.exists("Secret", ns, name(tls)).await?)
        })
        .await?;
        k.annotations(app, "runtime", json!({"tlb.io/map-ports":"443/tls:80"}))
            .await?;
        wait("TLS reactivation restores copy", 90, async || {
            k.exists("Secret", ns, name(tls)).await
        })
        .await?;
        secret(
            k,
            app,
            "other-tls",
            json!({"tls.crt":"cert-three","tls.key":"private-three"}),
        )
        .await?;
        k.annotations(app, "runtime", json!({"tlb.io/tls-secret-name":"other-tls"}))
            .await?;
        wait("source-reference change reuses runtime name", 90, async || {
            Ok(k.get("Secret", ns, name(tls)).await?["data"]["tls.crt"] == encoded("cert-three"))
        })
        .await?;
        k.delete("Secret", app, "source-key").await?;
        k.delete("Secret", app, "other-tls").await?;
        wait("source loss reported", 90, async || {
            Ok(k.list("Event", app, "").await?.iter().any(|e| {
                let note = e["note"].as_str().unwrap_or_default();
                note.contains("cannot read credential") || (note.contains("other-tls") && note.contains("not found"))
            }))
        })
        .await?;
        ensure!(
            uid(&k.first("StatefulSet", ns, &sel).await?) == uid(&sts),
            "source loss replaced workload"
        );
        ensure!(
            copy_has(k, ns, &sel, "setup-key", "second").await?,
            "source loss discarded last valid credential"
        );
        k.create(object("Pod",ns,"cleanup-blocker",json!({"metadata":{"labels":sts["metadata"]["labels"],"finalizers":["test.tlb.io/hold"],"ownerReferences":[{"apiVersion":"apps/v1","kind":"StatefulSet","name":name(&sts),"uid":uid(&sts)}]},"spec":{"nodeSelector":{"test.tlb.io/unschedulable":"true"},"containers":[{"name":"test","image":"busybox:1.37"}]}}))).await?;
        k.delete("Service", app, "runtime").await?;
        wait("cleanup waits for terminating Pods", 90, async || {
            Ok(k.list("Pod", ns, &sel)
                .await?
                .iter()
                .any(|p| !p["metadata"]["deletionTimestamp"].is_null()))
        })
        .await?;
        k.restart().await?;
        ensure!(
            k.exists("Secret", ns, name(tls)).await?,
            "restart removed a mounted copy"
        );
        k.patch("Pod", ns, "cleanup-blocker", json!({"metadata":{"finalizers":[]}}))
            .await?;
        wait("restart and absent sources permit complete cleanup", 120, async || {
            k.clean(ns, &sel).await
        })
        .await?;
        wait("journal cleanup completes", 90, async || {
            Ok(k.list("Secret", SYSTEM, &sel).await?.is_empty())
        })
        .await?;
        if ns != SYSTEM {
            ensure!(
                k.list("ConfigMap", ns, "controller.tlb.io/workload-owner")
                    .await?
                    .is_empty(),
                "owner leaked"
            );
        }
        ensure!(
            k.exists("Secret", app, "source-tls").await?,
            "source Secret deleted by cleanup"
        );
        k.delete("Namespace", "", app).await?;
        k.gone("Namespace", "", app).await?;
    }
    // Both API scopes obey opt-in and revocation, including simultaneous namespace reset.
    for kind in ["TunnelClass", "ClusterTunnelClass"] {
        let app = "runtime-policy";
        k.namespace(app).await?;
        let class_ns = if kind == "TunnelClass" { app } else { "" };
        secret(k, app, "key", json!({"key":"test"})).await?;
        k.configure("tlb-tunnels", true).await?;
        k.apply(object(kind,class_ns,"policy",json!({"spec":{"netbird":{"managementUrl":"https://netbird.example.com","setupKeyRef":{"name":"key","key":"key","namespace":app},"image":"netbirdio/netbird:latest","enableEbpfCapabilities":false}}}))).await?;
        let service = k
            .service(app, "policy", "policy", json!({"tlb.io/replicas":"0"}))
            .await?;
        let sel = selector(&service);
        k.present(
            "StatefulSet",
            "tlb-tunnels",
            &sel,
            "explicit opt-in permits custom image",
        )
        .await?;
        k.patch(
            kind,
            class_ns,
            "policy",
            json!({"spec":{"netbird":{"enableEbpfCapabilities":true}}}),
        )
        .await?;
        wait("eBPF opt-in updates existing workload", 90, async || {
            Ok(entries(
                &k.first("StatefulSet", "tlb-tunnels", &sel).await?["spec"]["template"]["spec"]["containers"][0]["env"],
            )
            .iter()
            .any(|e| e["name"] == "NB_DISABLE_EBPF_WG_PROXY" && e["value"] == "false"))
        })
        .await?;
        let sts = k.first("StatefulSet", "tlb-tunnels", &sel).await?;
        ensure!(
            sts["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"]["add"]
                == json!(["NET_ADMIN", "SYS_ADMIN", "SYS_RESOURCE"]),
            "eBPF capabilities missing"
        );
        k.configure(SYSTEM, false).await?;
        wait("revoking opt-in stops affected workloads", 90, async || {
            Ok(k.list("StatefulSet", "tlb-tunnels", &sel).await?.is_empty())
        })
        .await?;
        ensure!(
            !k.list("Secret", "tlb-tunnels", &sel).await?.is_empty()
                && !k.list("Secret", SYSTEM, &sel).await?.is_empty(),
            "revocation removed recovery credentials"
        );
        k.delete("Namespace", "", app).await?;
        wait("revoked policy and namespace reset permit cleanup", 120, async || {
            Ok(k.clean("tlb-tunnels", &sel).await? && k.list("Secret", SYSTEM, &sel).await?.is_empty())
        })
        .await?;
        ensure!(
            k.list("ConfigMap", "tlb-tunnels", "controller.tlb.io/workload-owner")
                .await?
                .is_empty(),
            "owner leaked after revocation"
        );
        if kind == "ClusterTunnelClass" {
            k.delete(kind, "", "policy").await?;
            k.gone(kind, "", "policy").await?;
        }
        k.gone("Namespace", "", app).await?;
    }
    Ok(())
}
