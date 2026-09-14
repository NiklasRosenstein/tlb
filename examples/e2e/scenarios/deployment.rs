use crate::kubernetes::*;
use anyhow::{Result, ensure};
use kube::api::{Patch, PatchParams};
use serde::Deserialize;
use serde_json::{Value, json};
pub async fn run(k: &Kubernetes) -> Result<()> {
    let mut desired = object("ConfigMap", SYSTEM, "guard-test", json!({"data":{"owned":"initial"}}));
    let original = k.create(desired.clone()).await?;
    k.patch(
        "ConfigMap",
        SYSTEM,
        "guard-test",
        json!({"data":{"foreign":"preserve"}}),
    )
    .await?;
    desired["metadata"]["uid"] = original["metadata"]["uid"].clone();
    desired["metadata"]["resourceVersion"] = original["metadata"]["resourceVersion"].clone();
    desired["data"]["owned"] = "updated".into();
    let api = k.api("ConfigMap", SYSTEM);
    let params = PatchParams::apply("tlb-guard-test").force();
    let error = api
        .patch("guard-test", &params, &Patch::Apply(&desired))
        .await
        .expect_err("stale RV must fail");
    ensure!(
        matches!(error,kube::Error::Api(ref e) if e.code==409),
        "expected resource version conflict: {error}"
    );
    let current = k.get("ConfigMap", SYSTEM, "guard-test").await?;
    desired["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"].clone();
    desired["metadata"]["uid"] = "00000000-0000-0000-0000-000000000001".into();
    let error = api
        .patch("guard-test", &params, &Patch::Apply(&desired))
        .await
        .expect_err("foreign UID must fail");
    ensure!(
        error.to_string().to_lowercase().contains("uid"),
        "expected UID guard failure: {error}"
    );
    desired["metadata"]["uid"] = current["metadata"]["uid"].clone();
    api.patch("guard-test", &params, &Patch::Apply(&desired)).await?;
    ensure!(
        k.get("ConfigMap", SYSTEM, "guard-test").await?["data"] == json!({"owned":"updated","foreign":"preserve"}),
        "apply removed foreign fields"
    );
    k.delete("ConfigMap", SYSTEM, "guard-test").await?;
    pass("forced apply preserves UID/RV guards and foreign fields");
    k.delete("CustomResourceDefinition", "", "tunnelclasses.tlb.io").await?;
    k.gone("CustomResourceDefinition", "", "tunnelclasses.tlb.io").await?;
    let unavailable = wait("missing primary watch resource clears readiness", 60, async || {
        Ok(k.list("Pod", SYSTEM, CONTROLLER)
            .await?
            .iter()
            .filter(|p| ready(p))
            .count()
            < 2)
    })
    .await;
    for doc in serde_yaml::Deserializer::from_str(include_str!("../../../deploy/crds.yaml")) {
        let value = Value::deserialize(doc)?;
        if !value.is_null() {
            k.apply(value).await?;
        }
    }
    unavailable?;
    wait("restoring CRDs recovers readiness", 90, async || {
        Ok(k.list("Pod", SYSTEM, CONTROLLER)
            .await?
            .iter()
            .filter(|p| ready(p))
            .count()
            == 2)
    })
    .await?;
    k.failover().await?;
    Ok(())
}
