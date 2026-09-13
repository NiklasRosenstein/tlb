//! Kubernetes operations use the dedicated cluster client; no ambient context is consulted.
use anyhow::{Context, Result, ensure};
use kube::{
    Api, Client,
    api::{ApiResource, DeleteParams, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams, PostParams},
};
use serde_json::{Value, json};
use std::{future::Future, time::Duration};

pub const SYSTEM: &str = "kube-system";
pub const BINDING: &str = "controller.tlb.io/binding-uid";
pub const CONTROLLER: &str = "app.kubernetes.io/instance=tlb-controller";
#[derive(Clone)]
pub struct Kubernetes(pub Client);

pub fn resource(kind: &str) -> ApiResource {
    let (group, version, plural) = match kind {
        "Namespace" => ("", "v1", "namespaces"),
        "Secret" => ("", "v1", "secrets"),
        "Service" => ("", "v1", "services"),
        "Pod" => ("", "v1", "pods"),
        "ConfigMap" => ("", "v1", "configmaps"),
        "PersistentVolumeClaim" => ("", "v1", "persistentvolumeclaims"),
        "Deployment" => ("apps", "v1", "deployments"),
        "StatefulSet" => ("apps", "v1", "statefulsets"),
        "TunnelClass" => ("tlb.io", "v1alpha1", "tunnelclasses"),
        "ClusterTunnelClass" => ("tlb.io", "v1alpha1", "clustertunnelclasses"),
        "Event" => ("events.k8s.io", "v1", "events"),
        "Ingress" => ("networking.k8s.io", "v1", "ingresses"),
        "Lease" => ("coordination.k8s.io", "v1", "leases"),
        "ClusterRole" => ("rbac.authorization.k8s.io", "v1", "clusterroles"),
        "CustomResourceDefinition" => ("apiextensions.k8s.io", "v1", "customresourcedefinitions"),
        "ServiceAccount" => ("", "v1", "serviceaccounts"),
        "Role" => ("rbac.authorization.k8s.io", "v1", "roles"),
        "RoleBinding" => ("rbac.authorization.k8s.io", "v1", "rolebindings"),
        "ClusterRoleBinding" => ("rbac.authorization.k8s.io", "v1", "clusterrolebindings"),
        _ => panic!("unsupported test resource {kind}"),
    };
    ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk(group, version, kind), plural)
}
pub fn object(kind: &str, ns: &str, name: &str, fields: Value) -> Value {
    let mut value = json!({"apiVersion":resource(kind).api_version,"kind":kind,"metadata":{"name":name}});
    if !ns.is_empty() {
        value["metadata"]["namespace"] = ns.into();
    }
    for (key, field) in fields.as_object().expect("object fields") {
        if key == "metadata" {
            value["metadata"]
                .as_object_mut()
                .unwrap()
                .extend(field.as_object().unwrap().clone());
        } else {
            value[key] = field.clone();
        }
    }
    value
}
pub fn name(v: &Value) -> &str {
    v["metadata"]["name"].as_str().expect("resource name")
}
pub fn uid(v: &Value) -> &str {
    v["metadata"]["uid"].as_str().expect("resource UID")
}
pub fn selector(v: &Value) -> String {
    format!("controller.tlb.io/service-uid={}", uid(v))
}
pub fn entries(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or_default()
}
pub fn ready(p: &Value) -> bool {
    entries(&p["status"]["conditions"])
        .iter()
        .any(|c| c["type"] == "Ready" && c["status"] == "True")
}
pub fn pass(message: &str) {
    eprintln!("PASS {message}");
}
pub async fn wait<F, Fut>(description: &str, seconds: u64, mut check: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            if check().await.with_context(|| format!("checking {description}"))? {
                pass(description);
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .with_context(|| format!("timed out after {seconds}s: {description}"))?
}
impl Kubernetes {
    pub fn api(&self, kind: &str, ns: &str) -> Api<DynamicObject> {
        let resource = resource(kind);
        if ns.is_empty() {
            Api::all_with(self.0.clone(), &resource)
        } else {
            Api::namespaced_with(self.0.clone(), ns, &resource)
        }
    }
    pub async fn get(&self, kind: &str, ns: &str, name: &str) -> Result<Value> {
        Ok(serde_json::to_value(self.api(kind, ns).get(name).await?)?)
    }
    pub async fn exists(&self, kind: &str, ns: &str, name: &str) -> Result<bool> {
        Ok(self.api(kind, ns).get_opt(name).await?.is_some())
    }
    pub async fn list(&self, kind: &str, ns: &str, selector: &str) -> Result<Vec<Value>> {
        self.api(kind, ns)
            .list(&ListParams::default().labels(selector))
            .await?
            .items
            .into_iter()
            .map(|v| Ok(serde_json::to_value(v)?))
            .collect()
    }
    pub async fn apply(&self, value: Value) -> Result<Value> {
        let kind = value["kind"].as_str().context("kind")?;
        let ns = value["metadata"]["namespace"].as_str().unwrap_or_default();
        Ok(serde_json::to_value(
            self.api(kind, ns)
                .patch(
                    name(&value),
                    &PatchParams::apply("tlb-e2e").force(),
                    &Patch::Apply(&value),
                )
                .await?,
        )?)
    }
    pub async fn create(&self, value: Value) -> Result<Value> {
        let api = self.api(
            value["kind"].as_str().context("kind")?,
            value["metadata"]["namespace"].as_str().unwrap_or_default(),
        );
        Ok(serde_json::to_value(
            api.create(&PostParams::default(), &serde_json::from_value(value)?)
                .await?,
        )?)
    }
    pub async fn patch(&self, kind: &str, ns: &str, name: &str, value: Value) -> Result<Value> {
        Ok(serde_json::to_value(
            self.api(kind, ns)
                .patch(name, &PatchParams::default(), &Patch::Merge(value))
                .await?,
        )?)
    }
    pub async fn delete(&self, kind: &str, ns: &str, name: &str) -> Result<()> {
        match self.api(kind, ns).delete(name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    pub async fn gone(&self, kind: &str, ns: &str, name: &str) -> Result<()> {
        wait(&format!("{kind} {ns}/{name} deleted"), 90, async || {
            Ok(!self.exists(kind, ns, name).await?)
        })
        .await
    }
    pub async fn first(&self, kind: &str, ns: &str, selector: &str) -> Result<Value> {
        self.list(kind, ns, selector)
            .await?
            .into_iter()
            .next()
            .with_context(|| format!("no {kind} in {ns} matching {selector}"))
    }
    pub async fn present(&self, kind: &str, ns: &str, selector: &str, message: &str) -> Result<Value> {
        wait(message, 90, async || {
            Ok(!self.list(kind, ns, selector).await?.is_empty())
        })
        .await?;
        self.first(kind, ns, selector).await
    }
    pub async fn clean(&self, ns: &str, selector: &str) -> Result<bool> {
        for kind in ["Pod", "Deployment", "StatefulSet", "Secret", "PersistentVolumeClaim"] {
            if !self.list(kind, ns, selector).await?.is_empty() {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub async fn namespace(&self, ns: &str) -> Result<()> {
        self.apply(object("Namespace", "", ns, json!({}))).await?;
        Ok(())
    }
    pub async fn service(&self, ns: &str, name: &str, class: &str, annotations: Value) -> Result<Value> {
        self.apply(object("Service",ns,name,json!({"metadata":{"annotations":annotations},"spec":{"type":"LoadBalancer","loadBalancerClass":format!("tlb.io/{class}"),"ports":[{"port":80}]}}))).await
    }
    pub async fn annotations(&self, ns: &str, name: &str, annotations: Value) -> Result<()> {
        self.patch("Service", ns, name, json!({"metadata":{"annotations":annotations}}))
            .await?;
        Ok(())
    }
    pub async fn rollout(&self) -> Result<()> {
        wait("controller rollout ready", 120, async || {
            let d = self.get("Deployment", SYSTEM, "tlb-controller").await?;
            let n = d["spec"]["replicas"].as_i64().unwrap_or(1);
            Ok(
                d["status"]["observedGeneration"].as_i64() >= d["metadata"]["generation"].as_i64()
                    && d["status"]["updatedReplicas"].as_i64() == Some(n)
                    && d["status"]["availableReplicas"].as_i64() == Some(n)
                    && d["status"]["replicas"].as_i64() == Some(n),
            )
        })
        .await
    }
    pub async fn configure(&self, ns: &str, unsafe_overrides: bool) -> Result<()> {
        self.api("Deployment",SYSTEM).patch("tlb-controller",&PatchParams::default(),&Patch::Strategic(json!({"spec":{"template":{"spec":{"containers":[{"name":"tlb-controller","env":[
            {"name":"TLB_WORKLOAD_NAMESPACE","value":ns},{"name":"TLB_ALLOW_UNSAFE_WORKLOAD_OVERRIDES","value":unsafe_overrides.to_string()}]}]}}}}))).await?;
        self.rollout().await?;
        // Leader replacement waits for expiry of the previous 15-second Lease.
        tokio::time::sleep(Duration::from_secs(17)).await;
        Ok(())
    }
    pub async fn restart(&self) -> Result<()> {
        self.patch("Deployment",SYSTEM,"tlb-controller",json!({"spec":{"template":{"metadata":{"annotations":{"e2e.tlb.io/restart":rand::random::<u64>().to_string()}}}}})).await?;
        self.rollout().await
    }
    pub async fn logs(&self, ns: &str, pod: &str, container: &str) -> Result<String> {
        Ok(Api::<k8s_openapi::api::core::v1::Pod>::namespaced(self.0.clone(), ns)
            .logs(
                pod,
                &kube::api::LogParams {
                    container: Some(container.into()),
                    tail_lines: Some(500),
                    ..Default::default()
                },
            )
            .await?)
    }
    pub async fn failover(&self) -> Result<()> {
        let initial = self.get("Lease", SYSTEM, "tlb-controller").await?["spec"]["holderIdentity"].clone();
        let mut active = Vec::new();
        for pod in self.list("Pod", SYSTEM, CONTROLLER).await? {
            if self
                .logs(SYSTEM, name(&pod), "tlb-controller")
                .await?
                .contains("acquired controller leadership")
            {
                active.push(pod);
            }
        }
        ensure!(
            active.len() == 1,
            "expected exactly one elected controller, got {}",
            active.len()
        );
        self.delete("Pod", SYSTEM, name(&active[0])).await?;
        wait("standby takes over controller leadership", 90, async || {
            Ok(self.get("Lease", SYSTEM, "tlb-controller").await?["spec"]["holderIdentity"] != initial)
        })
        .await?;
        self.rollout().await
    }
}
