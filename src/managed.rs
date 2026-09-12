//! UID-checked Kubernetes mutations shared by the providers.
use std::{collections::BTreeMap, fmt::Debug};

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, StatefulSet},
        core::v1::{ConfigMap, LoadBalancerIngress, PersistentVolumeClaim, Secret, Service},
    },
    apimachinery::pkg::apis::meta::v1::OwnerReference,
};
use kube::{
    Api, Resource, ResourceExt,
    api::{DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams, Preconditions, PropagationPolicy},
    core::NamespaceResourceScope,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::{
    Error, ReconcileContext, Result,
    state::{BINDING_LABEL, CLASS_UID_LABEL, SERVICE_UID_LABEL, required_uid},
};

pub const FIELD_MANAGER: &str = "tlb-controller";

impl ReconcileContext {
    pub fn labels(&self) -> Result<BTreeMap<String, String>> {
        Ok(BTreeMap::from([
            (BINDING_LABEL.into(), self.binding.uid()?.into()),
            (CLASS_UID_LABEL.into(), required_uid(&self.metadata)?.into()),
            (
                SERVICE_UID_LABEL.into(),
                required_uid(&self.binding.data.service.metadata)?.into(),
            ),
            (
                crate::PROVIDER_LABEL.into(),
                if self.binding.data.class.spec.netbird.is_some() {
                    "netbird"
                } else {
                    "cloudflare"
                }
                .into(),
            ),
        ]))
    }

    pub fn selector(&self) -> Result<String> {
        Ok(format!("{BINDING_LABEL}={}", self.binding.uid()?))
    }

    pub fn resource_name(&self, prefix: &str, suffix: &str) -> Result<String> {
        self.resource_name_with_limit(prefix, suffix, 63)
    }

    pub fn resource_name_with_limit(&self, prefix: &str, suffix: &str, limit: usize) -> Result<String> {
        let uid = self.binding.uid()?;
        let readable = format!("{prefix}{}", self.binding.data.service.name_any());
        let max = limit.saturating_sub(uid.len() + suffix.len() + 1);
        let readable = readable.chars().take(max).collect::<String>();
        Ok(format!("{}-{uid}{suffix}", readable.trim_end_matches('-')))
    }

    pub fn owner_references(&self) -> Result<Vec<OwnerReference>> {
        let service = &self.binding.data.service;
        Ok(vec![OwnerReference {
            api_version: "v1".into(),
            kind: "Service".into(),
            name: service.name_any(),
            uid: required_uid(&service.metadata)?.into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }])
    }

    pub fn metadata(&self, name: &str) -> Result<ObjectMeta> {
        Ok(ObjectMeta {
            name: Some(name.into()),
            namespace: self.binding.data.service.namespace(),
            labels: Some(self.labels()?),
            owner_references: Some(self.owner_references()?),
            ..Default::default()
        })
    }

    pub fn check_owned(&self, metadata: &ObjectMeta) -> Result<()> {
        if metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(BINDING_LABEL))
            .map(String::as_str)
            != Some(self.binding.uid()?)
            || !metadata.owner_references.as_ref().is_some_and(|refs| {
                refs.iter().any(|r| {
                    r.kind == "Service"
                        && r.api_version == "v1"
                        && Some(&r.uid) == self.binding.data.service.metadata.uid.as_ref()
                })
            })
        {
            return Err(Error::ConfigError(format!(
                "refusing to mutate unrelated resource {}/{}",
                metadata.namespace.as_deref().unwrap_or_default(),
                metadata.name.as_deref().unwrap_or_default()
            )));
        }
        Ok(())
    }
}

pub async fn apply<K>(ctx: &ReconcileContext, api: &Api<K>, desired: &K) -> Result<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + Serialize + DeserializeOwned,
{
    let mut desired = desired.clone();
    match api.get_opt(&desired.name_any()).await? {
        Some(existing) => {
            ctx.check_owned(existing.meta())?;
            if existing.meta().deletion_timestamp.is_some() {
                return Err(Error::CleanupPending);
            }
            desired.meta_mut().uid = existing.uid();
            desired.meta_mut().resource_version = existing.resource_version();
            Ok(api
                .patch(
                    &desired.name_any(),
                    // The controller is authoritative for the fields in its desired object.
                    // UID and resourceVersion fence this write to the verified resource instance.
                    &PatchParams::apply(FIELD_MANAGER).force(),
                    &Patch::Apply(&desired),
                )
                .await?)
        }
        None => Ok(api
            .create(
                &PostParams {
                    field_manager: Some(FIELD_MANAGER.into()),
                    ..Default::default()
                },
                &desired,
            )
            .await?),
    }
}

/// Resource version and UID preconditions preserve concurrent finalizers and object identity.
pub async fn set_finalizer<K>(api: &Api<K>, object: &K, name: &str, present: bool) -> Result<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + Serialize + DeserializeOwned,
{
    let mut finalizers = object.finalizers().to_vec();
    let contains = finalizers.iter().any(|f| f == name);
    if contains == present {
        return Ok(object.clone());
    }
    if present {
        if object.meta().deletion_timestamp.is_some() {
            return Err(Error::CleanupPending);
        }
        finalizers.push(name.into());
    } else {
        finalizers.retain(|f| f != name);
    }
    let resource_version = object
        .resource_version()
        .ok_or_else(|| Error::ConfigError("resource version required for finalizer mutation".into()))?;
    Ok(api.patch(&object.name_any(), &PatchParams::default(), &Patch::Merge(json!({
        "metadata": { "uid": required_uid(object.meta())?, "resourceVersion": resource_version, "finalizers": finalizers }
    }))).await?)
}

pub async fn delete<K>(api: &Api<K>, object: &K) -> Result<()>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned,
{
    if object.meta().deletion_timestamp.is_some() {
        return Ok(());
    }
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(required_uid(object.meta())?.into()),
            resource_version: object.resource_version(),
        }),
        propagation_policy: Some(PropagationPolicy::Foreground),
        ..Default::default()
    };
    match api.delete(&object.name_any(), &params).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e.into()),
    }
}

async fn delete_kind<K>(ctx: &ReconcileContext) -> Result<bool>
where
    K: Resource<DynamicType = (), Scope = NamespaceResourceScope> + Clone + Debug + DeserializeOwned,
{
    // Bindings carry immutable namespace identity; selectors never use display names.
    let namespace = ctx
        .binding
        .data
        .service
        .namespace()
        .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?;
    let api: Api<K> = Api::namespaced(ctx.client.clone(), &namespace);
    let objects = api.list(&ListParams::default().labels(&ctx.selector()?)).await?;
    let found = !objects.items.is_empty();
    for object in objects {
        ctx.check_owned(object.meta())?;
        delete(&api, &object).await?;
    }
    Ok(found)
}

/// Wait for workloads and their Pods before removing mounted Secrets and retained volumes.
pub async fn cleanup_workloads(ctx: &ReconcileContext) -> Result<()> {
    let deployments = delete_kind::<Deployment>(ctx).await?;
    let statefulsets = delete_kind::<StatefulSet>(ctx).await?;
    if deployments || statefulsets {
        return Err(Error::CleanupPending);
    }
    Ok(())
}

pub async fn cleanup_storage(ctx: &ReconcileContext) -> Result<()> {
    let configmaps = delete_kind::<ConfigMap>(ctx).await?;
    let secrets = delete_kind::<Secret>(ctx).await?;
    let pvcs = delete_kind::<PersistentVolumeClaim>(ctx).await?;
    if configmaps || secrets || pvcs {
        return Err(Error::CleanupPending);
    }
    Ok(())
}

pub async fn patch_ingress(
    ctx: &ReconcileContext,
    service: &Service,
    mut ingress: Vec<LoadBalancerIngress>,
) -> Result<()> {
    ingress.sort_by_key(|i| (i.hostname.clone(), i.ip.clone()));
    ingress.dedup();
    let api: Api<Service> = Api::namespaced(
        ctx.client.clone(),
        &service
            .namespace()
            .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?,
    );
    let Some(current) = api.get_opt(&service.name_any()).await? else {
        return Ok(());
    };
    if current.uid() != service.uid() {
        return Ok(());
    }
    let existing = current
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|s| s.ingress.as_ref())
        .cloned()
        .unwrap_or_default();
    if existing == ingress {
        return Ok(());
    }
    api.patch_status(
        &service.name_any(),
        &PatchParams::default(),
        &Patch::Merge(json!({
            "metadata": { "uid": required_uid(&current.metadata)?, "resourceVersion": current.resource_version() },
            "status": { "loadBalancer": { "ingress": ingress } }
        })),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Exchange, context, mock};

    fn conflict() -> serde_json::Value {
        json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "message":"conflict",
            "reason":"Conflict", "code":409})
    }

    #[tokio::test]
    async fn finalizers_preserve_other_owners_and_reject_stale_versions() {
        let (client, requests) = mock(vec![Exchange {
            method: "PATCH",
            path: "/api/v1/namespaces/apps/services/api",
            status: 409,
            response: conflict(),
            check: |body| {
                assert_eq!(body["metadata"]["uid"], "service-uid");
                assert_eq!(body["metadata"]["resourceVersion"], "1");
                assert_eq!(body["metadata"]["finalizers"], json!(["other.io/keep", "tlb.io/test"]));
            },
        }]);
        let mut ctx = context(client.clone());
        ctx.binding.data.service.metadata.finalizers = Some(vec!["other.io/keep".into()]);
        let result = set_finalizer(
            &Api::namespaced(client, "apps"),
            &ctx.binding.data.service,
            "tlb.io/test",
            true,
        )
        .await;
        assert!(matches!(result, Err(Error::KubeError(kube::Error::Api(e))) if e.code == 409));
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_rejects_unowned_collision_without_mutating_it() {
        let (client, requests) = mock(vec![Exchange {
            method: "GET",
            path: "/api/v1/namespaces/apps/configmaps/config",
            status: 200,
            response: json!({"metadata":{"name":"config", "namespace":"apps", "uid":"foreign"}}),
            check: |_| {},
        }]);
        let ctx = context(client.clone());
        let desired = ConfigMap {
            metadata: ctx.metadata("config").unwrap(),
            ..Default::default()
        };
        assert!(apply(&ctx, &Api::namespaced(client, "apps"), &desired).await.is_err());
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unchanged_status_has_no_write() {
        let (client, requests) = mock(vec![Exchange {
            method: "GET",
            path: "/api/v1/namespaces/apps/services/api",
            status: 200,
            response: json!({"metadata":{"name":"api", "namespace":"apps", "uid":"service-uid"},
                "status":{"loadBalancer":{"ingress":[{"hostname":"example.com"}]}}}),
            check: |_| {},
        }]);
        let ctx = context(client);
        let ingress = LoadBalancerIngress {
            hostname: Some("example.com".into()),
            ..Default::default()
        };
        patch_ingress(&ctx, &ctx.binding.data.service, vec![ingress.clone(), ingress])
            .await
            .unwrap();
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn deletion_is_uid_guarded_and_404_is_success() {
        let (client, requests) = mock(vec![Exchange {
            method: "DELETE",
            path: "/api/v1/namespaces/apps/services/api",
            status: 404,
            response: json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "message":"gone",
                "reason":"NotFound", "code":404}),
            check: |body| {
                assert_eq!(body["preconditions"]["uid"], "service-uid");
                assert_eq!(body["preconditions"]["resourceVersion"], "1");
                assert_eq!(body["propagationPolicy"], "Foreground");
            },
        }]);
        let ctx = context(client.clone());
        delete(&Api::namespaced(client, "apps"), &ctx.binding.data.service)
            .await
            .unwrap();
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn statefulset_names_reserve_space_for_the_pod_ordinal() {
        let (client, _) = mock(vec![]);
        let mut ctx = context(client);
        ctx.binding.data.service.metadata.name = Some("a".repeat(63));
        let name = ctx.resource_name_with_limit("tunnel-", "", 52).unwrap();
        assert!(format!("{name}-2147483647").len() <= 63);
        assert!(name.ends_with(ctx.binding.uid().unwrap()));
        assert!(crate::config::dns_label(&name));
    }
}
