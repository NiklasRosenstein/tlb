//! UID-checked Kubernetes mutations shared by the providers.
use std::{collections::BTreeMap, fmt::Debug};

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, StatefulSet},
        core::v1::{ConfigMap, LoadBalancerIngress, PersistentVolumeClaim, Pod, Secret, Service},
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
            (
                "controller.tlb.io/service-namespace".into(),
                self.binding
                    .data
                    .service
                    .namespace()
                    .ok_or_else(|| Error::ConfigError("Service namespace missing".into()))?,
            ),
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
        self.binding
            .data
            .workload_owner
            .clone()
            .map(|owner| vec![owner])
            .ok_or_else(|| Error::ConfigError("binding workload owner is not initialized".into()))
    }

    pub fn metadata(&self, name: &str) -> Result<ObjectMeta> {
        Ok(ObjectMeta {
            name: Some(name.into()),
            namespace: Some(self.binding.data.workload_namespace.clone()),
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
                self.binding
                    .data
                    .workload_owner
                    .as_ref()
                    .is_some_and(|owner| refs.iter().any(|r| r == owner))
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
    let namespace = &ctx.binding.data.workload_namespace;
    let api: Api<K> = Api::namespaced(ctx.client.clone(), namespace);
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
    let pods = Api::<Pod>::namespaced(ctx.client.clone(), &ctx.binding.data.workload_namespace)
        .list(&ListParams::default().labels(&ctx.selector()?))
        .await?;
    if deployments || statefulsets || !pods.items.is_empty() {
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

const OWNER_LABEL: &str = "controller.tlb.io/workload-owner";

fn local_owner_name(binding: &crate::state::Binding) -> Result<String> {
    Ok(format!("tlb-owner-{}", binding.uid()?))
}

/// Persist the owner before any provider can create dependent resources.
pub async fn ensure_owner(binding: &mut crate::state::Binding, client: kube::Client) -> Result<bool> {
    let namespace = &binding.data.workload_namespace;
    if binding.secret.namespace().as_deref() == Some(namespace) {
        let owner = OwnerReference {
            api_version: "v1".into(),
            kind: "Secret".into(),
            name: binding.secret.name_any(),
            uid: binding.uid()?.into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        };
        if binding.data.workload_owner.as_ref() != Some(&owner) {
            binding.data.workload_owner = Some(owner);
            binding.save(client).await?;
        }
        return Ok(true);
    }
    let api = Api::<ConfigMap>::namespaced(client.clone(), namespace);
    let name = local_owner_name(binding)?;
    let existing = api.get_opt(&name).await?;
    let object = match existing {
        Some(object) => {
            if object.labels().get(OWNER_LABEL).map(String::as_str) != Some(binding.uid()?) {
                return Err(Error::ConfigError(
                    "workload owner name is occupied by an unrelated ConfigMap".into(),
                ));
            }
            if object.metadata.deletion_timestamp.is_some()
                || binding
                    .data
                    .workload_owner
                    .as_ref()
                    .is_some_and(|owner| object.uid().as_ref() != Some(&owner.uid))
            {
                return Ok(false);
            }
            object
        }
        None if binding.data.workload_owner.is_some() => return Ok(false),
        None => {
            api.create(
                &PostParams::default(),
                &ConfigMap {
                    metadata: ObjectMeta {
                        name: Some(name),
                        namespace: Some(namespace.clone()),
                        labels: Some(BTreeMap::from([(OWNER_LABEL.into(), binding.uid()?.into())])),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await?
        }
    };
    if binding.data.workload_owner.is_none() {
        binding.data.workload_owner = Some(OwnerReference {
            api_version: "v1".into(),
            kind: "ConfigMap".into(),
            name: object.name_any(),
            uid: required_uid(&object.metadata)?.into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        });
        binding.save(client).await?;
    }
    Ok(true)
}

pub async fn cleanup_owner(ctx: &ReconcileContext) -> Result<()> {
    if ctx.binding.secret.namespace().as_deref() == Some(&ctx.binding.data.workload_namespace) {
        return Ok(());
    }
    let api = Api::<ConfigMap>::namespaced(ctx.client.clone(), &ctx.binding.data.workload_namespace);
    if let Some(object) = api.get_opt(&local_owner_name(&ctx.binding)?).await? {
        if object.labels().get(OWNER_LABEL).map(String::as_str) != Some(ctx.binding.uid()?)
            || ctx
                .binding
                .data
                .workload_owner
                .as_ref()
                .is_some_and(|owner| object.uid().as_ref() != Some(&owner.uid))
        {
            return Err(Error::ConfigError("refusing to delete unrelated workload owner".into()));
        }
        delete(&api, &object).await?;
        return Err(Error::CleanupPending);
    }
    Ok(())
}

/// Avoid writes and Pod rotations when only source metadata changes.
pub async fn apply_secret(ctx: &ReconcileContext, desired: &Secret) -> Result<Secret> {
    let api = Api::<Secret>::namespaced(ctx.client.clone(), &ctx.binding.data.workload_namespace);
    if let Some(existing) = api.get_opt(&desired.name_any()).await? {
        ctx.check_owned(&existing.metadata)?;
        if existing.metadata.deletion_timestamp.is_some() {
            return Err(Error::CleanupPending);
        }
        if existing.data == desired.data && existing.type_ == desired.type_ {
            return Ok(existing);
        }
    }
    apply(ctx, &api, desired).await
}

pub async fn prune_secret(ctx: &ReconcileContext, name: &str) -> Result<()> {
    let api = Api::<Secret>::namespaced(ctx.client.clone(), &ctx.binding.data.workload_namespace);
    let Some(secret) = api.get_opt(name).await? else {
        return Ok(());
    };
    ctx.check_owned(&secret.metadata)?;
    let pods = Api::<Pod>::namespaced(ctx.client.clone(), &ctx.binding.data.workload_namespace)
        .list(&ListParams::default().labels(&ctx.selector()?))
        .await?;
    if pods.iter().any(|pod| {
        pod.spec
            .as_ref()
            .and_then(|spec| spec.volumes.as_ref())
            .is_some_and(|volumes| {
                volumes
                    .iter()
                    .any(|v| v.secret.as_ref().and_then(|s| s.secret_name.as_deref()) == Some(name))
            })
    }) {
        return Ok(());
    }
    delete(&api, &secret).await
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::test_support::{Exchange, context, mock};

    fn list(path: &'static str, items: serde_json::Value) -> Exchange {
        Exchange {
            method: "GET",
            path,
            status: 200,
            response: json!({"metadata":{},"items":items}),
            check: |_| {},
        }
    }

    #[tokio::test]
    async fn remaining_pods_block_storage_cleanup_even_without_workload_controllers() {
        let (client, requests) = mock(vec![
            list("/apis/apps/v1/namespaces/tunnels/deployments", json!([])),
            list("/apis/apps/v1/namespaces/tunnels/statefulsets", json!([])),
            list(
                "/api/v1/namespaces/tunnels/pods",
                json!([{"metadata":{"name":"terminating","deletionTimestamp":"2026-01-01T00:00:00Z"}}]),
            ),
        ]);
        let mut ctx = context(client);
        ctx.binding.data.workload_namespace = "tunnels".into();
        assert!(matches!(cleanup_workloads(&ctx).await, Err(Error::CleanupPending)));
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn copied_secret_cleanup_uses_persisted_namespace_and_uid_without_source_reads() {
        let (client, _) = mock(vec![]);
        let mut ctx = context(client);
        ctx.binding.data.workload_namespace = "tunnels".into();
        let mut metadata = ctx.metadata("runtime-key").unwrap();
        metadata.uid = Some("runtime-uid".into());
        metadata.resource_version = Some("4".into());
        let (client, requests) = mock(vec![
            list("/api/v1/namespaces/tunnels/configmaps", json!([])),
            list("/api/v1/namespaces/tunnels/secrets", json!([{"metadata":metadata}])),
            Exchange {
                method: "DELETE",
                path: "/api/v1/namespaces/tunnels/secrets/runtime-key",
                status: 200,
                response: json!({"apiVersion":"v1","kind":"Status","status":"Success"}),
                check: |body| {
                    assert_eq!(body["preconditions"]["uid"], "runtime-uid");
                    assert_eq!(body["preconditions"]["resourceVersion"], "4");
                },
            },
            list("/api/v1/namespaces/tunnels/persistentvolumeclaims", json!([])),
        ]);
        ctx.client = client;
        assert!(matches!(cleanup_storage(&ctx).await, Err(Error::CleanupPending)));
        assert!(requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unchanged_runtime_secret_does_not_write_or_rotate() {
        let (client, _) = mock(vec![]);
        let ctx = context(client);
        let desired = Secret {
            metadata: ctx.metadata("key").unwrap(),
            data: Some(BTreeMap::from([("key".into(), k8s_openapi::ByteString(vec![1]))])),
            ..Default::default()
        };
        let mut existing = desired.clone();
        existing.metadata.resource_version = Some("3".into());
        let (client, requests) = mock(vec![Exchange {
            method: "GET",
            path: "/api/v1/namespaces/apps/secrets/key",
            status: 200,
            response: serde_json::to_value(existing).unwrap(),
            check: |_| {},
        }]);
        let ctx = context(client);
        assert_eq!(
            apply_secret(&ctx, &desired)
                .await
                .unwrap()
                .resource_version()
                .as_deref(),
            Some("3")
        );
        assert!(requests.lock().unwrap().is_empty());
    }
}
