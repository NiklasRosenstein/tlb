---
title: Installation
description: Install the TLB controller and its custom resource definitions with kubectl.
---

You need a Kubernetes cluster and `kubectl` access with permission to install cluster-scoped resources. Tunnel Pods
need outbound connectivity to their provider and connectivity to the Service they expose.

Run **one TLB installation per cluster**. Multiple controller replicas share a leadership Lease.

## Install

Use the manifest from the release tag you want to run:

```bash
git clone https://github.com/NiklasRosenstein/tlb.git
cd tlb
# Select a release tag before installing its manifest.
kubectl apply --server-side -f deploy/tlb.yaml
kubectl -n kube-system rollout status deployment/tlb-controller --timeout=120s
```

The bundle installs both CRDs, the controller ServiceAccount, RBAC, and Deployment. The controller, binding journals,
leadership Lease, and tunnel workloads default to `kube-system`. The manifest does not create or manage that Namespace.

```bash
kubectl -n kube-system logs deployment/tlb-controller --tail=50
kubectl get crd tunnelclasses.tlb.io clustertunnelclasses.tlb.io
```

## Customize

Keep the manifest and controller image from the same release. Apply changes through your GitOps tool or a local
manifest patch. For example, to run two replicas:

```bash
kubectl -n kube-system scale deployment/tlb-controller --replicas=2
```

See [deployment configuration](../../reference/deployment/) for image, resource, and namespace settings.
[Service annotations](../../reference/annotations/) configure tunnel replicas and placement.

## Remove

Delete the Services that use TLB and wait for their cleanup to finish, then delete their classes. Keep the controller
running until its binding journals are gone:

```bash
kubectl -n kube-system get secrets -l controller.tlb.io/journal=true
```

Once no journals remain, remove the installation using the manifest you installed:

```bash
kubectl delete -f deploy/tlb.yaml --timeout=120s
```

Never delete `kube-system`. Keep a separate workload namespace available until all its bindings are cleaned up.
Follow [cleanup troubleshooting](../../operations/troubleshooting/#a-service-or-class-stays-terminating) if a binding
cannot finish; deleting its journal can lose external teardown information.
