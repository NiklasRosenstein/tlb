---
title: Deployment configuration
description: Configure the controller and tunnel workload namespace through manifest patches.
---

`deploy/tlb.yaml` contains the installation resources. Patch the Deployment through your manifest or GitOps tooling.
The controller defaults to one replica, requests 100m CPU and 64Mi memory, and serves readiness and liveness probes on
port 8080. Multiple replicas use one elected leader.

The controller image tag is versioned with the release. Development installations can patch the image and pull policy;
kind installations can load a locally built image with `kind load docker-image`.

## Workload namespace and operator policy

`TLB_WORKLOAD_NAMESPACE` defaults to `POD_NAMESPACE`, which the Deployment reads through the Downward API. A configured
workload namespace must exist and must not be terminating. Drain bindings before changing their placement; cleanup
uses the namespace recorded in each journal.

Custom provider images, NetBird startup commands, and NetBird eBPF capability grants require
`TLB_ALLOW_UNSAFE_WORKLOAD_OVERRIDES=true`. This requires an explicitly configured workload namespace different from
both the controller namespace and `kube-system`. For example:

```bash
kubectl create namespace tlb-tunnels
kubectl -n kube-system set env deployment/tlb-controller \
  TLB_WORKLOAD_NAMESPACE=tlb-tunnels \
  TLB_ALLOW_UNSAFE_WORKLOAD_OVERRIDES=true
```

Keep these settings in your deployment configuration so reapplying manifests preserves them. The controller validates
namespace and boolean settings at startup. Both class kinds use the same policy. An explicitly supplied custom image
or command requires opt-in even when its value equals a built-in default.

Class authors with this opt-in can run arbitrary code in the workload namespace. A separate namespace does not contain
the node-level risks of `SYS_ADMIN`; only trusted administrators should configure these classes. Namespace-scoped
admission and NetworkPolicy rules must permit the intended workloads and Service traffic.

Disabling the opt-in stops affected workloads and clears their announced ingress. Credentials and persistent volumes
remain available for recovery or explicit binding cleanup. Re-enabling permitted configuration allows provisioning to
resume. Missing source Secrets alone leave the last valid runtime copy and existing workload intact.

## Manifest generation

`deploy/controller.yaml` defines the controller and access rules. `deploy/crds.yaml` is generated from the Rust types.
`mise run update-crds` generates the CRDs and assembles `deploy/tlb.yaml`; CI checks both for drift. The release script
updates the controller image tag in the source and bundle along with the Cargo version.
