---
title: Installation
description: Install the TLB controller and its custom resource definitions with Helm.
---

You need a Kubernetes cluster, `kubectl` access with permission to install cluster-scoped resources, and Helm. Tunnel
Pods need outbound connectivity to their provider and connectivity to the Service they expose.

Run **one TLB installation per cluster**. You can run multiple controller replicas within that installation.

## Install the chart

The Helm chart is in the repository:

```bash
git clone https://github.com/NiklasRosenstein/tlb.git
cd tlb
helm upgrade --install tlb-controller ./helm/tlb-controller \
  --namespace tlb-system --create-namespace \
  --wait --timeout 120s
```

The chart installs the controller, ServiceAccount, RBAC, and the `TunnelClass` and `ClusterTunnelClass` CRDs. The
controller namespace also stores private binding journals and the leadership Lease.

Check the installation:

```bash
kubectl -n tlb-system get deployments,pods
kubectl get crd tunnelclasses.tlb.io clustertunnelclasses.tlb.io
kubectl -n tlb-system logs deployment/tlb-controller --tail=50
```

## Select a controller image

The chart defaults to `ghcr.io/niklasrosenstein/tlb` and the version in `helm/tlb-controller/values.yaml`. Use the chart
and image from the same revision. To run a development checkout, build its image and make it available to your cluster:

```bash
docker build -t registry.example.com/tlb:development .
docker push registry.example.com/tlb:development
helm upgrade --install tlb-controller ./helm/tlb-controller \
  --namespace tlb-system --create-namespace \
  --set image.repository=registry.example.com/tlb \
  --set image.tag=development \
  --wait --timeout 120s
```

Replace the registry with one your cluster can pull from. For a local kind cluster, `kind load docker-image` loads a
locally built image without a registry.

## Configure the controller

```yaml title="tlb-values.yaml"
replicaCount: 2
resources:
  requests:
    cpu: 100m
    memory: 64Mi
```

```bash
helm upgrade tlb-controller ./helm/tlb-controller \
  --namespace tlb-system --values tlb-values.yaml
```

These settings configure **the controller**, not the tunnel Pods. Use
[Service annotations](../../reference/annotations/) and [class fields](../../reference/classes/) for tunnel replicas,
placement, and images.

## Remove the installation

Delete the Services that use TLB and wait for their cleanup to finish. Then delete their classes. Keep the controller
running, its namespace available, and provider credentials valid throughout cleanup.

Once all bindings have finished, uninstall the chart:

```bash
helm uninstall tlb-controller --namespace tlb-system
```

If a resource remains terminating, follow
[the cleanup troubleshooting steps](../../operations/troubleshooting/#a-service-or-class-stays-terminating) before
removing any finalizer.
