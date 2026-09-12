---
title: Troubleshooting
description: Diagnose pending addresses, unscheduled tunnel Pods, missing DNS, and incomplete cleanup.
---

Start with the Service, its selected class, the tunnel Pods, and the controller logs:

```bash
kubectl -n apps describe service website
kubectl -n apps get tunnelclasses
kubectl get clustertunnelclasses
kubectl -n apps get pods -l controller.tlb.io/binding-uid
kubectl -n tlb-system logs deployment/tlb-controller --since=10m
```

Replace `apps`, `website`, and the controller Deployment name with your installation's names. Kubernetes Events are best
effort; controller logs remain useful when Event publication is unavailable.

## The Service has no external address

Check that:

- `spec.type` is `LoadBalancer` and `spec.loadBalancerClass` is exactly `tlb.io/<class-name>`.
- The Service has an allocated ClusterIP and declared ports.
- A matching class exists. A class in the Service namespace takes precedence over the cluster-scoped class.
- The class configures exactly one provider and all required credential keys exist.
- The Service annotations pass validation. Cloudflare accepts only one TCP port; replica counts cannot be negative.
- The tunnel Pods are ready and can reach their provider and the application Service.

For Quick Tunnels, discovery waits for a running, ready connector and a generated URL. For NetBird IP mode, the
controller must reach the Pod's peer-IP endpoint on TCP port `15411`; account for NetworkPolicies between the controller
and tunnel Pods.

## A tunnel Pod is Pending or restarting

```bash
kubectl -n apps describe pod <tunnel-pod>
kubectl -n apps logs <tunnel-pod> --all-containers --tail=100
kubectl -n apps logs <tunnel-pod> --all-containers --previous --tail=100
```

For Pending Pods, inspect node selectors, admission failures, image pull errors, and unbound PVCs. The chart's
scheduling settings affect the controller; Service annotations affect tunnel Pods.

For NetBird, check the management URL, reusable setup key, required image tools, permitted network capabilities, and TLS
Secret. `tls.crt` and `tls.key` must be present and usable. A failed forwarder terminates the container so that
Kubernetes can restart it.

## The public Cloudflare hostname does not work

Check the token's tunnel, DNS, and zone permissions and whether the configured account owns the DNS zone. An existing
unrelated record at the requested name causes a conflict rather than automatic adoption.

An internal `<id>.cfargotunnel.com` value in Service status is a tunnel identifier, not proof that public DNS is
configured. Check the intended proxied CNAME and any provider access policy.

A Quick Tunnel hostname may change after a container restarts. Query Service status again rather than relying on a
previously copied URL.

## A configuration update is rejected

`resourcePrefix` is immutable while bound. Kubernetes also restricts changes to StatefulSet fields, including claim
templates. TLB leaves existing workloads and PVCs intact when such an update is invalid.

Inspect the controller's error and correct the class configuration. Plan storage changes using Kubernetes and your
storage provider's supported procedures; repeated reconciliation does not make an immutable field mutable.

## A Service or class stays Terminating

Inspect the controller logs and the resource's finalizers. Common causes include unavailable provider APIs, revoked
credentials, workloads still terminating, storage protection, and ownership conflicts.

Keep the controller running. Restore provider access or the required credential, then allow reconciliation to retry. To
list journal metadata without printing credential contents:

```bash
kubectl -n tlb-system get secrets \
  -l controller.tlb.io/journal=true \
  -o custom-columns=NAME:.metadata.name,CREATED:.metadata.creationTimestamp
```

A resource without verifiable binding state needs an explicit operator ownership investigation. Do not guess ownership
from its name or remove a finalizer before external and Kubernetes cleanup is verified.

## The controller is not ready

Inspect Pod logs, ServiceAccount permissions, CRD availability, and the Lease in the controller namespace:

```bash
kubectl -n tlb-system get lease tlb-controller
kubectl -n tlb-system describe deployment tlb-controller
```

The leader waits for its primary caches to initialize. Watch errors clear readiness and restart its controller loops. A
standby can be ready while waiting to acquire the Lease. All replicas must use the same controller namespace.
