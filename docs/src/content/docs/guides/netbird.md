---
title: NetBird
description: Expose Kubernetes TCP and UDP Services to a NetBird peer network.
---

The NetBird provider runs a peer for your Service and forwards traffic from the peer into the cluster. Clients connect
through the NetBird network using an announced peer IP or DNS name.

You need a NetBird management service, a reusable setup key, and network policies that allow the intended clients to
reach these peers. Configure these in NetBird; TLB does not create access policies.

## Define a class

Create a Secret named `netbird-setup-key` with a `key` entry in `apps`, using your normal secret-management process.
Then apply:

```yaml title="netbird-class.yaml"
apiVersion: tlb.io/v1alpha1
kind: TunnelClass
metadata:
  name: private
  namespace: apps
spec:
  netbird:
    managementUrl: https://netbird.example.com
    setupKeyRef:
      name: netbird-setup-key
      key: key
    announceType: IP
```

Use the field name **`managementUrl`**, including that capitalization.

For a shared class, use `ClusterTunnelClass` and set the setup key reference's `namespace`. TLB copies the setup key
into a managed Secret in each Service namespace; the tunnel workloads still run beside the Service.

## Expose a Service

```yaml title="private-service.yaml"
apiVersion: v1
kind: Service
metadata:
  name: database
  namespace: apps
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/private
  selector:
    app: database
  ports:
    - name: postgres
      port: 5432
      targetPort: 5432
      protocol: TCP
```

With `announceType: IP`, Service status contains the IP addresses of ready peers. Connect to that address and the
Service port from an allowed NetBird client.

NetBird supports multiple TCP/UDP ports. The default mapping preserves port numbers. Use [port mappings](../tls/) when
the public peer port must differ from the Service port. Port **15411** is reserved for peer-IP discovery.

## Persist peer identity

By default, peer state uses an `emptyDir`. To keep it across Pod replacement, select a StorageClass:

```yaml
spec:
  netbird:
    managementUrl: https://netbird.example.com
    setupKeyRef:
      name: netbird-setup-key
      key: key
    storageClass: standard
    size: 128Mi
```

Each replica has its own PVC. Use a size supported by your StorageClass. Normal image updates preserve the StatefulSet
and its volumes. Kubernetes restricts changes to StatefulSet claim templates; TLB reports an invalid update instead of
deleting the running workload.

Deleting the Service also deletes its managed claims after workload cleanup. TLB does not call NetBird's management API
to delete peer registrations; manage retired peers through NetBird when needed.

## DNS names and replicas

```yaml
metadata:
  annotations:
    tlb.io/dns: database.netbird.selfhosted
    tlb.io/replicas: "2"
```

Set `netbirdDnsDomain` on the class when your network uses a different DNS suffix. The default is `netbird.selfhosted`.

To publish a DNS name instead of peer IPs, set `announceType: DNS` and provide `tlb.io/dns`. The first name is used in
Service status. Clients must be able to resolve that NetBird name; it is not automatically a public DNS record.

Use `tlb.io/topology-key` to prefer spreading replicas across a node or zone, and `tlb.io/node-selector` to restrict
their placement. More replicas also require enough reusable setup-key uses and storage capacity.

## Pod DNS resolution

The default launch command includes `--disable-dns`, so NetBird leaves the Pod's Kubernetes resolver configuration
intact. Forwarding uses the Service ClusterIP; the connector does not need to resolve NetBird peer names. Other peers
can still resolve the connector's advertised DNS labels.

A custom `spec.netbird.upCommand` must include `--disable-dns` to preserve cluster DNS. If the connector itself needs
NetBird DNS, use `--disable-dns=false` and configure NetBird nameservers to resolve your cluster domains as well.
NetBird persists this setting in peer state, so enabling DNS management requires the explicit `false` value.
See [NetBird DNS settings](https://docs.netbird.io/manage/dns/dns-settings).

## Pod requirements

NetBird Pods require network capabilities, including `NET_ADMIN`. The class enables `SYS_ADMIN` and `SYS_RESOURCE` for
eBPF by default; `enableEbpfCapabilities: false` omits those two additions. Your admission policy must allow the
resulting Pod.

The image must support the configured NetBird command, shell, `ip`, and BusyBox-compatible `nc`. Forwarding uses
`socat`; the launch script attempts `apk add` when it is absent. Prefer a tested image with the required tools already
installed for predictable startup.
