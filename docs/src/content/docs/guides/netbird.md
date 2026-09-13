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

## Custom-zone DNS

TLB can publish explicit Service hostnames as A records pointing to ready tunnel-peer IPv4 addresses. Create and enable
an existing NetBird custom zone, such as `private.example.com`, and distribute it to the client peer groups that should
resolve these names. The zone must not conflict with the peer DNS domain. Clients require NetBird DNS management;
the connector Pods can keep `--disable-dns` because they forward traffic to Kubernetes ClusterIPs.
See [NetBird custom zones](https://docs.netbird.io/manage/dns/custom-zones).

Store a NetBird management API token with DNS read/create/update/delete permissions in a Secret using your normal
secret-management process. Configure the class:

```yaml
spec:
  netbird:
    managementUrl: https://netbird.example.com
    setupKeyRef:
      name: netbird-setup-key
      key: key
    customDns:
      apiTokenRef:
        name: netbird-dns-token
        key: token
      zoneId: "your-zone-id"
      ttl: 60
```

`customDns.apiUrl` defaults to `managementUrl` with `/api` appended. Override it when the REST API is served separately.
The API token remains private to the controller; the setup key enrolls the tunnel peers.

Declare names on the tunnel Service:

```yaml
metadata:
  annotations:
    tlb.io/netbird-custom-dns-hostnames: grafana.private.example.com,prometheus.private.example.com
    tlb.io/replicas: "2"
```

For an ingress Service, Traefik handles HTTP routing and TLS. Hostnames must be declared explicitly; TLB does not inspect
Ingress or Gateway routes. `tlb.io/dns` configures peer aliases independently of these custom-zone names.

Each declaration reserves the complete A-record set at that exact hostname for this Service. TLB adopts existing A
records, repairs TTLs, and removes stale addresses. AAAA/CNAME records cause a conflict and remain untouched. Other
hostnames remain untouched. Use one active TLB installation per zone; its controller replicas coordinate through the
leadership Lease. A canonical API URL and the private journal identify reservations across reconciliation and restarts.

Pod readiness changes trigger reconciliation through Kubernetes watches. External DNS drift is checked every five
minutes by default. When an eligible peer's address query fails, TLB retains that Pod's last-known address until discovery
succeeds or the Pod is confirmed unready, terminating, or absent. Confirmed zero ready peers removes the reserved names'
A records. DNS caching and NetBird distribution can delay clients observing changes.

Inspect Service condition `tlb.io/CustomDNSReady` and Kubernetes warning events. DNS failures do not prevent tunnel
workload reconciliation or Service address updates. `NoReadyPeers` indicates that no ready addresses can be published.
API failures and conflicts retry automatically.

Changing the DNS API URL or zone reconciles the new target before cleaning previous targets. A failed migration keeps
previous records and cleanup credentials in the private journal. Each destination must contain all declared names.
Removing declarations or `customDns` cleans up reserved A records. Service deletion waits for DNS cleanup before
tearing down tunnel workloads; restore API access if cleanup is blocked. Revoked tokens cannot be recovered from a
snapshot: restore a valid token at the retained Secret reference. Removing `customDns` while declarations remain also
reports invalid configuration.

### Verify custom DNS

Use a disposable cluster and dedicated NetBird zones, with the controller running as the chart's ServiceAccount.

1. Configure a zone and allowed client group, then expose a test Service with two replicas and two hostnames.
2. Wait for `tlb.io/CustomDNSReady=True`. On a client in the distribution group, resolve both names and compare their
   A records with the Service's announced peer IPs. Verify application traffic using the configured Service port.
3. Scale to one replica and confirm its retired address disappears. Scale to zero and confirm the A-record sets are empty.
4. Restore two replicas. Change `customDns.zoneId` to a second enabled test zone and update the declarations to names within it.
   Confirm the new target receives records and the previous target is cleaned up. Repeat with an unavailable destination
   and verify previous records remain.
5. Rotate the API token Secret and confirm DNS reconciliation succeeds without a tunnel Pod restart.
6. Delete the Service and confirm its reserved A records disappear while an unrelated test record remains. Check that
   Service and journal finalizers complete. Resolution checks must allow for record TTLs and NetBird propagation.

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
