---
title: Tunnel classes
description: The complete TunnelClass and ClusterTunnelClass configuration reference.
---

Both resources use `apiVersion: tlb.io/v1alpha1` and the same `spec`. Configure **exactly one** of `spec.cloudflare` or
`spec.netbird`.

| Kind                 | Scope      | Resolution                                                            |
| -------------------- | ---------- | --------------------------------------------------------------------- |
| `TunnelClass`        | Namespaced | Matches Services in its namespace                                     |
| `ClusterTunnelClass` | Cluster    | Used when no same-named `TunnelClass` exists in the Service namespace |

A Service selects a class with `spec.loadBalancerClass: tlb.io/<name>`. It must have `type: LoadBalancer`, an allocated
ClusterIP, and at least one Service port.

## Cloudflare fields

These fields belong under `spec.cloudflare`.

| Field               | Type                       | Default / requirement           | Meaning                                                                                 |
| ------------------- | -------------------------- | ------------------------------- | --------------------------------------------------------------------------------------- |
| `accountId`         | string                     | Omitted in Quick mode           | 32-character hexadecimal Cloudflare account ID; required with `apiTokenRef`             |
| `apiTokenRef`       | Secret reference           | Omitted in Quick mode           | API credential; required with `accountId`                                               |
| `image`             | string                     | `cloudflare/cloudflared:latest` | Connector image                                                                         |
| `resourcePrefix`    | string                     | `cf-`                           | Prefix for Kubernetes resources; immutable while bound                                  |
| `tunnelPrefix`      | string                     | `kube-`                         | Prefix used when creating the external API tunnel                                       |
| `announceType`      | `External` or `Internal`   | `External`                      | Managed hostnames or internal tunnel identifier in Service status                       |
| `transportProtocol` | `auto`, `quic`, or `http2` | `auto`                          | Transport from cloudflared to the Cloudflare edge; `http2` uses TCP when UDP is blocked |

Quick mode uses `cloudflare: {}`. API mode requires both `accountId` and `apiTokenRef`.

Prefixes contain lowercase letters, digits, and hyphens, with no leading hyphen and at most 40 characters. Kubernetes
resource names also include a binding UID and are truncated to fit their limits. Changing `tunnelPrefix` does not rename
an existing external tunnel.

See the [Cloudflare guide](../../guides/cloudflare/) for routing and DNS behavior.

## NetBird fields

These fields belong under `spec.netbird`.

| Field                    | Type                | Default / requirement                  | Meaning                                                                                |
| ------------------------ | ------------------- | -------------------------------------- | -------------------------------------------------------------------------------------- |
| `managementUrl`          | string              | Required                               | HTTP(S) management URL                                                                 |
| `setupKeyRef`            | Secret reference    | Required                               | Reusable NetBird setup key                                                             |
| `customDns`             | object              | Omitted                                | Optional custom-zone A-record reconciliation; fields below                              |
| `netbirdDnsDomain`       | string              | `netbird.selfhosted`                   | Suffix for peer DNS names                                                              |
| `image`                  | string              | `netbirdio/netbird:latest`             | Peer image with the required forwarding tools                                          |
| `netbirdInterface`       | string              | `wt0`                                  | Interface used for peer-IP discovery and readiness                                     |
| `clusterInterface`       | string              | `eth0`                                 | Accepted configuration field; current socat forwarding follows the Pod's routing table |
| `upCommand`              | string              | `/usr/local/bin/netbird up -F -l=warn --disable-dns` | Foreground NetBird command launched by the supervisor                                  |
| `announceType`           | `IP` or `DNS`       | `IP`                                   | Peer IP addresses or the first configured peer DNS name                                |
| `resourcePrefix`         | string              | `tunnel-`                              | Kubernetes resource prefix; immutable while bound                                      |
| `storageClass`           | string              | Omitted                                | Enables a PVC per replica; otherwise state uses `emptyDir`                             |
| `size`                   | Kubernetes quantity | `32Mi`                                 | Requested claim size when persistent storage is enabled                                |
| `enableEbpfCapabilities` | boolean             | `true`                                 | Adds `SYS_ADMIN` and `SYS_RESOURCE` to the always-requested `NET_ADMIN` capability     |

Interface names must be nonempty, at most 15 characters, and contain only letters, digits, `_`, `-`, `.`, or `:`.
Resource prefixes use the same constraints as the Cloudflare prefix.

`announceType: DNS` needs `tlb.io/dns`; without it, the provider falls back to IP announcement. See the
[NetBird guide](../../guides/netbird/) for storage and peer requirements.

### Custom-zone DNS fields

These fields belong under `spec.netbird.customDns`.

| Field | Default / requirement | Meaning |
| --- | --- | --- |
| `apiUrl` | `managementUrl` with `/api` appended | REST API root; trailing slashes are removed and management path prefixes are preserved |
| `apiTokenRef` | Required | Secret holding a NetBird management API token with DNS read/create/update/delete permissions |
| `zoneId` | Required | Existing custom-zone ID |
| `ttl` | `60` | Record TTL in seconds, from 1 through 2,147,483,647 |

The API URL must use HTTP(S) without embedded credentials, query strings, or fragments. For example,
`https://netbird.example.com/` derives `https://netbird.example.com/api`; set `apiUrl` explicitly when the REST API is
served elsewhere. Use one canonical API URL for each deployment.

Services declare hostnames with `tlb.io/netbird-custom-dns-hostnames` or discover them through an explicit
`tlb.io/netbird-custom-dns-ingress-class` association. DNS API credentials remain in the controller's
private journal and are not copied into tunnel Pods. DNS changes reconcile the new target before cleaning up previous
targets; TTL and API-token changes do not restart peers. See [custom-zone DNS](../../guides/netbird/#custom-zone-dns).

## Secret references

```yaml
setupKeyRef:
  name: netbird-setup-key
  key: key
  namespace: tlb-system
```

| Field       | Required | Meaning                                      |
| ----------- | -------- | -------------------------------------------- |
| `name`      | Yes      | Secret name                                  |
| `key`       | Yes      | Nonempty data key holding a UTF-8 credential |
| `namespace` | No       | Defaults to the Service namespace            |

For a `TunnelClass`, an explicit namespace must equal the class and Service namespace. A `ClusterTunnelClass` may
reference another namespace. Empty credential values are rejected.

Use `apiTokenRef` for Cloudflare API access, `setupKeyRef` for NetBird enrollment, and `customDns.apiTokenRef` for
NetBird DNS API access. Enrollment keys and DNS API tokens serve separate purposes.

## Updating a class

Image, credential, and announcement changes update the current binding. Changes to the class UID, provider, Cloudflare
account, or NetBird management URL require cleanup and a new binding. TLB validates desired configuration before
starting a planned transition.

`resourcePrefix` cannot change while a Service is bound. Kubernetes may also reject immutable StatefulSet fields, such
as claim-template changes; the running workload and its PVCs remain intact when an update is rejected.

For the structural schema installed in your cluster:

```bash
kubectl explain tunnelclass.spec --recursive
kubectl explain clustertunnelclass.spec --recursive
```
