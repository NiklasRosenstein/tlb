---
title: Service annotations
description: Provider support, defaults, and validation rules for every TLB Service annotation.
---

Annotations belong on the **Service's** `metadata.annotations`. Kubernetes annotation values are strings; quote numbers
in YAML.

| Annotation               | Cloudflare                    | NetBird                                                | Default                              |
| ------------------------ | ----------------------------- | ------------------------------------------------------ | ------------------------------------ |
| `tlb.io/dns`             | Managed hostnames in API mode | Extra peer DNS labels; first name for DNS announcement | None                                 |
| `tlb.io/protocol`        | Selects the origin protocol   | Not used                                               | Detected from the Service port       |
| `tlb.io/replicas`        | Connector replicas            | Peer replicas                                          | `"1"`                                |
| `tlb.io/topology-key`    | No replica-spreading effect   | Preferred anti-affinity topology                       | `kubernetes.io/hostname` for NetBird |
| `tlb.io/node-selector`   | Tunnel Pod node selector      | Tunnel Pod node selector                               | No restriction                       |
| `tlb.io/map-ports`       | Rejected                      | Explicit listener-to-Service mappings                  | Same port numbers                    |
| `tlb.io/tls-secret-name` | Not used                      | Secret for listener-side TLS                           | None                                 |

## `tlb.io/dns`

Comma-separated DNS names, for example `"app.example.com,api.example.com"`. Names must be valid DNS hostnames.

Cloudflare API mode manages proxied CNAME records for these names when `announceType` is `External`. Quick mode uses
generated hostnames. NetBird passes names as peer DNS labels, removing the configured NetBird domain suffix first.
`announceType: DNS` publishes the first resulting full name.

## `tlb.io/protocol`

Cloudflare accepts an explicit protocol, such as `"http"`, or a port-specific mapping such as `"8080:http"` or
`"web:https"`. A mapping may identify the port by number or name.

Resolution order:

1. Matching port-specific annotation.
2. A single global protocol annotation.
3. Recognized hints in the port name (`http`, `https`, `ssh`, `rdp`).
4. Recognized well-known port numbers.
5. TCP fallback.

Accepted origin protocols are `http`, `https`, `tcp`, `ssh`, `rdp`, and `smb`. TLB's Cloudflare provider requires
exactly one **TCP** Service port; a mapping annotation does not enable multiport routing. Prefer an explicit protocol to
relying on inference.

## `tlb.io/replicas`

A nonnegative integer. `"0"` scales tunnel workloads down but does not remove the binding or API-managed external
resources. Multiple Cloudflare Quick replicas each have their own generated hostname. Multiple NetBird replicas each
create a peer and, when configured, a PVC.

## `tlb.io/topology-key`

NetBird uses preferred Pod anti-affinity to spread tunnel replicas across the specified topology, for example
`"topology.kubernetes.io/zone"`. This is a scheduling preference, not a guarantee that every replica lands in a distinct
zone.

The Cloudflare provider does not use this annotation for spreading. Both providers can prefer placement near the
application's selected Pods.

## `tlb.io/node-selector`

Comma-separated `key=value` labels, for example `"disktype=ssd,region=west"`. The labels restrict **tunnel Pods**, not
the controller or application Pods. Use the Helm `nodeSelector` value for the controller.

## `tlb.io/map-ports`

NetBird-only format:

```text
listen-port[/tls]:service-port[/tls[-no-verify]]
```

Example: `"8080:http,443/tls:https/tls"`. Every target must reference a declared Service port name or number. Listener
ports must be unique, nonzero, and not `15411`. TLS is supported only for TCP mappings.

See [TLS and port mapping](../../guides/tls/) for complete examples.

## `tlb.io/tls-secret-name`

Name of the TLS Secret in the Service namespace. Required when a mapping uses `/tls` on the **listening** side. The
Secret needs nonempty `tls.crt` and `tls.key` entries. Its resource-version changes trigger Pod rotation.
