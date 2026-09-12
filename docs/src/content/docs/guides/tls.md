---
title: TLS and port mapping
description: Map NetBird peer ports to Service ports and configure TLS termination or encrypted upstream connections.
---

NetBird's `tlb.io/map-ports` annotation defines the listening peer port and the Service port it forwards to:

```text
listen-port[/tls]:service-port[/tls[-no-verify]]
```

`service-port` is a Service port number or a Service port **name**. It is not a Pod `targetPort`. Separate mappings with
commas.

## Choose a mapping

| Mapping                      | Connection                                                              |
| ---------------------------- | ----------------------------------------------------------------------- |
| `8080:http`                  | Peer TCP port 8080 → Service port named `http`                          |
| `443/tls:http`               | Terminate TLS on peer port 443 → plain TCP to `http`                    |
| `443:8443/tls`               | Plain TCP on peer port 443 → verified TLS to Service port 8443          |
| `443/tls:8443/tls`           | TLS termination at peer → verified TLS to Service port 8443             |
| `443/tls:8443/tls-no-verify` | TLS termination at peer → TLS upstream without certificate verification |

TLS options require a TCP Service port. Listener ports must be unique, nonzero, and different from the reserved peer-IP
port `15411`. If you specify mappings, they replace the default one-to-one port forwarding configuration.

## Terminate TLS on the peer

Create the certificate Secret in the **same namespace as the Service**:

```bash
kubectl -n apps create secret tls website-tls \
  --cert=certificate.pem --key=private-key.pem
```

Then annotate a NetBird-backed Service:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: website
  namespace: apps
  annotations:
    tlb.io/map-ports: "443/tls:http"
    tlb.io/tls-secret-name: website-tls
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/private
  selector:
    app: website
  ports:
    - name: http
      port: 80
      targetPort: 8080
      protocol: TCP
```

The Secret must contain nonempty `tls.crt` and `tls.key` entries with a usable certificate and key. TLB mounts them for
the forwarder and rotates Pods when the Secret changes. A failed forwarder causes the tunnel container to exit.

The certificate must match the hostname your clients use. A peer IP does not automatically match a certificate issued
for a DNS name.

## Encrypt the upstream connection

The right-hand `/tls` enables certificate verification for the connection to the Service ClusterIP. Configure the
forwarder's trust and certificate identity accordingly. `/tls-no-verify` encrypts that connection but disables
verification; use it only when you deliberately accept that tradeoff.

A mapping that uses TLS **only on the upstream side** does not require `tlb.io/tls-secret-name`. That Secret is for TLS
termination on the listening side.

For Cloudflare origins, use [`tlb.io/protocol: https`](../cloudflare/#protocols-and-origin-routing); NetBird port
mapping annotations do not apply to Cloudflare.
