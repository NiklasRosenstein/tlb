---
title: Introduction
description: What TLB does, how traffic reaches a Service, and how to choose a tunnel provider.
---

TLB (Tunnel LoadBalancer) is a Kubernetes controller that exposes `LoadBalancer` Services through tunnel providers. It
runs the tunnel workloads and writes their reachable addresses into each Service's `.status.loadBalancer.ingress`.

Your application keeps its ordinary Deployment and Service. TLB connects that Service to a provider selected by
`spec.loadBalancerClass`.

## How it fits together

```text
Client → Cloudflare or NetBird → tunnel Pod → Service → application Pods
                                   ↑
                     TLB reconciles Kubernetes configuration
```

Three resources define a tunnel:

1. A **TunnelClass** or **ClusterTunnelClass** defines one provider and its settings.
2. A **Secret** supplies provider credentials when the provider needs them.
3. A **Service** selects the class with `loadBalancerClass: tlb.io/<class-name>`.

A `TunnelClass` applies in its own namespace. A `ClusterTunnelClass` is available across the cluster. When both have the
same name, the class in the Service's namespace takes precedence.

## Choose a provider

| Need                                               | Provider                | What clients use                                 |
| -------------------------------------------------- | ----------------------- | ------------------------------------------------ |
| Try an HTTP application without a provider account | Cloudflare Quick Tunnel | A generated `https://…trycloudflare.com` address |
| Publish an application on your domain              | Cloudflare API tunnel   | Your Cloudflare-managed hostname                 |
| Reach TCP or UDP services on a private network     | NetBird                 | The peer IP or NetBird DNS name                  |

Cloudflare tunnels accept **one TCP Service port** in TLB. HTTP and HTTPS applications are the simplest way to start;
non-HTTP origins also require the appropriate Cloudflare client configuration. NetBird supports multiple TCP/UDP ports
and optional TLS forwarding.

TLB does not provision a cloud load balancer, manage an Ingress, or configure your provider's access policies. Configure
authentication and network access in the application and provider as appropriate for your endpoint.

## Next steps

[Install the controller](../installation/), then [create an HTTP Quick Tunnel](../quickstart/). For the configuration
vocabulary, see the [class reference](../../reference/classes/) and [Service annotations](../../reference/annotations/).
