---
title: Controller and CLI
description: Controller commands, environment variables, reconciliation behavior, health endpoints, and resource metadata.
---

## Commands

| Command             | Behavior                                               |
| ------------------- | ------------------------------------------------------ |
| `controller`        | Runs the controller                                    |
| `controller run`    | Explicit form of the default command                   |
| `controller crds`   | Writes both CRD definitions as YAML to standard output |
| `controller --help` | Shows CLI usage                                        |

From a development checkout, use `cargo run --locked -- crds` to generate the CRDs.

## Environment

| Variable        | Default                    | Purpose                                                                            |
| --------------- | -------------------------- | ---------------------------------------------------------------------------------- |
| `POD_NAMESPACE` | `tlb-system`               | Private journal and leadership Lease namespace; set from the Pod namespace by Helm |
| `RUST_LOG`      | `info`                     | Rust log filtering, for example `info,controller=debug`                            |
| `KUBECONFIG`    | Kubernetes client defaults | Kubeconfig for local execution; in-cluster Pods use their ServiceAccount           |

Local debugging processes must use the same `POD_NAMESPACE` as other controller replicas in that cluster. Use a separate
disposable cluster for development.

## Reconciliation

Services are the unit of work. The controller watches Services, classes, Secrets, tunnel workloads, and Pods, and
refreshes external state every five minutes by default. Settled classes, journals, and Quick Tunnels wait for watch
events. Running Quick Tunnels awaiting a URL retry after five seconds; failed API and peer-address reads use bounded
error retries. Journal and Service events drive class and orphan cleanup.

Set `TLB_EXTERNAL_REFRESH_INTERVAL_SECONDS` to a positive integer to configure external refreshes. The Helm value is
`externalRefreshIntervalSeconds` (default `300`). This interval does not delay Kubernetes watch events or error retries.

- Up to 16 Service reconciliations run concurrently.
- A UID lock serializes work for one Service and its private journal.
- One reconciliation has a 120-second deadline.
- Provider/API calls and peer-IP reads have their own shorter bounds.
- Failures retry with bounded exponential delay and jitter; cleanup in progress retries promptly.
- Controller replicas coordinate through the `tlb-controller` Lease in `POD_NAMESPACE`.

## Health endpoints

The controller listens on port `8080`:

| Path       | Meaning                                                                       |
| ---------- | ----------------------------------------------------------------------------- |
| `/healthz` | The health-serving process is running                                         |
| `/readyz`  | Leader caches are initialized, or this is a standby participating in election |

A watch failure clears leader readiness and restarts its controller loops. An error on one Service does not make every
other Service unhealthy. Readiness also does not guarantee that every external tunnel is connected; inspect workload
readiness and Service status.

## Resource labels

| Label                           | Purpose                                              |
| ------------------------------- | ---------------------------------------------------- |
| `controller.tlb.io/binding-uid` | Private binding identity on managed tunnel resources |
| `controller.tlb.io/service-uid` | Originating Service instance                         |
| `controller.tlb.io/class-uid`   | Resolved class instance                              |
| `controller.tlb.io/provider`    | `cloudflare` or `netbird` on tunnel resources        |
| `controller.tlb.io/journal`     | `true` on private binding Secrets                    |

Pod-template annotations such as `controller.tlb.io/secret-version`, `controller.tlb.io/config-version`, and
`controller.tlb.io/tls-secret-version` trigger rotation when mounted configuration changes.

## Finalizers

| Finalizer                | Resource                         | Retained until                                 |
| ------------------------ | -------------------------------- | ---------------------------------------------- |
| `tlb.io/finalizer`       | TunnelClass / ClusterTunnelClass | Associated bindings finish teardown            |
| `tlb.io/tunnel-cleanup`  | Service                          | Tunnel workload and provider cleanup completes |
| `tlb.io/binding-cleanup` | Private journal Secret           | Teardown state is no longer needed             |

Finalizer mutations preserve other owners' finalizers. Updates and deletes use UID/resource-version preconditions. See
[security and ownership](../../operations/security/) for the journal's trust boundary.
