---
title: Development
description: Build TLB, run its tests, update CRDs, and work on the documentation site.
---

The repository pins Rust and Deno through mise and Rust's toolchain file. Documentation uses a separate Node project in
`docs/` with a pinned Node version and npm lockfile.

## Controller checks

```bash
mise install
mise run fmt
mise run ci
```

The CI suite checks formatting, Rust and Deno code, tests, build output, and generated CRD consistency. To regenerate
CRDs after changing their Rust definitions:

```bash
mise run update-crds
```

## End-to-end scenarios

The Rust runner in `examples/e2e/` builds the controller image once per invocation and runs named scenarios in
separate disposable kind clusters. It requires Docker, kind, and kubectl; the real NetBird scenario also uses OpenSSL.
Python runs inside fixture containers, so a host Python installation is not needed.

```bash
mise run e2e -- kubernetes
mise run e2e -- netbird
mise run e2e -- quick-tunnel
mise run e2e -- all
```

The `kubernetes` group runs `lifecycle`, `classes`, `dns`, `deployment`, and `runtime`. Each can also be selected directly,
for example `mise run e2e -- classes`. Kubernetes API operations and assertions use the dedicated cluster client.
The runner never adopts an existing cluster or reads the ambient Kubernetes context.

| Scenario | Coverage |
| --- | --- |
| `lifecycle` | Class precedence, namespace isolation, validation, storage preservation, Service recreation and cleanup |
| `classes` | Live cluster-class deletion across namespaces, same-name local classes, class recreation and local overrides |
| `dns` | Ingress watches, DNS ownership, peer readiness/scaling, provider and RBAC failures, failover and cleanup |
| `deployment` | UID/resource-version guards, readiness after CRD loss/restoration, controller leadership failover |
| `runtime` | Copied Secrets, rotation/pruning, source loss, restart-safe cleanup, and unsafe-policy revocation for both class scopes |
| `netbird` | Disposable real server and peers; TCP, UDP and TLS forwarding without eBPF, including forced relay, and Secret cleanup |
| `quick-tunnel` | Public HTTPS through Cloudflare with exact response contents |

The DNS scenario uses two schedulable nodes and the API/peer fixture in `tests/netbird/`. It configures a two-hour
external refresh interval and checks watch-triggered updates after an idle period, within 45 seconds. The real NetBird
scenario bootstraps its own account and setup keys; it requires no existing provider account. These are distinct tests
of DNS reconciliation and real tunnel traffic.

Every scenario has a 25-minute deadline, with shorter deadlines for subprocesses and individual assertions. Clusters
and run-specific images are removed after success, failure, and handled interruption. A failed scenario preserves
redacted Pod logs, Pod status and events under its printed temporary directory (`/tmp/tlb-e2e-*/logs` on Linux).
Scenario groups report failures separately and continue with fresh clusters; interruption stops the group. If cluster
cleanup fails, the error includes its kubeconfig path for manual recovery. Forced termination can prevent cleanup.

The Quick Tunnel scenario uses HTTP/2 transport and verifies public HTTPS in Rust with certificate validation and an
exact response marker. It requires registry and Cloudflare access, but no Cloudflare account, API token, or domain.
The public retry budget defaults to 240 seconds. `mise run e2e -- --help` lists `--tunnel-timeout`, `--node-image`, and
`--origin-image`. Live provider tests can fail because of provider, DNS, or registry availability.

CI runs all seven scenarios in the `kubernetes` job using `mise run e2e -- all`. `mise run e2e-kubernetes`,
`mise run e2e-netbird`, and `mise run e2e-quick-tunnel` select scenario groups or individual scenarios locally.

## Documentation

From the repository root:

```bash
npm --prefix docs ci
npm --prefix docs run dev
```

Use the Node version in `docs/.node-version`. Open the `/tlb/` path printed by Astro. The production checks are:

```bash
npm --prefix docs run check
npm --prefix docs run build
```

Pages live in `docs/src/content/docs/`. Keep task-oriented instructions in Guides and exhaustive fields/defaults in
Reference. The build checks local links and anchors with the GitHub Pages base path. Search is generated from the built
pages.

The documentation workflow builds pull requests and deploys `main` to GitHub Pages. Only `docs/src/content/docs/`
contributes documentation pages; repository review notes are outside the published content collection.
