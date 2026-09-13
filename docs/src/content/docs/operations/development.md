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

## Kubernetes lifecycle tests

The isolated suite builds a controller image, creates a dedicated kind cluster with two schedulable nodes, installs the chart, and verifies
lifecycle, NetBird DNS discovery, and deployment behavior. It requires Docker, kind, Helm, kubectl, Python 3, and `timeout`:

```bash
bash tests/kubernetes.sh
```

The script uses a dedicated kubeconfig and deletes its `tlb-audit` cluster on exit. It refuses to run when a cluster of
that name already exists.

For an existing **test** cluster named `tlb-audit`, run the suites directly:

```bash
python3 tests/kubernetes.py --kubeconfig /path/to/test-kubeconfig
python3 tests/kubernetes_netbird.py --kubeconfig /path/to/test-kubeconfig
python3 tests/kubernetes_deployment.py --kubeconfig /path/to/test-kubeconfig
```

The NetBird suite requires the `tlb-netbird-test:audit` image from `tests/netbird/Dockerfile` loaded into kind and the
chart's `externalRefreshIntervalSeconds` set to `7200`. The shell runner configures both. It runs a stateful DNS API
double and peer Pods with dummy interfaces through TLB's generated launch script and readiness probe. Tests exercise
Ingress watches, hostname selection and ownership, peer readiness and scaling, API and Kubernetes listing failures,
leader failover, and finalizer cleanup. Ingress watch assertions follow an idle period and complete within 45 seconds, well
before the external refresh. Real NetBird enrollment, DNS distribution to clients, tunnel traffic, and TLS require a
separate provider integration environment.

These tests create and delete resources, terminate test controller Pods, temporarily revoke Ingress list permission,
and temporarily remove a test CRD. They are not production-cluster checks.

## Public Quick Tunnel E2E

The Rust runner in `examples/quick-tunnel-e2e/` builds the controller image, creates an isolated kind cluster, installs
TLB through its Helm chart, and creates a small nginx Pod with a run-specific response. It discovers the Quick Tunnel
hostname from Service status and retries public HTTPS until the response is HTTP 200 with that exact body.

```bash
mise run e2e-quick-tunnel
```

Docker must be running. The runner needs access to container registries and Cloudflare; it needs no Cloudflare account,
API token, or domain. The test class selects HTTP/2 transport so outbound UDP is not required. It uses its own
kubeconfig and never selects your current Kubernetes context. Each run gets a unique cluster name and image tag. Cluster
and image cleanup runs after success, failure, and Ctrl-C. Failure diagnostics are retained under the printed temporary
directory. Forced termination can prevent cleanup; use the printed cluster name with `kind delete cluster --name <name>`
in that case.

The public HTTP retry budget defaults to 240 seconds. Use `mise run e2e-quick-tunnel -- --help` to see the
`--tunnel-timeout`, `--node-image`, and `--origin-image` options. Commands and the overall scenario also have deadlines.
The HTTP assertion runs in Rust with certificate verification enabled; no external curl process is required.

The **Quick Tunnel E2E** GitHub Actions workflow runs on every pull request and every push to `develop`, including
merges. Manual runs are also available. It exercises a live external provider, whose
[Quick Tunnel service has no uptime guarantee](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/).
It complements the isolated lifecycle tests and can fail because of provider, DNS, or registry availability.

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
