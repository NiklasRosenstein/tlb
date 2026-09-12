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

The isolated suite builds a controller image, creates a dedicated kind cluster, installs the chart, and verifies
lifecycle and deployment behavior. It requires Docker, kind, Helm, kubectl, Python 3, and `timeout`:

```bash
bash tests/kubernetes.sh
```

The script uses a dedicated kubeconfig and deletes its `tlb-audit` cluster on exit. It refuses to run when a cluster of
that name already exists.

For an existing **test** cluster named `tlb-audit`, run the suites directly:

```bash
python3 tests/kubernetes.py --kubeconfig /path/to/test-kubeconfig
python3 tests/kubernetes_deployment.py --kubeconfig /path/to/test-kubeconfig
```

These tests create and delete resources, terminate a test controller Pod, and temporarily remove a test CRD. They are
not production-cluster checks. Provider API tests use local mocks; public traffic needs provider integration validation.

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
