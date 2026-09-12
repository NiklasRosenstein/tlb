---
title: Helm values
description: Configure the controller Deployment, ServiceAccount, image, and scheduling through Helm.
---

The chart is at `helm/tlb-controller`. Helm values configure the **TLB controller**. Use [classes](../classes/) and
[Service annotations](../annotations/) to configure the tunnel workloads.

## Image and replicas

| Value              | Default                        | Meaning                                                         |
| ------------------ | ------------------------------ | --------------------------------------------------------------- |
| `replicaCount`     | `1`                            | Controller replicas; one elected leader runs reconciliation     |
| `image.repository` | `ghcr.io/niklasrosenstein/tlb` | Controller image repository                                     |
| `image.tag`        | `0.6.5`                        | Controller image tag; an empty value uses the chart app version |
| `image.pullPolicy` | `IfNotPresent`                 | Kubernetes image pull policy                                    |
| `imagePullSecrets` | `[]`                           | Registry authentication Secrets                                 |

Keep the chart and controller image aligned. Pin provider images separately using their class's `image` field.

## Identity and access

| Value                        | Default | Meaning                                                                                                      |
| ---------------------------- | ------- | ------------------------------------------------------------------------------------------------------------ |
| `nameOverride`               | `""`    | Overrides the chart name used in naming                                                                      |
| `fullnameOverride`           | `""`    | Overrides the generated full resource name                                                                   |
| `serviceAccount.create`      | `true`  | Creates the controller ServiceAccount                                                                        |
| `serviceAccount.name`        | `""`    | Explicit ServiceAccount name; otherwise the chart generates one, or uses `default` when creation is disabled |
| `serviceAccount.automount`   | `true`  | API credential automount setting on a chart-created ServiceAccount                                           |
| `serviceAccount.annotations` | `{}`    | Annotations on a chart-created ServiceAccount                                                                |

The chart binds permissions to the selected ServiceAccount even when `create` is false. An existing ServiceAccount must
allow the controller to authenticate to the Kubernetes API.

## Pod configuration

| Value                       | Default | Meaning                               |
| --------------------------- | ------- | ------------------------------------- |
| `podAnnotations`            | `{}`    | Controller Pod annotations            |
| `podLabels`                 | `{}`    | Additional controller Pod labels      |
| `podSecurityContext`        | `{}`    | Controller Pod security context       |
| `securityContext`           | `{}`    | Controller container security context |
| `resources.requests.cpu`    | `100m`  | Requested CPU                         |
| `resources.requests.memory` | `64Mi`  | Requested memory                      |
| `nodeSelector`              | `{}`    | Controller node selector              |
| `tolerations`               | `[]`    | Controller tolerations                |
| `affinity`                  | `{}`    | Controller affinity                   |

`resources` is passed through to the controller container, so you can also specify limits. Readiness and liveness probes
use the controller's port `8080`.

The values file contains `service.type` and `service.port`, but the chart does not render a Service from them. They do
not expose the controller's health endpoint or affect tunnel Services.

## Inspect before installing

```bash
helm show values ./helm/tlb-controller
helm template tlb-controller ./helm/tlb-controller \
  --namespace tlb-system --values tlb-values.yaml
```

Use the [installation guide](../../start/installation/) for deployment and teardown order.
