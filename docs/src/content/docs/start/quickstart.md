---
title: Your first tunnel
description: Publish a small HTTP application through a Cloudflare Quick Tunnel without an API token.
---

This example publishes an nginx application using a generated Cloudflare hostname. No Cloudflare account, API token, or
domain is required. [Install TLB](../installation/) first.

:::note[Use Quick Tunnels for experiments] Quick Tunnel addresses are temporary and may change when a container
restarts. Cloudflare positions them for testing and development; see its
[Quick Tunnel limits](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/).
Use an [API tunnel](../../guides/cloudflare/) for a hostname you control. :::

## Apply the application and class

Save this as `hello-tunnel.yaml`:

```yaml title="hello-tunnel.yaml"
apiVersion: v1
kind: Namespace
metadata:
  name: tlb-demo
---
apiVersion: tlb.io/v1alpha1
kind: TunnelClass
metadata:
  name: quick
  namespace: tlb-demo
spec:
  cloudflare: {}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hello
  namespace: tlb-demo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: hello
  template:
    metadata:
      labels:
        app: hello
    spec:
      containers:
        - name: nginx
          image: nginx:stable-alpine
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: hello
  namespace: tlb-demo
  annotations:
    tlb.io/map-ports: "http:80"
spec:
  type: LoadBalancer
  loadBalancerClass: tlb.io/quick
  selector:
    app: hello
  ports:
    - name: http
      port: 80
      targetPort: 80
      protocol: TCP
```

```bash
kubectl apply -f hello-tunnel.yaml
kubectl -n tlb-demo rollout status deployment/hello --timeout=120s
kubectl -n tlb-demo get service hello --watch
```

Wait for a hostname ending in `.trycloudflare.com` in `EXTERNAL-IP`. Press **Ctrl+C** to stop watching.

## Open the endpoint

```bash
tunnel_hostname=$(kubectl -n tlb-demo get service hello \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl --fail --max-time 30 "https://${tunnel_hostname}"
```

You should see the nginx welcome page. An empty hostname means discovery is still pending; inspect the tunnel Pods using
the [troubleshooting guide](../../operations/troubleshooting/).

## Clean up

```bash
kubectl delete namespace tlb-demo --wait=true --timeout=120s
```

The controller reconciles namespace deletion and removes its binding state. Keep the controller running while cleanup
completes.

Next, [use a domain you own](../../guides/cloudflare/) or [connect a Service to NetBird](../../guides/netbird/).
