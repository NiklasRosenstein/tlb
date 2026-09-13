#!/usr/bin/env bash
set -euo pipefail

if kind get clusters | grep -qx tlb-audit; then
  echo 'The dedicated tlb-audit cluster already exists; use tests/kubernetes.py with its kubeconfig.' >&2
  exit 1
fi
kubeconfig=$(mktemp)
cleanup() {
  if [[ ${1:-0} != 0 ]]; then
    kubectl --kubeconfig "$kubeconfig" --request-timeout=10s -n tlb-system logs \
      -l app.kubernetes.io/instance=tlb-audit --all-containers --tail=100 || true
  fi
  timeout 120 kind delete cluster --name tlb-audit || true
  rm -f "$kubeconfig"
}
trap 'cleanup $?' EXIT

timeout 600 docker build -t tlb:audit .
timeout 240 kind create cluster --name tlb-audit --image kindest/node:v1.37.0 --kubeconfig "$kubeconfig" --wait 120s
timeout 120 kind load docker-image tlb:audit --name tlb-audit
timeout 120 helm upgrade --install tlb-audit helm/tlb-controller --kubeconfig "$kubeconfig" \
  --namespace tlb-system --create-namespace --set image.repository=tlb --set image.tag=audit \
  --set image.pullPolicy=Never --set replicaCount=2 --wait --timeout 90s
timeout 360 python3 tests/kubernetes.py --kubeconfig "$kubeconfig"
timeout 180 python3 tests/kubernetes_deployment.py --kubeconfig "$kubeconfig"
