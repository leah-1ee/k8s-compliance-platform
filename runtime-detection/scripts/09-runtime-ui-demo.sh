#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

RESPONSE_SERVER_URL="${RESPONSE_SERVER_URL:-http://127.0.0.1:5000}"
AI_CONSOLE_URL="${AI_CONSOLE_URL:-http://127.0.0.1:18000}"
NAMESPACE="${NAMESPACE:-runtime-demo}"
POD_NAME="${POD_NAME:-runtime-demo-target}"

echo "============================================"
echo " Runtime UI Demo Event Generator"
echo " Response Server: ${RESPONSE_SERVER_URL}"
echo " AI Console:      ${AI_CONSOLE_URL}/ui"
echo " Target Pod:      ${NAMESPACE}/${POD_NAME}"
echo "============================================"
echo

echo "[1/5] Applying demo workload..."
kubectl apply -f "${PROJECT_DIR}/manifests/runtime-ui-demo-workload.yaml"

echo "[2/5] Waiting for demo pod..."
kubectl wait --for=condition=ready "pod/${POD_NAME}" -n "${NAMESPACE}" --timeout=90s

echo "[3/5] Checking manifest lookup permissions..."
if ! kubectl auth can-i get pods -n "${NAMESPACE}" \
  --as="system:serviceaccount:compliance-system:ai-classifier" >/dev/null; then
  echo "ERROR: ai-classifier cannot read pod manifests in namespace ${NAMESPACE}." >&2
  echo "Apply the AI server RBAC manifest, then restart ai-classifier:" >&2
  echo "  kubectl apply -f ai-observability/deploy/ai-server.yaml" >&2
  echo "  kubectl rollout restart deploy/ai-classifier -n compliance-system" >&2
  exit 1
fi

echo "[4/5] Generating Falco events from the demo pod..."
kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- sh -c "cat /etc/passwd >/dev/null"
kubectl exec -n "${NAMESPACE}" "${POD_NAME}" -- sh -c "id >/dev/null; uname -a >/dev/null"

echo "[5/5] Waiting for Response Server ingestion..."
sleep 5

echo
echo "Recent runtime-demo events from Response Server:"
curl -fsS "${RESPONSE_SERVER_URL}/api/v1/events?namespace=${NAMESPACE}&limit=10" | python3 -m json.tool

echo
echo "Open the AI Console and click '최근 위반 새로고침':"
echo "  ${AI_CONSOLE_URL}/ui"
