#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${SCRIPT_DIR}/k8s/compliance-agent.yaml"

CENTRAL_INGEST_URL="${CENTRAL_INGEST_URL:-${1:-}}"
CLUSTER_NAME="${CLUSTER_NAME:-$(kubectl config current-context 2>/dev/null || echo customer-cluster)}"
CENTRAL_API_KEY="${CENTRAL_API_KEY:-}"
INSTALL_FALCO="${INSTALL_FALCO:-true}"

if [ -z "${CENTRAL_INGEST_URL}" ]; then
  echo "ERROR: CENTRAL_INGEST_URL is required." >&2
  echo "Example:" >&2
  echo "  CENTRAL_INGEST_URL=https://ai.example.com/ingest/falco-events CLUSTER_NAME=prod ./install-agent.sh" >&2
  exit 1
fi

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "ERROR: ${command_name} command not found." >&2
    exit 1
  fi
}

escape_sed() {
  printf '%s' "$1" | sed -e 's/[&|\]/\\&/g'
}

require_command kubectl
require_command sed

echo "Installing compliance-agent"
echo "  cluster: ${CLUSTER_NAME}"
echo "  ingest:  ${CENTRAL_INGEST_URL}"

kubectl create namespace compliance-system --dry-run=client -o yaml | kubectl apply -f -

if [ -n "${CENTRAL_API_KEY}" ]; then
  kubectl create secret generic compliance-agent \
    -n compliance-system \
    --from-literal=central-api-key="${CENTRAL_API_KEY}" \
    --dry-run=client -o yaml | kubectl apply -f -
fi

tmp_manifest="$(mktemp)"
sed \
  -e "s|__CENTRAL_INGEST_URL__|$(escape_sed "${CENTRAL_INGEST_URL}")|g" \
  -e "s|__CLUSTER_NAME__|$(escape_sed "${CLUSTER_NAME}")|g" \
  "${MANIFEST}" > "${tmp_manifest}"

kubectl apply -f "${tmp_manifest}"
rm -f "${tmp_manifest}"

kubectl rollout status deploy/compliance-agent -n compliance-system --timeout=120s

if [ "${INSTALL_FALCO}" = "true" ]; then
  require_command helm
  helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null
  helm repo update falcosecurity >/dev/null
  helm upgrade --install falco falcosecurity/falco \
    --namespace falco \
    --create-namespace \
    --set falco.json_output=true \
    --set falco.json_include_output_property=true \
    --set falco.json_include_output_fields_property=true \
    --set falco.http_output.enabled=true \
    --set falco.http_output.url=http://compliance-agent.compliance-system.svc.cluster.local:8080/webhook
fi

echo
echo "Compliance agent installed."
echo "Check:"
echo "  kubectl get pods -n compliance-system -l app=compliance-agent"
echo "  kubectl logs -n compliance-system deploy/compliance-agent --tail=100"
echo "  kubectl get pods -n falco"
