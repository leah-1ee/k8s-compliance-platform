#!/usr/bin/env bash
set -euo pipefail

VERSION="${LOCAL_PATH_PROVISIONER_VERSION:-v0.0.35}"
MANIFEST_URL="https://raw.githubusercontent.com/rancher/local-path-provisioner/${VERSION}/deploy/local-path-storage.yaml"

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "ERROR: ${command_name} command not found." >&2
    exit 1
  fi
}

require_command kubectl

echo "Installing Rancher Local Path Provisioner (${VERSION})..."
kubectl apply -f "${MANIFEST_URL}"

echo "Waiting for local-path-provisioner rollout..."
kubectl rollout status deployment/local-path-provisioner \
  -n local-path-storage \
  --timeout=180s

echo "Checking local-path StorageClass..."
kubectl get storageclass local-path

echo
echo "Local Path Provisioner is ready."
echo "AI server PVCs can now use storageClassName: local-path."
