#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZROK_BIN="${ZROK_BIN:-${HOME}/vscode/zrok2}"

AI_HOST="${AI_HOST:-compliance-ai-console.shares.zrok.io}"
GRAFANA_HOST="${GRAFANA_HOST:-compliance-grafana.shares.zrok.io}"

require_file() {
  local file_path="$1"
  if [ ! -x "${file_path}" ]; then
    echo "ERROR: zrok binary not executable: ${file_path}" >&2
    echo "Set ZROK_BIN=/path/to/zrok2 if your zrok binary lives elsewhere." >&2
    exit 1
  fi
}

delete_share_for_host() {
  local host="$1"
  local share_token

  share_token="$(
    "${ZROK_BIN}" list shares |
      awk -F '│' -v host="${host}" '
        index($0, host) {
          token = $2
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", token)
          print token
          exit
        }
      '
  )"
  if [ -z "${share_token}" ]; then
    echo "[skip] no zrok share found for ${host}"
    return
  fi

  echo "[delete] ${host} share_token=${share_token}"
  "${ZROK_BIN}" delete share "${share_token}"
}

require_file "${ZROK_BIN}"

echo "Repairing demo zrok shares..."
echo "  AI Console: ${AI_HOST}"
echo "  Grafana:    ${GRAFANA_HOST}"
echo

cd "${ROOT_DIR}"

scripts/stop-demo-tunnels.sh || true
delete_share_for_host "${AI_HOST}"
delete_share_for_host "${GRAFANA_HOST}"

echo
echo "Restarting demo tunnels..."
ZROK_BIN="${ZROK_BIN}" scripts/start-demo-tunnels.sh
