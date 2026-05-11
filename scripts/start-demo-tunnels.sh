#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="${ROOT_DIR}/.demo-pids"
LOG_DIR="${ROOT_DIR}/.demo-logs"
ZROK_BIN="${ZROK_BIN:-${HOME}/vscode/zrok2}"

AI_LOCAL_PORT="${AI_LOCAL_PORT:-18000}"
AI_TARGET_PORT="${AI_TARGET_PORT:-8000}"
GRAFANA_LOCAL_PORT="${GRAFANA_LOCAL_PORT:-3001}"
GRAFANA_TARGET_PORT="${GRAFANA_TARGET_PORT:-80}"
RESPONSE_LOCAL_PORT="${RESPONSE_LOCAL_PORT:-5000}"
RESPONSE_TARGET_PORT="${RESPONSE_TARGET_PORT:-5000}"

AI_SHARE_NAME="${AI_SHARE_NAME:-public:compliance-ai-console}"
GRAFANA_SHARE_NAME="${GRAFANA_SHARE_NAME:-public:compliance-grafana}"

mkdir -p "${PID_DIR}" "${LOG_DIR}"

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "ERROR: ${command_name} command not found." >&2
    exit 1
  fi
}

require_file() {
  local file_path="$1"
  if [ ! -x "${file_path}" ]; then
    echo "ERROR: zrok binary not executable: ${file_path}" >&2
    echo "Set ZROK_BIN=/path/to/zrok2 if your zrok binary lives elsewhere." >&2
    exit 1
  fi
}

check_http() {
  local name="$1"
  local url="$2"
  local attempts="${3:-10}"
  local wait_seconds="${4:-1}"
  local attempt=1

  while [ "${attempt}" -le "${attempts}" ]; do
    if curl -fsS -L --max-time 5 -o /dev/null "${url}" >/dev/null 2>&1; then
      echo "[ok] ${name} reachable: ${url}"
      return 0
    fi

    sleep "${wait_seconds}"
    attempt=$((attempt + 1))
  done

  echo "[warn] ${name} not reachable yet: ${url}" >&2
  return 1
}

print_log_tail() {
  local name="$1"
  local log_file="${LOG_DIR}/${name}.log"

  if [ -f "${log_file}" ]; then
    echo
    echo "Last log lines for ${name}:"
    sed -n '1,120p' "${log_file}" >&2 || true
  fi
}

pid_is_running() {
  local pid_file="$1"
  [ -f "${pid_file}" ] && kill -0 "$(cat "${pid_file}")" 2>/dev/null
}

start_bg() {
  local name="$1"
  shift
  local pid_file="${PID_DIR}/${name}.pid"
  local log_file="${LOG_DIR}/${name}.log"

  if pid_is_running "${pid_file}"; then
    echo "[skip] ${name} already running pid=$(cat "${pid_file}") log=${log_file}"
    return
  fi

  rm -f "${pid_file}"
  echo "[start] ${name}"
  nohup "$@" >"${log_file}" 2>&1 &
  echo $! >"${pid_file}"
  sleep 1

  if ! pid_is_running "${pid_file}"; then
    echo "ERROR: ${name} exited early. Log follows:" >&2
    sed -n '1,120p' "${log_file}" >&2 || true
    exit 1
  fi

  echo "[ok] ${name} running pid=$(cat "${pid_file}") log=${log_file}"
}

require_command kubectl
require_command curl
require_file "${ZROK_BIN}"

start_bg grafana-port-forward \
  kubectl port-forward -n monitoring svc/monitoring-grafana \
  "${GRAFANA_LOCAL_PORT}:${GRAFANA_TARGET_PORT}"

start_bg response-server-port-forward \
  kubectl port-forward -n compliance-system svc/response-server \
  "${RESPONSE_LOCAL_PORT}:${RESPONSE_TARGET_PORT}"

start_bg ai-console-port-forward \
  kubectl port-forward -n compliance-system deploy/ai-classifier \
  "${AI_LOCAL_PORT}:${AI_TARGET_PORT}"

start_bg grafana-zrok \
  "${ZROK_BIN}" share public "http://localhost:${GRAFANA_LOCAL_PORT}" \
  -n "${GRAFANA_SHARE_NAME}"

start_bg ai-console-zrok \
  "${ZROK_BIN}" share public "http://localhost:${AI_LOCAL_PORT}" \
  -n "${AI_SHARE_NAME}"

echo
echo "Checking local endpoints..."
check_http "AI Console local" "http://127.0.0.1:${AI_LOCAL_PORT}/ui"
check_http "Grafana local" "http://127.0.0.1:${GRAFANA_LOCAL_PORT}"
check_http "Response server local" "http://127.0.0.1:${RESPONSE_LOCAL_PORT}/api/v1/events"

echo
echo "Checking public zrok endpoints..."
if ! check_http "AI Console zrok" "https://compliance-ai-console.shares.zrok.io/ui" 10 2; then
  print_log_tail "ai-console-zrok"
  exit 1
fi

if ! check_http "Grafana zrok" "https://compliance-grafana.shares.zrok.io" 10 2; then
  print_log_tail "grafana-zrok"
  exit 1
fi

echo
echo "Demo tunnels started."
echo "- AI Console: https://compliance-ai-console.shares.zrok.io/ui"
echo "- Grafana:    https://compliance-grafana.shares.zrok.io"
echo "- Webhook:    http://127.0.0.1:${RESPONSE_LOCAL_PORT}/webhook"
echo
echo "Logs: ${LOG_DIR}"
echo "Stop: scripts/stop-demo-tunnels.sh"
echo "All tunnel processes are running in the background; this command should return to your shell prompt."
