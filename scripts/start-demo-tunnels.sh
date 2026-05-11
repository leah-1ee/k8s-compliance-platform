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
AI_PUBLIC_URL="${AI_PUBLIC_URL:-https://compliance-ai-console.shares.zrok.io/ui}"
GRAFANA_PUBLIC_URL="${GRAFANA_PUBLIC_URL:-https://compliance-grafana.shares.zrok.io}"

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

share_namespace() {
  echo "${1%%:*}"
}

share_name() {
  echo "${1#*:}"
}

ensure_zrok_name() {
  local full_name="$1"
  local namespace
  local name
  local log_file

  namespace="$(share_namespace "${full_name}")"
  name="$(share_name "${full_name}")"
  log_file="${LOG_DIR}/zrok-create-name-${name}.log"

  echo "[check] zrok reserved name ${namespace}:${name}"
  if "${ZROK_BIN}" create name -n "${namespace}" "${name}" >"${log_file}" 2>&1; then
    echo "[ok] created zrok reserved name ${namespace}:${name}"
    return
  fi

  if "${ZROK_BIN}" list names 2>/dev/null | grep -q "${name}"; then
    echo "[ok] zrok reserved name already exists ${namespace}:${name}"
    return
  fi

  echo "ERROR: failed to create or find zrok reserved name ${namespace}:${name}. Log follows:" >&2
  sed -n '1,120p' "${log_file}" >&2 || true
  exit 1
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

start_zrok_share() {
  local name="$1"
  local public_url="$2"
  shift 2

  if check_http "${name} existing public endpoint" "${public_url}" 2 1; then
    echo "[skip] ${name} public endpoint is already reachable"
    return
  fi

  if "${ZROK_BIN}" list shares 2>/dev/null | grep -q "${public_url#https://}"; then
    echo "[warn] ${name} is registered in zrok but is not reachable yet."
    echo "       Starting another share may fail with shareConflict if the old session is stale."
  fi

  start_bg "${name}" "$@"
}

require_command kubectl
require_command curl
require_command grep
require_file "${ZROK_BIN}"

ensure_zrok_name "${GRAFANA_SHARE_NAME}"
ensure_zrok_name "${AI_SHARE_NAME}"

start_bg grafana-port-forward \
  kubectl port-forward -n monitoring svc/monitoring-grafana \
  "${GRAFANA_LOCAL_PORT}:${GRAFANA_TARGET_PORT}"

start_bg response-server-port-forward \
  kubectl port-forward -n compliance-system svc/response-server \
  "${RESPONSE_LOCAL_PORT}:${RESPONSE_TARGET_PORT}"

start_bg ai-console-port-forward \
  kubectl port-forward -n compliance-system deploy/ai-classifier \
  "${AI_LOCAL_PORT}:${AI_TARGET_PORT}"

start_zrok_share grafana-zrok "${GRAFANA_PUBLIC_URL}" \
  "${ZROK_BIN}" share public "http://localhost:${GRAFANA_LOCAL_PORT}" \
  -n "${GRAFANA_SHARE_NAME}"

start_zrok_share ai-console-zrok "${AI_PUBLIC_URL}" \
  "${ZROK_BIN}" share public "http://localhost:${AI_LOCAL_PORT}" \
  -n "${AI_SHARE_NAME}"

echo
echo "Checking local endpoints..."
check_http "AI Console local" "http://127.0.0.1:${AI_LOCAL_PORT}/ui"
check_http "Grafana local" "http://127.0.0.1:${GRAFANA_LOCAL_PORT}"
check_http "Response server local" "http://127.0.0.1:${RESPONSE_LOCAL_PORT}/api/v1/events"

echo
echo "Checking public zrok endpoints..."
if ! check_http "AI Console zrok" "${AI_PUBLIC_URL}" 10 2; then
  print_log_tail "ai-console-zrok"
  exit 1
fi

if ! check_http "Grafana zrok" "${GRAFANA_PUBLIC_URL}" 10 2; then
  print_log_tail "grafana-zrok"
  exit 1
fi

echo
echo "Demo tunnels started."
echo "- AI Console: ${AI_PUBLIC_URL}"
echo "- Grafana:    ${GRAFANA_PUBLIC_URL}"
echo "- Webhook:    http://127.0.0.1:${RESPONSE_LOCAL_PORT}/webhook"
echo
echo "Logs: ${LOG_DIR}"
echo "Stop: scripts/stop-demo-tunnels.sh"
echo "All tunnel processes are running in the background; this command should return to your shell prompt."
