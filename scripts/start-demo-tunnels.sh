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
ENABLE_DIRECT_GRAFANA_ZROK="${ENABLE_DIRECT_GRAFANA_ZROK:-false}"

AI_SHARE_NAME="${AI_SHARE_NAME:-public:compliance-ai-console}"
GRAFANA_SHARE_NAME="${GRAFANA_SHARE_NAME:-public:compliance-grafana}"
AI_PUBLIC_URL="${AI_PUBLIC_URL:-https://compliance-ai-console.shares.zrok.io/ui}"
GRAFANA_PUBLIC_URL="${GRAFANA_PUBLIC_URL:-https://compliance-grafana.shares.zrok.io}"
GRAFANA_PROXY_PUBLIC_URL="${GRAFANA_PROXY_PUBLIC_URL:-https://compliance-ai-console.shares.zrok.io/grafana-ui/}"

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

check_http_status() {
  local name="$1"
  local url="$2"
  local expected_pattern="$3"
  local status

  status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "${url}" || true)"
  if echo "${status}" | grep -Eq "${expected_pattern}"; then
    echo "[ok] ${name} reachable: ${url} status=${status}"
    return 0
  fi

  echo "[warn] ${name} unexpected status=${status}: ${url}" >&2
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

zrok_host_from_url() {
  local url="$1"
  local without_scheme
  without_scheme="${url#http://}"
  without_scheme="${without_scheme#https://}"
  echo "${without_scheme%%/*}"
}

delete_zrok_shares_for_host() {
  local host="$1"
  local share_tokens

  share_tokens="$(
    "${ZROK_BIN}" list shares |
      awk -F '│' -v host="${host}" '
        index($0, host) {
          token = $2
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", token)
          print token
        }
      '
  )"

  if [ -z "${share_tokens}" ]; then
    return
  fi

  while IFS= read -r share_token; do
    [ -n "${share_token}" ] || continue
    echo "[delete] stale zrok share ${host} share_token=${share_token}"
    "${ZROK_BIN}" delete share "${share_token}" >/dev/null
  done <<< "${share_tokens}"
}

# namespace:name 에서 name만 추출 (create name 명령용)
share_namespace() { echo "${1%%:*}"; }
share_name()      { echo "${1#*:}"; }

ensure_zrok_name() {
  local full_name="$1"   # ex) public:compliance-ai-console
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
  local public_host
  shift 2

  if check_http "${name} existing public endpoint" "${public_url}" 2 1; then
    echo "[skip] ${name} public endpoint is already reachable"
    return
  fi

  public_host="$(zrok_host_from_url "${public_url}")"
  stop_bg "${name}"
  delete_zrok_shares_for_host "${public_host}"

  start_bg "${name}" "$@"
}

stop_bg() {
  local name="$1"
  local pid_file="${PID_DIR}/${name}.pid"

  if ! pid_is_running "${pid_file}"; then
    rm -f "${pid_file}"
    return
  fi

  echo "[stop] stale ${name} pid=$(cat "${pid_file}")"
  kill "$(cat "${pid_file}")" 2>/dev/null || true
  sleep 1
  if pid_is_running "${pid_file}"; then
    kill -9 "$(cat "${pid_file}")" 2>/dev/null || true
  fi
  rm -f "${pid_file}"
}

require_command kubectl
require_command curl
require_command grep
require_file "${ZROK_BIN}"

ensure_zrok_name "${AI_SHARE_NAME}"
if [ "${ENABLE_DIRECT_GRAFANA_ZROK}" = "true" ]; then
  ensure_zrok_name "${GRAFANA_SHARE_NAME}"
fi

start_bg grafana-port-forward \
  kubectl port-forward -n monitoring svc/monitoring-grafana \
  "${GRAFANA_LOCAL_PORT}:${GRAFANA_TARGET_PORT}"

start_bg response-server-port-forward \
  kubectl port-forward -n compliance-system svc/response-server \
  "${RESPONSE_LOCAL_PORT}:${RESPONSE_TARGET_PORT}"

start_bg ai-console-port-forward \
  kubectl port-forward -n compliance-system deploy/ai-classifier \
  "${AI_LOCAL_PORT}:${AI_TARGET_PORT}"

start_zrok_share ai-console-zrok "${AI_PUBLIC_URL}" \
  "${ZROK_BIN}" share public "http://127.0.0.1:${AI_LOCAL_PORT}" \
  -n "${AI_SHARE_NAME}"

if [ "${ENABLE_DIRECT_GRAFANA_ZROK}" = "true" ]; then
  start_zrok_share grafana-zrok "${GRAFANA_PUBLIC_URL}" \
    "${ZROK_BIN}" share public "http://127.0.0.1:${GRAFANA_LOCAL_PORT}" \
    -n "${GRAFANA_SHARE_NAME}"
fi

echo
echo "Checking local endpoints..."
check_http "AI Console local" "http://127.0.0.1:${AI_LOCAL_PORT}/ui"
check_http_status "Grafana proxy local" "http://127.0.0.1:${AI_LOCAL_PORT}/grafana-ui/" "^(200|302|401)$" || true
check_http_status "Grafana direct local" "http://127.0.0.1:${GRAFANA_LOCAL_PORT}" "^(200|302)$" || true
check_http "Response server local" "http://127.0.0.1:${RESPONSE_LOCAL_PORT}/api/v1/events"

echo
echo "Checking public zrok endpoints..."
if ! check_http "AI Console zrok" "${AI_PUBLIC_URL}" 10 2; then
  print_log_tail "ai-console-zrok"
  exit 1
fi

if [ "${ENABLE_DIRECT_GRAFANA_ZROK}" = "true" ]; then
  if ! check_http "Grafana direct zrok" "${GRAFANA_PUBLIC_URL}" 10 2; then
    print_log_tail "grafana-zrok"
    exit 1
  fi
fi

echo
echo "Demo tunnels started."
echo "- AI Console: ${AI_PUBLIC_URL}"
echo "- Grafana:    ${GRAFANA_PROXY_PUBLIC_URL} (via AI Console auth proxy)"
if [ "${ENABLE_DIRECT_GRAFANA_ZROK}" = "true" ]; then
  echo "- Grafana direct debug: ${GRAFANA_PUBLIC_URL}"
fi
echo "- Webhook:    http://127.0.0.1:${RESPONSE_LOCAL_PORT}/webhook"
echo
echo "Logs: ${LOG_DIR}"
echo "Stop: scripts/stop-demo-tunnels.sh"
