#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="${ROOT_DIR}/.demo-pids"

stop_process() {
  local name="$1"
  local pid="$2"
  local signal="TERM"
  local attempt=1

  if [[ "${name}" == *-zrok ]]; then
    signal="INT"
  fi

  echo "[stop] ${name} pid=${pid} signal=${signal}"
  kill "-${signal}" "${pid}" || true

  while [ "${attempt}" -le 10 ]; do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return
    fi

    sleep 1
    attempt=$((attempt + 1))
  done

  if kill -0 "${pid}" 2>/dev/null; then
    echo "[warn] ${name} did not stop after ${signal}; sending TERM"
    kill -TERM "${pid}" || true
  fi
}

if [ ! -d "${PID_DIR}" ]; then
  echo "No demo tunnel PID directory found."
  exit 0
fi

for pid_file in "${PID_DIR}"/*.pid; do
  [ -e "${pid_file}" ] || continue
  name="$(basename "${pid_file}" .pid)"
  pid="$(cat "${pid_file}")"

  if kill -0 "${pid}" 2>/dev/null; then
    stop_process "${name}" "${pid}"
  else
    echo "[skip] ${name} not running"
  fi

  rm -f "${pid_file}"
done

echo "Demo tunnels stopped."
