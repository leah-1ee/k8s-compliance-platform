#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_DIR="${ROOT_DIR}/.demo-pids"

if [ ! -d "${PID_DIR}" ]; then
  echo "No demo tunnel PID directory found."
  exit 0
fi

for pid_file in "${PID_DIR}"/*.pid; do
  [ -e "${pid_file}" ] || continue
  name="$(basename "${pid_file}" .pid)"
  pid="$(cat "${pid_file}")"

  if kill -0 "${pid}" 2>/dev/null; then
    echo "[stop] ${name} pid=${pid}"
    kill "${pid}" || true
  else
    echo "[skip] ${name} not running"
  fi

  rm -f "${pid_file}"
done

echo "Demo tunnels stopped."
