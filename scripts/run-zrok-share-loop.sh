#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <name> <zrok command...>" >&2
  exit 2
fi

NAME="$1"
shift
RESTART_DELAY_SECONDS="${ZROK_RESTART_DELAY_SECONDS:-3}"
CHILD_PID=""

stop_child() {
  if [ -n "${CHILD_PID}" ] && kill -0 "${CHILD_PID}" 2>/dev/null; then
    kill "${CHILD_PID}" 2>/dev/null || true
    wait "${CHILD_PID}" 2>/dev/null || true
  fi
}

trap 'stop_child; exit 0' INT TERM

while true; do
  echo "[$(date -Is)] starting ${NAME}: $*"
  "$@" &
  CHILD_PID="$!"
  set +e
  wait "${CHILD_PID}"
  STATUS="$?"
  set -e
  CHILD_PID=""
  echo "[$(date -Is)] ${NAME} exited status=${STATUS}; restarting in ${RESTART_DELAY_SECONDS}s"
  sleep "${RESTART_DELAY_SECONDS}"
done
