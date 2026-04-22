#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${1:-}"
BINARY="${2:-}"
EXEC_TIMEOUT="${EXEC_TIMEOUT:-}"

usage() {
  echo "Usage: $0 <container_name> <binary>"
  echo "Example: $0 master-thesis-B_external_host_01 sample.exe"
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: required command '$1' not found"
    exit 1
  }
}

need_cmd docker

[ -n "$CONTAINER" ] || usage
[ -n "$BINARY" ] || usage

if [ ! -f "$BINARY" ]; then
  echo "Error: binary '$BINARY' not found"
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "Error: container '$CONTAINER' is not running"
  exit 1
fi

FILENAME="$(basename "$BINARY")"

run_payload() {
  if [[ "$FILENAME" == *.exe ]]; then
    docker exec "$CONTAINER" sh -lc "cd /tmp && wine \"$FILENAME\""
  else
    docker exec "$CONTAINER" sh -lc "cd /tmp && chmod +x \"$FILENAME\" && ./\"$FILENAME\""
  fi
}

echo "[*] Copying $BINARY to $CONTAINER:/tmp/"
docker cp "$BINARY" "$CONTAINER:/tmp/$FILENAME"

echo "[*] Running inside container: $CONTAINER"
if [ -n "$EXEC_TIMEOUT" ]; then
  if timeout "$EXEC_TIMEOUT" bash -lc '
    set -euo pipefail
    CONTAINER="$1"
    FILENAME="$2"

    if [[ "$FILENAME" == *.exe ]]; then
      docker exec "$CONTAINER" sh -lc "cd /tmp && wine \"$FILENAME\""
    else
      docker exec "$CONTAINER" sh -lc "cd /tmp && chmod +x \"$FILENAME\" && ./\"$FILENAME\""
    fi
  ' _ "$CONTAINER" "$FILENAME"; then
    echo "[*] Execution completed"
  else
    rc=$?
    if [ "$rc" -eq 124 ]; then
      echo "[!] Execution timed out after $EXEC_TIMEOUT"
    else
      echo "[!] Execution failed"
      exit "$rc"
    fi
  fi
else
  run_payload
  echo "[*] Execution completed"
fi