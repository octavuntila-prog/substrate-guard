#!/usr/bin/env bash
# Start docker-compose.stack.yml and run doctor + audit inside substrate-guard.
# Requires: Docker Compose v2, .env optional (POSTGRES_PASSWORD; default in compose).
# SKIP_CLEANUP=1 — leave containers running after success or failure.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose -f docker-compose.stack.yml)

STACK_UP=0
teardown() {
  if [[ "${SKIP_CLEANUP:-0}" == 1 ]]; then
    return 0
  fi
  if [[ "${STACK_UP}" == 1 ]]; then
    echo "Tearing down stack..." >&2
    "${COMPOSE[@]}" down --remove-orphans 2>/dev/null || true
    STACK_UP=0
  fi
}

"${COMPOSE[@]}" up -d --build
STACK_UP=1

echo "Waiting for Postgres (max 120s)..."
ready=0
for _ in $(seq 1 120); do
  if "${COMPOSE[@]}" exec -T db pg_isready -U guard -d substrate >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "${ready}" != 1 ]]; then
  echo "ERROR: Postgres did not become ready in time." >&2
  "${COMPOSE[@]}" logs --tail 80 db >&2 || true
  teardown || true
  exit 1
fi

if ! "${COMPOSE[@]}" exec -T substrate-guard python -m substrate_guard.cli doctor; then
  teardown || true
  exit 1
fi

if ! "${COMPOSE[@]}" exec -T substrate-guard substrate-guard audit "$@"; then
  audit_ec=$?
  teardown || true
  exit "${audit_ec}"
fi

teardown || true
exit 0
