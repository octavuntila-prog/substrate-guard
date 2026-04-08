#!/usr/bin/env bash
# Start docker-compose.stack.yml and run doctor + audit inside substrate-guard.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose -f docker-compose.stack.yml)
"${COMPOSE[@]}" up -d --build
echo "Waiting for Postgres health..."
for i in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T db pg_isready -U guard -d substrate >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"${COMPOSE[@]}" exec -T substrate-guard python -m substrate_guard.cli doctor
"${COMPOSE[@]}" exec -T substrate-guard substrate-guard audit "$@"
