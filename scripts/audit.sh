#!/bin/bash
# substrate-guard — Run real DB audit
# Usage:
#   ./audit.sh              # Audit ALL records
#   ./audit.sh 24           # Audit last 24 hours
#   ./audit.sh 1            # Audit last 1 hour
#   ./audit.sh docker       # Run audit from Docker container
#   ./audit.sh docker 24    # Docker audit, last 24 hours

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_DIR="/opt/ai-research-agency"
ENV_FILE="${APP_DIR}/.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Parse .env for DB credentials ──
if [ -f "$ENV_FILE" ]; then
    # Source .env safely
    export $(grep -E '^(POSTGRES_USER|POSTGRES_PASSWORD|POSTGRES_DB|POSTGRES_HOST|POSTGRES_PORT|DATABASE_URL)=' "$ENV_FILE" | xargs)
fi

# Build DB URL — strip +asyncpg from DATABASE_URL if present
if [ -n "${DATABASE_URL:-}" ]; then
    DB_URL=$(echo "$DATABASE_URL" | sed 's|postgresql+asyncpg://|postgresql://|' | sed 's|postgres+asyncpg://|postgresql://|' | sed 's|postgres://|postgresql://|')
else
    DB_HOST="${POSTGRES_HOST:-localhost}"
    DB_PORT="${POSTGRES_PORT:-5432}"
    DB_USER="${POSTGRES_USER:-}"
    DB_PASS="${POSTGRES_PASSWORD:-}"
    DB_NAME="${POSTGRES_DB:-}"
    DB_URL="postgresql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
fi

# Resolve postgres container IP for host-side access
# "postgres" hostname only works inside Docker network, not from host
resolve_postgres_ip() {
    local CONTAINER_NAME="ai-research-agency-postgres-1"
    # Try common container name patterns
    for name in "$CONTAINER_NAME" "postgres" "ai-research-agency_postgres_1"; do
        local ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name" 2>/dev/null)
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    done
    # Fallback: localhost (works if postgres port is exposed)
    echo "localhost"
}

HOST_DB_URL="$DB_URL"
if echo "$HOST_DB_URL" | grep -q "@postgres:"; then
    PG_IP=$(resolve_postgres_ip)
    HOST_DB_URL=$(echo "$HOST_DB_URL" | sed "s|@postgres:|@${PG_IP}:|")
fi

# Extract user/pass/db from DB_URL for Docker usage
DB_USER="${DB_USER:-$(echo "$DB_URL" | sed -n 's|postgresql://\([^:]*\):.*|\1|p')}"
DB_PASS="${DB_PASS:-$(echo "$DB_URL" | sed -n 's|postgresql://[^:]*:\([^@]*\)@.*|\1|p')}"
DB_NAME="${DB_NAME:-$(echo "$DB_URL" | sed -n 's|.*/\([^?]*\).*|\1|p')}"

MODE="${1:-all}"
HOURS="${2:-}"

case "$MODE" in
    docker)
        # Run from Docker container (uses internal network, postgres hostname)
        DOCKER_DB_URL="postgresql://${DB_USER}:${DB_PASS}@postgres:5432/${DB_NAME}"
        
        echo -e "${CYAN}Running audit from Docker container...${NC}"
        
        HOURS_ARG=""
        if [ -n "$HOURS" ]; then
            HOURS_ARG="--hours $HOURS"
        fi
        
        cd "$APP_DIR"
        docker compose -f docker-compose.guard.yml run --rm substrate-guard \
            python -m substrate_guard.audit --db-url "$DOCKER_DB_URL" $HOURS_ARG
        ;;
    
    [0-9]*)
        # Number = hours to audit, run on host
        echo -e "${CYAN}Running audit on host (last ${MODE} hours)...${NC}"
        
        # Check if psycopg2 is available
        python3 -c "import psycopg2" 2>/dev/null || {
            echo -e "${RED}psycopg2 not installed. Installing...${NC}"
            pip3 install psycopg2-binary --break-system-packages -q
        }
        
        cd "$PROJECT_DIR"
        PYTHONPATH="$PROJECT_DIR" python3 -m substrate_guard.audit \
            --db-url "$HOST_DB_URL" --hours "$MODE"
        ;;
    
    all)
        # Audit everything, run on host
        echo -e "${CYAN}Running FULL audit on host (all records)...${NC}"
        
        python3 -c "import psycopg2" 2>/dev/null || {
            echo -e "${RED}psycopg2 not installed. Installing...${NC}"
            pip3 install psycopg2-binary --break-system-packages -q
        }
        
        cd "$PROJECT_DIR"
        PYTHONPATH="$PROJECT_DIR" python3 -m substrate_guard.audit \
            --db-url "$HOST_DB_URL"
        ;;
    
    *)
        echo "Usage: ./audit.sh [all|<hours>|docker [hours]]"
        echo ""
        echo "  all           Audit ALL records from DB (default)"
        echo "  <hours>       Audit last N hours (e.g., ./audit.sh 24)"
        echo "  docker        Run audit from Docker container"
        echo "  docker <hours> Docker audit, last N hours"
        ;;
esac
