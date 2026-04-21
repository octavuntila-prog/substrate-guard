#!/bin/bash
# substrate-guard daily audit — called by cron
# Runs after db-backup.sh (03:00), before disk-monitor.sh cycle

LOG_DIR="/var/log/substrate-guard"
LOG_FILE="$LOG_DIR/cron_$(date +%Y%m%d).log"
APP_DIR="/opt/ai-research-agency"

mkdir -p "$LOG_DIR"

{
    echo "=== substrate-guard audit: $(date) ==="
    
    # Source DB credentials
    if [ -f "$APP_DIR/.env" ]; then
        export $(grep -E '^(POSTGRES_USER|POSTGRES_PASSWORD|POSTGRES_DB|DATABASE_URL)=' "$APP_DIR/.env" | xargs)
    fi
    
    # Strip +asyncpg from DATABASE_URL, fallback to component parts
    if [ -n "${DATABASE_URL:-}" ]; then
        DB_URL=$(echo "$DATABASE_URL" | sed 's|postgresql+asyncpg://|postgresql://|' | sed 's|postgres+asyncpg://|postgresql://|' | sed 's|postgres://|postgresql://|')
    else
        DB_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}"
    fi
    
    # Cron runs on host — resolve postgres container IP via docker inspect
    if echo "$DB_URL" | grep -q "@postgres:"; then
        PG_IP=""
        for name in "ai-research-agency-postgres-1" "postgres" "ai-research-agency_postgres_1"; do
            PG_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name" 2>/dev/null || true)
            [ -n "$PG_IP" ] && break
        done
        PG_IP="${PG_IP:-localhost}"
        DB_URL=$(echo "$DB_URL" | sed "s|@postgres:|@${PG_IP}:|")
    fi
    
    # Run audit for last 24 hours
    cd /opt/substrate-guard
    PYTHONPATH=/opt/substrate-guard python3 -m substrate_guard.audit \
        --db-url "$DB_URL" \
        --hours 24 \
        --output "$LOG_DIR" 2>&1
    
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -ne 0 ]; then
        echo "VIOLATIONS DETECTED — sending alert"
        # Use existing Telegram bot (same as watchdog.sh and disk-monitor.sh)
        if [ -f "$APP_DIR/.env" ]; then
            export $(grep -E '^(TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|TELEGRAM_ADMIN_ID)=' "$APP_DIR/.env" | xargs)
            # Use TELEGRAM_CHAT_ID if present, otherwise fall back to TELEGRAM_ADMIN_ID
            TELEGRAM_TARGET="${TELEGRAM_CHAT_ID:-${TELEGRAM_ADMIN_ID:-}}"
            if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "$TELEGRAM_TARGET" ]; then
                LATEST_REPORT=$(ls -t "$LOG_DIR"/audit_*.json 2>/dev/null | head -1)
                if [ -n "$LATEST_REPORT" ]; then
                    VIOLATIONS=$(python3 -c "import json; d=json.load(open('$LATEST_REPORT')); print(d['evaluation']['violations'])")
                    EVENTS=$(python3 -c "import json; d=json.load(open('$LATEST_REPORT')); print(d['events_generated'])")
                    MSG="⚠️ substrate-guard: ${VIOLATIONS} violations in ${EVENTS} events (last 24h). Check $LATEST_REPORT"
                else
                    MSG="⚠️ substrate-guard: Violations detected but no report file found"
                fi
                curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
                    -d "chat_id=${TELEGRAM_TARGET}" \
                    -d "text=${MSG}" > /dev/null 2>&1 || true
            fi
        fi
    fi
    
    echo "=== Done: $(date) ==="
    
} >> "$LOG_FILE" 2>&1
