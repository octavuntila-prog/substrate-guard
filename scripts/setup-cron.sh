#!/bin/bash
# substrate-guard — Setup automated audit cron job
# Adds a daily audit to the existing crontab on ai-research-agency
#
# Runs: Every day at 04:00 (after db-backup at 03:00)
# Audits: Last 24 hours of pipeline_traces + agent_runs
# Output: /var/log/substrate-guard/audit_YYYYMMDD_HHMMSS.json
# Alert: Sends Telegram notification if violations found

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD_DIR="$(dirname "$SCRIPT_DIR")"

echo "Setting up substrate-guard daily audit cron..."

# Create the audit wrapper that the cron will call
cat > /opt/substrate-guard/scripts/cron-audit.sh << 'CRONSCRIPT'
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
            export $(grep -E '^(TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID)=' "$APP_DIR/.env" | xargs)
            if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "${TELEGRAM_CHAT_ID:-}" ]; then
                LATEST_REPORT=$(ls -t "$LOG_DIR"/audit_*.json 2>/dev/null | head -1)
                if [ -n "$LATEST_REPORT" ]; then
                    VIOLATIONS=$(python3 -c "import json; d=json.load(open('$LATEST_REPORT')); print(d['evaluation']['violations'])")
                    EVENTS=$(python3 -c "import json; d=json.load(open('$LATEST_REPORT')); print(d['events_generated'])")
                    MSG="⚠️ substrate-guard: ${VIOLATIONS} violations in ${EVENTS} events (last 24h). Check $LATEST_REPORT"
                else
                    MSG="⚠️ substrate-guard: Violations detected but no report file found"
                fi
                curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
                    -d "chat_id=${TELEGRAM_CHAT_ID}" \
                    -d "text=${MSG}" > /dev/null 2>&1 || true
            fi
        fi
    fi
    
    echo "=== Done: $(date) ==="
    
} >> "$LOG_FILE" 2>&1
CRONSCRIPT

chmod +x /opt/substrate-guard/scripts/cron-audit.sh

# Add to crontab (after db-backup at 03:00, before watchdog cycle)
# Check if already added
if crontab -l 2>/dev/null | grep -q "substrate-guard"; then
    echo "Cron entry already exists — skipping"
else
    (crontab -l 2>/dev/null; echo "0 4 * * * /opt/substrate-guard/scripts/cron-audit.sh") | crontab -
    echo "Added cron: 0 4 * * * /opt/substrate-guard/scripts/cron-audit.sh"
fi

# Verify
echo ""
echo "Current crontab:"
crontab -l 2>/dev/null | grep -E "(substrate-guard|db-backup|watchdog|disk-monitor)"
echo ""
echo "Done. Audit runs daily at 04:00."
echo "Logs: /var/log/substrate-guard/cron_YYYYMMDD.log"
echo "Reports: /var/log/substrate-guard/audit_YYYYMMDD_HHMMSS.json"
echo "Alerts: Telegram (if violations found)"
