#!/bin/bash
# substrate-guard daily audit — called by cron
# Runs after db-backup.sh (03:00), before disk-monitor.sh cycle

# Paths are env-overridable (same production defaults) so the exit-code logic can be
# exercised by tests without touching /etc or /opt (M-g).
LOG_DIR="${LOG_DIR:-/var/log/substrate-guard}"
LOG_FILE="$LOG_DIR/cron_$(date +%Y%m%d).log"
APP_DIR="${APP_DIR:-/opt/ai-research-agency}"
GUARD_DIR="${GUARD_DIR:-/opt/substrate-guard}"

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

    # Telegram alert helper -- defined HERE, BEFORE the HMAC checks, so the most-likely
    # first-deploy failure (a missing/insecure key) actually pages instead of being a
    # silent daily no-op. (It used to be defined only after the audit ran.)
    _send_telegram() {
        if [ -f "$APP_DIR/.env" ]; then
            export $(grep -E '^(TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|TELEGRAM_ADMIN_ID)=' "$APP_DIR/.env" | xargs)
            TELEGRAM_TARGET="${TELEGRAM_CHAT_ID:-${TELEGRAM_ADMIN_ID:-}}"
            if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -n "$TELEGRAM_TARGET" ]; then
                curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
                    -d "chat_id=${TELEGRAM_TARGET}" -d "text=$1" > /dev/null 2>&1 || true
            fi
        fi
    }

    # HMAC secret for tamper-evident chain (v13.4.0 — Decision 1: fail-loud).
    # Production deployments MUST have /etc/substrate-guard/hmac.key configured
    # with a stable secret (chmod 600). Random fallback would lose cross-run
    # chain verifiability, so we abort here if missing or insecure.
    HMAC_KEY_FILE="${HMAC_KEY_FILE:-/etc/substrate-guard/hmac.key}"
    if [ ! -f "$HMAC_KEY_FILE" ]; then
        echo "FATAL: HMAC key file missing at $HMAC_KEY_FILE"
        echo "       Set up via: openssl rand -hex 32 > $HMAC_KEY_FILE && chmod 600 $HMAC_KEY_FILE"
        echo "       See docs/releases/v13.4.0.md for ops procedure."
        _send_telegram "🔧 substrate-guard cron: HMAC key MISSING at $HMAC_KEY_FILE — audit did NOT run (exit 2). Create it (chmod 600)."
        exit 2  # 2 = setup ERROR (not a policy violation)
    fi
    PERMS=$(stat -c %a "$HMAC_KEY_FILE" 2>/dev/null)
    if [ "$PERMS" != "600" ] && [ "$PERMS" != "400" ]; then
        echo "FATAL: HMAC key file has insecure permissions ($PERMS), must be 600 or 400"
        echo "       Fix via: chmod 600 $HMAC_KEY_FILE"
        _send_telegram "🔧 substrate-guard cron: HMAC key has INSECURE perms ($PERMS) — audit did NOT run (exit 2). chmod 600 $HMAC_KEY_FILE."
        exit 2  # 2 = setup ERROR (not a policy violation)
    fi
    export SUBSTRATE_GUARD_HMAC_SECRET=$(cat "$HMAC_KEY_FILE")

    # Policy engine: defaults to built-in Python rules.
    # To activate Rego enforcement (requires OPA binary installed):
    #   export SUBSTRATE_GUARD_POLICY=rego
    # Or override per-run:
    #   python3 -m substrate_guard.audit --policy rego [...]

    # Run audit for last 24 hours
    cd "$GUARD_DIR"
    PYTHONPATH="$GUARD_DIR" python3 -m substrate_guard.audit \
        --db-url "$DB_URL" \
        --hours 24 \
        --output "$LOG_DIR" 2>&1
    
    EXIT_CODE=$?

    # Audit exit-code contract (substrate_guard.audit): 0 = clean, 1 = policy
    # violations, 2 = audit ERROR (DB/config). A DB outage is an ERROR, NOT a
    # violation, so it must not fire the "VIOLATIONS DETECTED" alert.
    if [ $EXIT_CODE -eq 0 ]; then
        echo "Audit clean — no violations"
    elif [ $EXIT_CODE -eq 1 ]; then
        echo "VIOLATIONS DETECTED — sending alert"
        LATEST_REPORT=$(ls -t "$LOG_DIR"/audit_*.json 2>/dev/null | head -1)
        if [ -n "$LATEST_REPORT" ]; then
            VIOLATIONS=$(python3 -c "import json; d=json.load(open('$LATEST_REPORT')); print(d['evaluation']['violations'])")
            EVENTS=$(python3 -c "import json; d=json.load(open('$LATEST_REPORT')); print(d['events_generated'])")
            MSG="⚠️ substrate-guard: ${VIOLATIONS} violations in ${EVENTS} events (last 24h). Check $LATEST_REPORT"
        else
            MSG="⚠️ substrate-guard: Violations detected but no report file found"
        fi
        _send_telegram "$MSG"
    else
        echo "AUDIT ERROR (exit $EXIT_CODE) — DB/config failure, NOT a violation"
        _send_telegram "🔧 substrate-guard: audit FAILED to run (exit ${EXIT_CODE}) — DB/config error, NOT a policy violation. Check $LOG_FILE"
    fi
    
    echo "=== Done: $(date) ==="
    
} >> "$LOG_FILE" 2>&1
