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

# Install the CANONICAL cron-audit.sh -- NEVER a frozen heredoc copy. The old embedded
# copy drifted badly: it predated the HMAC-key handling AND the distinct 0/1/2 exit
# codes, so on a real host it crashed on the missing secret and reported that crash as a
# FALSE "VIOLATIONS DETECTED" alert. The canonical script lives next to this one.
SRC_CRON="$SCRIPT_DIR/cron-audit.sh"
DEST_CRON="/opt/substrate-guard/scripts/cron-audit.sh"
mkdir -p /opt/substrate-guard/scripts
if [ ! -f "$SRC_CRON" ]; then
    echo "ERROR: canonical cron-audit.sh not found at $SRC_CRON" >&2
    echo "       Run deploy.sh (install_host copies scripts/ to /opt) first." >&2
    exit 1
fi
if [ "$SRC_CRON" != "$DEST_CRON" ]; then
    install -m 755 "$SRC_CRON" "$DEST_CRON"
    echo "Installed cron-audit.sh from $SRC_CRON"
else
    chmod 755 "$DEST_CRON"
    echo "cron-audit.sh already in place at $DEST_CRON"
fi

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
echo ""
echo "NOTE: the audit needs SUBSTRATE_GUARD_HMAC_SECRET (cron-audit.sh reads"
echo "      /etc/substrate-guard/hmac.key, chmod 600). Without it the audit exits 2."
