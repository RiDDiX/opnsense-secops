#!/bin/bash
# Scheduled Security Scan Script
# Geeignet für Cronjob-Nutzung

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_DIR/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$REPORTS_DIR/scheduled_scan_$TIMESTAMP.log"

# Wechsel ins Projekt-Verzeichnis
cd "$PROJECT_DIR" || exit 1

# Logging-Funktion
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "=========================================="
log "Starting scheduled security scan"
log "=========================================="

# Source .env
if [ ! -f .env ]; then
    log "ERROR: .env file not found!"
    exit 1
fi

source .env

# Run audit
log "Running security audit..."
if docker-compose run --rm opnsense-auditor >> "$LOG_FILE" 2>&1; then
    log "✅ Audit completed successfully"

    # Find latest reports
    LATEST_HTML=$(ls -t "$REPORTS_DIR"/security_audit_*.html 2>/dev/null | head -n1)
    LATEST_JSON=$(ls -t "$REPORTS_DIR"/security_audit_*.json 2>/dev/null | head -n1)

    log "Latest reports:"
    log "  HTML: $LATEST_HTML"
    log "  JSON: $LATEST_JSON"

    # Parse JSON for critical findings
    if [ -f "$LATEST_JSON" ]; then
        CRITICAL_COUNT=$(grep -o '"critical": [0-9]*' "$LATEST_JSON" | head -n1 | grep -o '[0-9]*')
        HIGH_COUNT=$(grep -o '"high": [0-9]*' "$LATEST_JSON" | head -n1 | grep -o '[0-9]*')
        TOTAL_COUNT=$(grep -o '"total_findings": [0-9]*' "$LATEST_JSON" | head -n1 | grep -o '[0-9]*')

        log "Findings Summary:"
        log "  Total: $TOTAL_COUNT"
        log "  Critical: $CRITICAL_COUNT"
        log "  High: $HIGH_COUNT"

        # Alert if critical findings
        if [ "$CRITICAL_COUNT" -gt 0 ]; then
            log "⚠️  WARNING: $CRITICAL_COUNT critical security issues found!"
            # Hier könnte eine Benachrichtigung gesendet werden
            # send_notification "Critical security issues found: $CRITICAL_COUNT"
        fi
    fi
else
    log "❌ Audit failed! Check logs for details."
    exit 1
fi

# Cleanup old reports (älter als 30 Tage)
log "Cleaning up old reports..."
find "$REPORTS_DIR" -name "security_audit_*.html" -mtime +30 -delete
find "$REPORTS_DIR" -name "security_audit_*.json" -mtime +30 -delete
find "$REPORTS_DIR" -name "security_audit_*.txt" -mtime +30 -delete
find "$REPORTS_DIR" -name "scheduled_scan_*.log" -mtime +30 -delete

log "=========================================="
log "Scheduled scan completed"
log "=========================================="
