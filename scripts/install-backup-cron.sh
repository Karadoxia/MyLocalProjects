#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRON_CMD="0 3 * * * cd ${PROJECT_DIR} && npm run backup-cart > /dev/null 2>&1"
( crontab -l 2>/dev/null | grep -v -F "npm run backup-cart" || true; echo "$CRON_CMD" ) | crontab -
echo "installed cron job: $CRON_CMD"