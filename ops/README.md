Backup agent & local deployment

Options provided here help you run the cart backup/maintenance agent on a developer or edge host.

Systemd (recommended for Linux desktop/server):

1. Copy `ops/backup-agent.service` to `/etc/systemd/system/` and `ops/backup-agent.timer` to the same folder.
2. sudo systemctl daemon-reload
3. sudo systemctl enable --now backup-cart.timer

Cron (alternate):

- Use `scripts/install-backup-cron.sh` to add a daily cron entry that runs `npm run backup-cart` in the project directory.

Notes:
- The backup agent simply copies `data/cart.json` to `backups/cart-<timestamp>.json`.
- The scripts are best-effort and safe to run concurrently.
