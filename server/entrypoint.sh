#!/usr/bin/env bash
# Container entrypoint. If Backblaze B2 (S3) credentials are present, restore the
# SQLite DB from object storage on boot and run the server under Litestream so
# every write is streamed back — durable across Render free-tier restarts. If
# not configured, run the server directly (ephemeral storage).
set -e

DB="${DATA_DIR:-/data}/whitelist.db"
mkdir -p "$(dirname "$DB")"

if [ -n "${B2_BUCKET:-}" ] && [ -n "${LITESTREAM_ACCESS_KEY_ID:-}" ]; then
  echo "[entrypoint] Litestream enabled — restoring $DB from B2 (if a backup exists)"
  litestream restore -if-replica-exists "$DB" || echo "[entrypoint] no existing replica; starting fresh"
  echo "[entrypoint] starting server under Litestream replication"
  exec litestream replicate -exec "node src/index.js"
else
  echo "[entrypoint] Litestream NOT configured (no B2 creds) — EPHEMERAL storage"
  exec node src/index.js
fi
