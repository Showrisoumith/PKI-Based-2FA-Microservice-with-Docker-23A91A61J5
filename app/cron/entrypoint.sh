#!/bin/sh
set -e

echo "[entrypoint] timezone: ${TZ:-UTC}"
# Ensure timezone (if a different TZ env var is provided)
if [ -n "$TZ" ]; then
  ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime || true
fi

# Install cron job files from /app/cron -> /etc/cron.d
if [ -d /app/cron ]; then
  for f in /app/cron/*; do
    # skip the entrypoint itself
    if [ -f "$f" ] && [ "$(basename "$f")" != "entrypoint.sh" ]; then
      echo "[entrypoint] installing cron file: $f"
      cp "$f" /etc/cron.d/$(basename "$f")
      chmod 0644 /etc/cron.d/$(basename "$f")
    fi
  done
fi

# Ensure /data exists (volume mount) and has safe permissions
mkdir -p /data
chmod 0755 /data || true

echo "[entrypoint] starting cron..."
# Start cron daemon (background)
cron

# small delay so cron has time to start
sleep 1

echo "[entrypoint] starting uvicorn on 0.0.0.0:8080..."
# Ensure working dir so Python can import app package
cd /app || exit 1

# Start uvicorn as PID 1 (so container lifecycle follows the server)
exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --app-dir /app
