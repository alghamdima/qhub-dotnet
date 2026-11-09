#!/usr/bin/env bash
# Creates deploy/secrets/* and .env for compose.yaml. Never overwrites: delete a file to regenerate it.
# Prints no secret values. Needs openssl.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p deploy/secrets
umask 077
rand() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
new() { [ -e "$1" ] && echo "kept    $1" && return 1; echo "created $1"; }

if new .env; then
  sed "s/^QHUB_SQL_SA_PASSWORD=.*/QHUB_SQL_SA_PASSWORD=Qh$(rand 28)9!/" .env.example > .env
fi
SA=$(sed -n 's/^QHUB_SQL_SA_PASSWORD=//p' .env)

new deploy/secrets/db_connection &&
  printf 'Server=sql,1433;Database=qhub;User ID=sa;Password=%s;TrustServerCertificate=True;Encrypt=True' "$SA" > deploy/secrets/db_connection
new deploy/secrets/server_key && openssl rand -base64 32 | tr -d '\n' > deploy/secrets/server_key
new deploy/secrets/admin_password && rand 24 > deploy/secrets/admin_password
if new deploy/secrets/data_protection.pem; then
  # MSYS_NO_PATHCONV: keeps Git Bash on Windows from rewriting -subj into a path.
  MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=qhub-data-protection" \
    -keyout deploy/secrets/dp.key -out deploy/secrets/dp.crt 2>/dev/null
  cat deploy/secrets/dp.crt deploy/secrets/dp.key > deploy/secrets/data_protection.pem
  rm deploy/secrets/dp.key deploy/secrets/dp.crt
fi
# Compose mounts secret files with their host permissions and the app runs as the non-root user "app":
# the files must be world-readable, and the 700 folder keeps other users of this machine out.
chmod 700 deploy/secrets
chmod 644 deploy/secrets/*
echo "Admin password: deploy/secrets/admin_password"
