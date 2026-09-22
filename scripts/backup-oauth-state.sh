#!/usr/bin/env bash
# Copy durable OAuth state to a backup path.
# Requires: DRLINK_RELAY_OAUTH_STATE_PATH, DRLINK_RELAY_OAUTH_STATE_BACKUP_PATH
set -euo pipefail
src="${DRLINK_RELAY_OAUTH_STATE_PATH:?DRLINK_RELAY_OAUTH_STATE_PATH is required}"
dst="${DRLINK_RELAY_OAUTH_STATE_BACKUP_PATH:?DRLINK_RELAY_OAUTH_STATE_BACKUP_PATH is required}"
if [[ ! -f "$src" ]]; then
  echo "oauth state file not found: $src" >&2
  exit 1
fi
mkdir -p -- "$(dirname -- "$dst")"
cp -a -- "$src" "$dst"
chmod 0600 -- "$dst"
echo "backed up oauth state to $dst"
