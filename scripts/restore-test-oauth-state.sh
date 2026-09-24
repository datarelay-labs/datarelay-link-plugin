#!/usr/bin/env bash
# Prove durable OAuth state can be written and reloaded (restore path).
# Uses an isolated temp file; does not touch production state.
set -euo pipefail
ROOT="$(cd "$(dirname -- "$0")/.." && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec python3 - <<'PY'
import os
import tempfile
import time
from pathlib import Path

from relay.oauth_state import STATE_VERSION, DurableOAuthStore

with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp) / "oauth-state.json"
    store = DurableOAuthStore(path)
    now = time.time()
    payload = {
        "version": STATE_VERSION,
        "clients": {
            "client_restore": {
                "client_id": "client_restore",
                "redirect_uris": ["https://chatgpt.com/connector/oauth/restore"],
                "client_name": "restore-test",
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "issued_at": int(now),
                "last_used_at": now,
            }
        },
        "refresh_tokens": {
            "rtk_restore": {
                "token": "rtk_restore",
                "client_id": "client_restore",
                "resource": "http://127.0.0.1/mcp",
                "scopes": ["mcp:proxy"],
                "expires_at": now + 3600,
                "revoked": False,
                "subject": "relay-owner",
            }
        },
        "server_bindings": {
            "bnd_restore": {
                "binding_id": "bnd_restore",
                "subject": "relay-owner",
                "upstream_url": "http://127.0.0.1:9/mcp",
                "upstream_host": "127.0.0.1",
                "connect_ips": ["127.0.0.1"],
                "allow_loopback": True,
                "upstream_bearer": "restore-bearer",
                "connected": True,
                "active": True,
                "created_at": now,
            }
        },
    }
    store.save(payload)
    loaded = DurableOAuthStore(path).load()
    assert loaded["clients"]["client_restore"]["client_id"] == "client_restore"
    assert loaded["refresh_tokens"]["rtk_restore"]["token"] == "rtk_restore"
    assert loaded["server_bindings"]["bnd_restore"]["binding_id"] == "bnd_restore"
    assert loaded["server_bindings"]["bnd_restore"]["upstream_bearer"] == "restore-bearer"
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600, mode
print("oauth state restore-test PASS")
PY
