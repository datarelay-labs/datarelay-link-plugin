#!/usr/bin/env python3
"""Durable OAuth state + public-relay abuse control regressions."""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from relay.config import load_config
from relay.oauth import (
    DCR_RATE_LIMIT,
    OWNER_FAIL_LIMIT,
    OAuthError,
    OAuthService,
)
from relay.oauth_state import STATE_VERSION, DurableOAuthStore, OAuthStateError
from tests.test_relay_poc import _free_port


def _oauth_config(state_path: str, *, port: int | None = None) -> object:
    bind_port = port if port is not None else _free_port()
    return load_config(
        {
            "DRLINK_RELAY_UPSTREAM_URL": "http://127.0.0.1:9/mcp",
            "DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1",
            "DRLINK_RELAY_UPSTREAM_TOKEN": "upstream-secret-token",
            "DRLINK_RELAY_BIND": "127.0.0.1",
            "DRLINK_RELAY_PORT": str(bind_port),
            "DRLINK_RELAY_AUTH_MODE": "oauth",
            "DRLINK_RELAY_PUBLIC_BASE_URL": f"http://127.0.0.1:{bind_port}",
            "DRLINK_RELAY_OWNER_APPROVAL_SECRET": "owner-approval-secret-32chars!!",
            "DRLINK_RELAY_OAUTH_STATE_PATH": state_path,
        }
    )


class DurableOAuthStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.state_path = str(Path(self._tmpdir.name) / "oauth-state.json")
        self.owner_secret = "owner-approval-secret-32chars!!"
        self.config = _oauth_config(self.state_path)
        self.resource = self.config.resource_url  # type: ignore[attr-defined]
        self.redirect = "https://chatgpt.com/connector/oauth/durable"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _register(self, svc: OAuthService, *, source: str = "127.0.0.1") -> str:
        result = svc.register_client(
            {
                "redirect_uris": [self.redirect],
                "client_name": "chatgpt-test",
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
            source=source,
        )
        return str(result["client_id"])

    def _issue_refresh(self, svc: OAuthService, client_id: str) -> str:
        tokens = svc._issue_tokens(  # noqa: SLF001 — deterministic unit helper
            client_id=client_id,
            resource=self.resource,
            scopes=frozenset({"mcp:proxy"}),
        )
        return str(tokens["refresh_token"])

    def test_dcr_client_survives_restart(self) -> None:
        svc1 = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc1)
        svc2 = OAuthService(self.config)  # type: ignore[arg-type]
        self.assertIn(client_id, svc2.clients)
        self.assertEqual(svc2.clients[client_id].redirect_uris, [self.redirect])

    def test_refresh_reconnect_survives_restart(self) -> None:
        svc1 = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc1)
        refresh = self._issue_refresh(svc1, client_id)
        svc2 = OAuthService(self.config)  # type: ignore[arg-type]
        refreshed = svc2.exchange_token(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": client_id,
                "resource": self.resource,
            }
        )
        self.assertIn("access_token", refreshed)
        self.assertNotEqual(refreshed["refresh_token"], refresh)

    def test_revocation_survives_restart(self) -> None:
        svc1 = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc1)
        refresh = self._issue_refresh(svc1, client_id)
        svc1.revoke({"token": refresh, "token_type_hint": "refresh_token"})
        svc2 = OAuthService(self.config)  # type: ignore[arg-type]
        with self.assertRaises(OAuthError) as ctx:
            svc2.exchange_token(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh,
                    "client_id": client_id,
                }
            )
        self.assertEqual(ctx.exception.error, "invalid_grant")

    def test_persisted_state_excludes_owner_and_upstream_secrets(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc)
        self._issue_refresh(svc, client_id)
        raw = Path(self.state_path).read_text(encoding="utf-8")
        self.assertNotIn(self.owner_secret, raw)
        self.assertNotIn("upstream-secret-token", raw)
        self.assertNotIn("owner_approval_secret", raw)
        self.assertNotIn("upstream_token", raw)
        payload = json.loads(raw)
        self.assertEqual(payload["version"], STATE_VERSION)

    def test_state_file_permissions_are_restrictive(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        self._register(svc)
        mode = Path(self.state_path).stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)
        dir_mode = Path(self.state_path).parent.stat().st_mode & 0o777
        self.assertEqual(dir_mode & 0o022, 0)

    def test_corrupt_state_fail_closed(self) -> None:
        Path(self.state_path).write_text("{not-json", encoding="utf-8")
        os.chmod(self.state_path, 0o600)
        with self.assertRaises(OAuthStateError):
            OAuthService(self.config)  # type: ignore[arg-type]

    def test_schema_version_mismatch_fail_closed(self) -> None:
        Path(self.state_path).write_text(
            json.dumps({"version": 999, "clients": {}, "refresh_tokens": {}}),
            encoding="utf-8",
        )
        os.chmod(self.state_path, 0o600)
        with self.assertRaises(OAuthStateError):
            DurableOAuthStore(self.state_path).load()

    def test_world_writable_state_dir_fail_closed(self) -> None:
        bad_dir = Path(self._tmpdir.name) / "world"
        bad_dir.mkdir()
        os.chmod(bad_dir, 0o777)
        with self.assertRaises(OAuthStateError):
            DurableOAuthStore(bad_dir / "state.json")

    def test_open_file_permissions_rejected_on_load(self) -> None:
        path = Path(self._tmpdir.name) / "open.json"
        path.write_text(
            json.dumps({"version": STATE_VERSION, "clients": {}, "refresh_tokens": {}}),
            encoding="utf-8",
        )
        os.chmod(path, 0o644)
        store = DurableOAuthStore(path)
        with self.assertRaises(OAuthStateError):
            store.load()

    def test_dcr_rate_limit(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        for _ in range(DCR_RATE_LIMIT):
            self._register(svc, source="203.0.113.10")
        with self.assertRaises(OAuthError) as ctx:
            self._register(svc, source="203.0.113.10")
        self.assertEqual(ctx.exception.error, "temporarily_unavailable")
        self.assertEqual(ctx.exception.status, 429)

    def test_owner_approval_rate_limit_uniform_denial(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc)
        pending = svc.begin_authorization(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": self.redirect,
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
                "resource": self.resource,
            }
        )
        assert not isinstance(pending, dict)
        messages: list[str] = []
        for i in range(OWNER_FAIL_LIMIT + 1):
            with self.assertRaises(OAuthError) as ctx:
                svc.complete_authorization(
                    request_id=pending.request_id,
                    owner_secret=f"wrong-secret-attempt-{i:02d}!!!!",
                    decision="approve",
                    source="203.0.113.20",
                )
            self.assertEqual(ctx.exception.error, "access_denied")
            messages.append(ctx.exception.description.lower())
        self.assertTrue(all(m == "authorization denied" for m in messages))
        with self.assertRaises(OAuthError) as ctx2:
            svc.complete_authorization(
                request_id=pending.request_id,
                owner_secret=self.owner_secret,
                decision="approve",
                source="203.0.113.20",
            )
        self.assertEqual(ctx2.exception.description.lower(), "authorization denied")

    def test_atomic_roundtrip_preserves_revoked_refresh(self) -> None:
        store = DurableOAuthStore(self.state_path)
        now = time.time()
        payload = {
            "version": STATE_VERSION,
            "clients": {
                "client_1": {
                    "client_id": "client_1",
                    "redirect_uris": [self.redirect],
                    "client_name": "c",
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "issued_at": int(now),
                    "last_used_at": now,
                }
            },
            "refresh_tokens": {
                "rtk_1": {
                    "token": "rtk_1",
                    "client_id": "client_1",
                    "resource": self.resource,
                    "scopes": ["mcp:proxy"],
                    "expires_at": now + 3600,
                    "revoked": True,
                    "subject": "relay-owner",
                }
            },
        }
        store.save(payload)
        loaded = store.load()
        self.assertTrue(loaded["refresh_tokens"]["rtk_1"]["revoked"])


if __name__ == "__main__":
    unittest.main()
