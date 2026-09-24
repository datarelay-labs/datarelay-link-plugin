#!/usr/bin/env python3
"""Durable OAuth state + public-relay abuse control regressions."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from relay.config import load_config
from relay import oauth as oauth_mod
from relay.oauth import (
    AUTHZ_RATE_LIMIT,
    DCR_RATE_LIMIT,
    INACTIVE_CLIENT_TTL_S,
    MAX_DCR_CLIENTS,
    MAX_INACTIVE_DCR_CLIENTS,
    MAX_PENDING_AUTHORIZATIONS,
    MAX_PENDING_PER_CLIENT,
    OWNER_FAIL_LIMIT,
    OAuthError,
    OAuthService,
    _SlidingWindow,
)
from relay.oauth_state import STATE_VERSION, DurableOAuthStore, OAuthStateError
from tests.test_relay_poc import _free_port


def _oauth_config(state_path: str, *, port: int | None = None) -> object:
    bind_port = port if port is not None else _free_port()
    return load_config(
        {
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

    def test_inactive_pool_fill_cannot_block_legitimate_registration(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        for i in range(MAX_INACTIVE_DCR_CLIENTS):
            self._register(svc, source=f"198.51.100.{i}")
        self.assertEqual(len(svc.clients), MAX_INACTIVE_DCR_CLIENTS)
        legitimate = self._register(svc, source="203.0.113.50")
        self.assertIn(legitimate, svc.clients)
        self.assertLessEqual(len(svc.clients), MAX_INACTIVE_DCR_CLIENTS)

    def test_oldest_inactive_evicted_at_capacity(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        oldest = self._register(svc, source="198.51.100.1")
        # Ensure deterministic oldest ordering even if clock resolution is coarse.
        svc.clients[oldest].issued_at -= 10
        svc.clients[oldest].last_used_at -= 10
        for i in range(MAX_INACTIVE_DCR_CLIENTS - 1):
            self._register(svc, source=f"198.51.100.{i + 2}")
        self.assertEqual(len(svc.clients), MAX_INACTIVE_DCR_CLIENTS)
        self.assertIn(oldest, svc.clients)
        newer = self._register(svc, source="203.0.113.60")
        self.assertNotIn(oldest, svc.clients)
        self.assertIn(newer, svc.clients)

    def test_active_client_with_live_refresh_never_evicted(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        active = self._register(svc, source="198.51.100.1")
        refresh = self._issue_refresh(svc, active)
        for round_i in range(3):
            for i in range(MAX_INACTIVE_DCR_CLIENTS):
                self._register(svc, source=f"198.51.100.{(round_i * 32 + i) % 200 + 2}")
        self.assertIn(active, svc.clients)
        self.assertTrue(svc._client_has_live_refresh(active, now=time.time()))  # noqa: SLF001
        churn = self._register(svc, source="203.0.113.200")
        self.assertIn(active, svc.clients)
        self.assertIn(churn, svc.clients)
        refreshed = svc.exchange_token(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": active,
                "resource": self.resource,
            }
        )
        self.assertIn("access_token", refreshed)

    def test_inactive_ttl_cleanup_persists_across_restart(self) -> None:
        svc1 = OAuthService(self.config)  # type: ignore[arg-type]
        expired = self._register(svc1, source="198.51.100.1")
        keep = self._register(svc1, source="198.51.100.2")
        svc1.clients[expired].last_used_at -= INACTIVE_CLIENT_TTL_S + 5
        svc1.clients[expired].issued_at = int(svc1.clients[expired].last_used_at)
        svc1._persist_locked()  # noqa: SLF001
        svc2 = OAuthService(self.config)  # type: ignore[arg-type]
        self.assertNotIn(expired, svc2.clients)
        self.assertIn(keep, svc2.clients)
        payload = json.loads(Path(self.state_path).read_text(encoding="utf-8"))
        self.assertNotIn(expired, payload["clients"])
        self.assertIn(keep, payload["clients"])

    def test_distributed_sources_cannot_lock_out_real_client(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        # Many distinct sources past the historical hard-full table size.
        for i in range(MAX_DCR_CLIENTS + 8):
            self._register(svc, source=f"203.0.113.{(i % 250) + 1}")
        self.assertLessEqual(len(svc.clients), MAX_INACTIVE_DCR_CLIENTS)
        real = self._register(svc, source="198.51.100.99")
        self.assertIn(real, svc.clients)
        refresh = self._issue_refresh(svc, real)
        for i in range(MAX_INACTIVE_DCR_CLIENTS + 4):
            self._register(svc, source=f"192.0.2.{(i % 250) + 1}")
        self.assertIn(real, svc.clients)
        svc2 = OAuthService(self.config)  # type: ignore[arg-type]
        self.assertIn(real, svc2.clients)
        refreshed = svc2.exchange_token(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": real,
                "resource": self.resource,
            }
        )
        self.assertIn("access_token", refreshed)

    def test_full_active_capacity_still_rejects(self) -> None:
        """Only when every durable slot holds a live-refresh client do we reject."""
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        original_max = oauth_mod.MAX_DCR_CLIENTS
        original_inactive = oauth_mod.MAX_INACTIVE_DCR_CLIENTS
        try:
            oauth_mod.MAX_DCR_CLIENTS = 3
            oauth_mod.MAX_INACTIVE_DCR_CLIENTS = 3
            for i in range(3):
                cid = self._register(svc, source=f"198.51.100.{i}")
                self._issue_refresh(svc, cid)
            with self.assertRaises(OAuthError) as ctx:
                self._register(svc, source="203.0.113.1")
            self.assertEqual(ctx.exception.error, "invalid_client_metadata")
            self.assertIn("limit reached", ctx.exception.description)
        finally:
            oauth_mod.MAX_DCR_CLIENTS = original_max
            oauth_mod.MAX_INACTIVE_DCR_CLIENTS = original_inactive

    def _authorize(
        self, svc: OAuthService, client_id: str, *, source: str = "127.0.0.1"
    ):
        return svc.begin_authorization(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": self.redirect,
                "code_challenge": "challenge",
                "code_challenge_method": "S256",
                "resource": self.resource,
            },
            source=source,
        )

    def test_pending_expired_swept_before_admit(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc)
        first = self._authorize(svc, client_id)
        assert not isinstance(first, dict)
        first.expires_at = time.time() - 1
        svc.pending[first.request_id] = first
        second = self._authorize(svc, client_id, source="198.51.100.2")
        assert not isinstance(second, dict)
        self.assertNotIn(first.request_id, svc.pending)
        self.assertIn(second.request_id, svc.pending)

    def test_pending_per_client_capacity_rejects_without_eviction(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc, source="198.51.100.1")
        kept: list[str] = []
        for i in range(MAX_PENDING_PER_CLIENT):
            pending = self._authorize(svc, client_id, source=f"198.51.100.{i + 10}")
            assert not isinstance(pending, dict)
            kept.append(pending.request_id)
        self.assertEqual(len(svc.pending), MAX_PENDING_PER_CLIENT)
        with self.assertRaises(OAuthError) as ctx:
            self._authorize(svc, client_id, source="198.51.100.99")
        self.assertEqual(ctx.exception.error, "temporarily_unavailable")
        self.assertEqual(ctx.exception.status, 429)
        for request_id in kept:
            self.assertIn(request_id, svc.pending)
        # A different client can still admit while this client is at cap.
        other = self._register(svc, source="203.0.113.50")
        other_pending = self._authorize(svc, other, source="203.0.113.51")
        assert not isinstance(other_pending, dict)
        for request_id in kept:
            self.assertIn(request_id, svc.pending)

    def test_same_public_client_distributed_churn_preserves_consent(self) -> None:
        """Same public client_id churn from many sources must not drop live consent."""
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc, source="198.51.100.1")
        verifier = "same-client-consent-verifier-value-0001"
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        legitimate = svc.begin_authorization(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": self.redirect,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": self.resource,
            },
            source="203.0.113.10",
        )
        assert not isinstance(legitimate, dict)
        legitimate_id = legitimate.request_id

        rejected = 0
        for i in range(MAX_PENDING_PER_CLIENT * 8):
            try:
                pending = self._authorize(
                    svc, client_id, source=f"192.0.2.{(i % 250) + 1}"
                )
                assert not isinstance(pending, dict)
            except OAuthError as exc:
                self.assertEqual(exc.error, "temporarily_unavailable")
                self.assertEqual(exc.status, 429)
                rejected += 1
        self.assertGreater(rejected, 0)
        self.assertIn(legitimate_id, svc.pending)
        self.assertLessEqual(
            sum(1 for p in svc.pending.values() if p.client_id == client_id),
            MAX_PENDING_PER_CLIENT,
        )
        self.assertLessEqual(len(svc.pending), MAX_PENDING_AUTHORIZATIONS)

        location = svc.complete_authorization(
            request_id=legitimate_id,
            owner_secret=self.owner_secret,
            decision="approve",
            source="127.0.0.1",
        )
        code = parse_qs(urlparse(location).query)["code"][0]
        tokens = svc.exchange_token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": self.resource,
            }
        )
        self.assertIn("access_token", tokens)
        self.assertIn("refresh_token", tokens)

    def test_cross_client_pending_churn_cannot_evict_legitimate(self) -> None:
        """Other clients filling global capacity must not displace live consent."""
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        legitimate_client = self._register(svc, source="203.0.113.1")
        legitimate = self._authorize(svc, legitimate_client, source="203.0.113.2")
        assert not isinstance(legitimate, dict)
        # Fill remaining global capacity via many distinct churn clients/sources.
        created = 0
        source_i = 0
        while len(svc.pending) < MAX_PENDING_AUTHORIZATIONS:
            churn = self._register(svc, source=f"198.51.100.{(source_i % 200) + 1}")
            for _ in range(MAX_PENDING_PER_CLIENT):
                if len(svc.pending) >= MAX_PENDING_AUTHORIZATIONS:
                    break
                source_i += 1
                pending = self._authorize(
                    svc, churn, source=f"203.0.113.{(source_i % 200) + 20}"
                )
                assert not isinstance(pending, dict)
                created += 1
            if created > MAX_PENDING_AUTHORIZATIONS * 4:
                self.fail("could not fill pending capacity for regression")
        self.assertEqual(len(svc.pending), MAX_PENDING_AUTHORIZATIONS)
        self.assertIn(legitimate.request_id, svc.pending)
        # Additional authorize at global capacity must reject, not evict.
        attacker = self._register(svc, source="192.0.2.50")
        with self.assertRaises(OAuthError) as ctx:
            self._authorize(svc, attacker, source="192.0.2.200")
        self.assertEqual(ctx.exception.error, "temporarily_unavailable")
        self.assertEqual(ctx.exception.status, 429)
        self.assertIn(legitimate.request_id, svc.pending)
        self.assertEqual(len(svc.pending), MAX_PENDING_AUTHORIZATIONS)

    def test_authorize_does_not_persist_or_refresh_inactive_ttl(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc)
        before_mtime = Path(self.state_path).stat().st_mtime_ns
        before_used = svc.clients[client_id].last_used_at
        time.sleep(0.02)
        pending = self._authorize(svc, client_id)
        assert not isinstance(pending, dict)
        after_mtime = Path(self.state_path).stat().st_mtime_ns
        self.assertEqual(after_mtime, before_mtime)
        self.assertEqual(svc.clients[client_id].last_used_at, before_used)

    def test_pending_churn_cannot_unboundedly_grow(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc)
        admitted = 0
        for i in range(MAX_PENDING_AUTHORIZATIONS * 3):
            try:
                pending = self._authorize(
                    svc, client_id, source=f"198.51.100.{(i % 200) + 1}"
                )
                assert not isinstance(pending, dict)
                admitted += 1
            except OAuthError as exc:
                self.assertEqual(exc.error, "temporarily_unavailable")
        self.assertEqual(admitted, MAX_PENDING_PER_CLIENT)
        self.assertLessEqual(len(svc.pending), MAX_PENDING_AUTHORIZATIONS)
        self.assertLessEqual(
            sum(1 for p in svc.pending.values() if p.client_id == client_id),
            MAX_PENDING_PER_CLIENT,
        )

    def test_authz_pending_rate_limit_per_source(self) -> None:
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc)
        for _ in range(AUTHZ_RATE_LIMIT):
            pending = self._authorize(svc, client_id, source="203.0.113.77")
            assert not isinstance(pending, dict)
            # Free per-client slot so the per-source limiter is what trips.
            del svc.pending[pending.request_id]
        with self.assertRaises(OAuthError) as ctx:
            self._authorize(svc, client_id, source="203.0.113.77")
        self.assertEqual(ctx.exception.error, "temporarily_unavailable")
        self.assertEqual(ctx.exception.status, 429)
        # A different source can still start authorize.
        other = self._authorize(svc, client_id, source="198.51.100.77")
        assert not isinstance(other, dict)

    def test_pending_client_survives_inactive_cleanup_through_token(self) -> None:
        """Consent-open client must not be removed by DCR cleanup before approval."""
        svc = OAuthService(self.config)  # type: ignore[arg-type]
        client_id = self._register(svc, source="198.51.100.1")
        verifier = "test-verifier-value-for-pending-protection-01"
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        pending = svc.begin_authorization(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": self.redirect,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": self.resource,
            },
            source="198.51.100.2",
        )
        assert not isinstance(pending, dict)
        # Age past inactive TTL without durable authorize touch.
        svc.clients[client_id].last_used_at -= INACTIVE_CLIENT_TTL_S + 5
        svc.clients[client_id].issued_at = int(svc.clients[client_id].last_used_at)
        svc._persist_locked()  # noqa: SLF001
        # Force inactive capacity pressure via new DCR registrations.
        for i in range(MAX_INACTIVE_DCR_CLIENTS + 2):
            try:
                self._register(svc, source=f"203.0.113.{(i % 200) + 1}")
            except OAuthError:
                # Capacity may reject once pending-protected slots occupy the budget.
                break
        self.assertIn(client_id, svc.clients)
        self.assertIn(pending.request_id, svc.pending)
        location = svc.complete_authorization(
            request_id=pending.request_id,
            owner_secret=self.owner_secret,
            decision="approve",
            source="127.0.0.1",
        )
        code = parse_qs(urlparse(location).query)["code"][0]
        tokens = svc.exchange_token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": self.resource,
            }
        )
        self.assertIn("access_token", tokens)
        self.assertIn("refresh_token", tokens)

    def test_sliding_window_prunes_empty_buckets_and_caps_sources(self) -> None:
        window = _SlidingWindow(max_events=2, window_s=1.0, max_sources=4)
        now = time.time()
        self.assertTrue(window.allow("probe-only", now=now))
        self.assertNotIn("probe-only", window._events)  # noqa: SLF001
        for i in range(6):
            window.record(f"src-{i}", now=now)
        self.assertLessEqual(len(window._events), 4)  # noqa: SLF001
        # Advance past window so buckets expire and are swept on next record.
        later = now + 2.0
        window.record("fresh", now=later)
        for key, bucket in list(window._events.items()):  # noqa: SLF001
            self.assertTrue(bucket)
            self.assertGreaterEqual(bucket[-1], later - 0.1)


if __name__ == "__main__":
    unittest.main()
