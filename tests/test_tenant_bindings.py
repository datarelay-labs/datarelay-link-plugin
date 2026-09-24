"""Multi-tenant DRLink server binding regressions."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from relay.binding import BindingError
from relay.oauth_state import STATE_VERSION, DurableOAuthStore
from relay.server import create_server
from relay.tenant_bindings import TenantBindingRegistry
from tests.test_oauth_poc import OAuthRelayTestCase
from tests.test_relay_poc import MockUpstream, _free_port


class TenantBindingRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.state_path = str(Path(self._tmpdir.name) / "oauth-state.json")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _registry(self, path: str | None = None) -> TenantBindingRegistry:
        store = DurableOAuthStore(path) if path else None
        return TenantBindingRegistry(
            allow_loopback=True,
            public_base_url="http://127.0.0.1:8741",
            store=store,
        )

    def test_v1_state_migrates_to_v2_without_dropping_oauth_records(self) -> None:
        path = Path(self.state_path)
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "clients": {"client_1": {"client_id": "client_1"}},
                    "refresh_tokens": {},
                }
            ),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        loaded = DurableOAuthStore(path).load()
        self.assertEqual(loaded["version"], STATE_VERSION)
        self.assertEqual(loaded["clients"]["client_1"]["client_id"], "client_1")
        self.assertEqual(loaded["server_bindings"], {})
        # Migration is in memory until the next save.
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["version"], 1)
        DurableOAuthStore(path).save(loaded)
        rewritten = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(rewritten["version"], STATE_VERSION)
        self.assertIn("server_bindings", rewritten)
        self.assertNotIn("upstream_token", rewritten)
        self.assertNotIn("owner_approval_secret", rewritten)

    def test_subjects_are_isolated_and_survive_restart(self) -> None:
        registry = self._registry(self.state_path)
        first = registry.connect(
            subject="tn_a",
            upstream_url="http://127.0.0.1:9001/mcp",
            upstream_token="bearer-a",
        )
        second = registry.connect(
            subject="tn_b",
            upstream_url="http://127.0.0.1:9002/mcp",
            upstream_token="bearer-b",
        )
        bound_a = registry.resolve(subject="tn_a", binding_id=None)
        bound_b = registry.resolve(subject="tn_b", binding_id=None)
        self.assertEqual(bound_a.upstream_url, "http://127.0.0.1:9001/mcp")
        self.assertEqual(bound_b.upstream_authorization, "Bearer bearer-b")
        self.assertNotEqual(bound_a.binding_id, "oauth-binding-1")
        with self.assertRaises(BindingError):
            registry.resolve(subject="tn_a", binding_id=second["binding_id"])
        with self.assertRaises(BindingError):
            registry.disconnect(subject="tn_a", binding_id=second["binding_id"])

        restarted = self._registry(self.state_path)
        again = restarted.resolve(subject="tn_a", binding_id=None)
        self.assertEqual(again.binding_id, first["binding_id"])
        self.assertEqual(again.plugin_subject, "tn_a")
        self.assertEqual(again.tenant_id, "tn_a")
        self.assertEqual(again.upstream_authorization, "Bearer bearer-a")

        backup = str(Path(self._tmpdir.name) / "backup.json")
        shutil.copy2(self.state_path, backup)
        os.chmod(backup, 0o600)
        restored = self._registry(backup)
        self.assertEqual(
            restored.resolve(subject="tn_b", binding_id=None).binding_id,
            second["binding_id"],
        )

        registry.disconnect(subject="tn_a", binding_id=first["binding_id"])
        with self.assertRaises(BindingError) as ctx:
            registry.resolve(subject="tn_a", binding_id=None)
        self.assertEqual(ctx.exception.status, 403)
        denied = self._registry(self.state_path)
        with self.assertRaises(BindingError):
            denied.resolve(subject="tn_a", binding_id=first["binding_id"])
        # The other subject remains connected.
        self.assertEqual(
            denied.resolve(subject="tn_b", binding_id=None).binding_id,
            second["binding_id"],
        )

        raw = Path(self.state_path).read_text(encoding="utf-8")
        self.assertNotIn("owner_approval_secret", raw)
        self.assertEqual(Path(self.state_path).stat().st_mode & 0o777, 0o600)
        public = json.dumps(registry.list_bindings("tn_a"))
        self.assertNotIn("bearer-a", public)
        self.assertNotIn("upstream_bearer", public)

    def test_active_binding_is_explicit(self) -> None:
        registry = self._registry(None)
        first = registry.connect(
            subject="tn_a",
            upstream_url="http://127.0.0.1:9001/mcp",
            upstream_token=None,
        )
        second = registry.connect(
            subject="tn_a",
            upstream_url="http://127.0.0.1:9002/mcp",
            upstream_token=None,
        )
        self.assertTrue(first["active"])
        self.assertFalse(second["active"])
        self.assertEqual(
            registry.resolve(subject="tn_a", binding_id=None).binding_id,
            first["binding_id"],
        )
        registry.activate(subject="tn_a", binding_id=second["binding_id"])
        self.assertEqual(
            registry.resolve(subject="tn_a", binding_id=None).binding_id,
            second["binding_id"],
        )
        self.assertEqual(
            registry.resolve(subject="tn_a", binding_id=first["binding_id"]).binding_id,
            first["binding_id"],
        )
        registry.disconnect(subject="tn_a", binding_id=second["binding_id"])
        with self.assertRaises(BindingError):
            registry.resolve(subject="tn_a", binding_id=None)
        self.assertEqual(
            registry.resolve(subject="tn_a", binding_id=first["binding_id"]).binding_id,
            first["binding_id"],
        )

    def test_connect_rejects_ssrf_and_relay_loop(self) -> None:
        registry = TenantBindingRegistry(
            allow_loopback=False,
            public_base_url="https://mcp.datarelay.run",
            store=None,
        )
        for url in (
            "https://169.254.169.254/mcp",
            "https://10.0.0.8/mcp",
            "http://example.com/mcp",
            "http://127.0.0.1:9/mcp",
            "https://mcp.datarelay.run/mcp",
            "https://user:pass@example.com/mcp",
        ):
            with self.assertRaises(BindingError):
                registry.connect(subject="tn_a", upstream_url=url, upstream_token="x")


class _RelayFixture:
    """Runs the OAuth relay harness without inheriting its test methods."""

    def __init__(self, *, state_path: str | None = None) -> None:
        self.case = OAuthRelayTestCase("test_protected_resource_metadata")
        if state_path is not None:
            self.case.state_path = state_path  # type: ignore[attr-defined]
        self.case.setUp()

    def close(self) -> None:
        self.case.tearDown()

    def __getattr__(self, name: str):
        return getattr(self.case, name)


class TenantBindingHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = _RelayFixture()

    def tearDown(self) -> None:
        self.fx.close()

    def test_unconnected_subject_is_not_an_open_proxy(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self.fx._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self.fx._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        status, _, body = self.fx._json(
            "POST",
            "/mcp",
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {"upstream_url": "https://evil.example/mcp"},
            },
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        self.assertEqual(status, 403)
        self.assertIn("no connected DRLink server", json.dumps(body))
        self.assertEqual(self.fx.upstream.requests, [])

    def test_cross_tenant_selector_and_disconnect_denied(self) -> None:
        other_port = _free_port()
        other = MockUpstream(("127.0.0.1", other_port))
        thread = threading.Thread(target=other.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(other.shutdown)
        self.addCleanup(other.server_close)

        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self.fx._register(redirect)
        verifier_a, challenge_a = _pkce_pair()
        verifier_b, challenge_b = _pkce_pair()
        token_a = self.fx._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier_a,
            challenge=challenge_a,
        )
        token_b = self.fx._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier_b,
            challenge=challenge_b,
        )
        self.assertNotEqual(token_a["access_token"], token_b["access_token"])
        bound_a = self.fx._connect_upstream(token_a["access_token"])
        status, _, bound_b = self.fx._json(
            "POST",
            "/bindings",
            body={
                "upstream_url": f"http://127.0.0.1:{other_port}/mcp",
                "upstream_token": "bearer-b",
            },
            headers={"Authorization": f"Bearer {token_b['access_token']}"},
        )
        self.assertEqual(status, 201, bound_b)
        assert isinstance(bound_b, dict)
        self.assertNotIn("bearer-b", json.dumps(bound_b))

        status, _, _ = self.fx._json(
            "POST",
            f"/bindings/{bound_b['binding_id']}/disconnect",
            headers={"Authorization": f"Bearer {token_a['access_token']}"},
        )
        self.assertEqual(status, 403)

        before = len(other.requests)
        status, _, _ = self.fx._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}},
            headers={
                "Authorization": f"Bearer {token_a['access_token']}",
                "X-DRLink-Server-Binding": bound_b["binding_id"],
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(len(other.requests), before)

        status, _, body = self.fx._json(
            "POST",
            "/mcp",
            body={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/list",
                "params": {"url": "https://evil.example/mcp"},
            },
            headers={"Authorization": f"Bearer {token_a['access_token']}"},
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(self.fx.upstream.requests)
        self.assertEqual(
            self.fx.upstream.requests[-1]["headers"].get("Authorization"),
            "Bearer upstream-secret-token",
        )
        self.assertNotEqual(
            self.fx.upstream.requests[-1]["headers"].get("Authorization"),
            f"Bearer {token_a['access_token']}",
        )
        self.assertEqual(other.requests, [])

        logs = self.fx.log_stream.getvalue()
        self.assertIn(bound_a["binding_id"], logs)
        self.assertIn("plugin_subject", logs)
        self.assertNotIn("upstream-secret-token", logs)
        self.assertNotIn("bearer-b", logs)
        self.assertNotIn(token_a["access_token"], logs)


class DurableTenantHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        state_path = str(Path(self._tmpdir.name) / "oauth-state.json")
        self.fx = _RelayFixture(state_path=state_path)

    def tearDown(self) -> None:
        self.fx.close()
        self._tmpdir.cleanup()

    def _restart(self) -> None:
        case = self.fx.case
        case.server.shutdown()
        case.server.server_close()
        case.server = create_server(case.config, case.logger)
        case.relay_thread = threading.Thread(target=case.server.serve_forever, daemon=True)
        case.relay_thread.start()

    def test_binding_survives_process_restart_until_disconnect(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self.fx._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self.fx._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        bound = self.fx._connect_upstream(token["access_token"])
        self._restart()
        status, _, refreshed = self.fx._json(
            "POST",
            "/oauth/token",
            form={
                "grant_type": "refresh_token",
                "refresh_token": token["refresh_token"],
                "client_id": client_id,
                "resource": self.fx.resource,
            },
        )
        self.assertEqual(status, 200, refreshed)
        assert isinstance(refreshed, dict)
        status, _, body = self.fx._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Authorization": f"Bearer {refreshed['access_token']}"},
        )
        self.assertEqual(status, 200, body)
        status, _, _ = self.fx._json(
            "POST",
            f"/bindings/{bound['binding_id']}/disconnect",
            headers={"Authorization": f"Bearer {refreshed['access_token']}"},
        )
        self.assertEqual(status, 200)
        self._restart()
        status, _, refreshed_again = self.fx._json(
            "POST",
            "/oauth/token",
            form={
                "grant_type": "refresh_token",
                "refresh_token": refreshed["refresh_token"],
                "client_id": client_id,
                "resource": self.fx.resource,
            },
        )
        self.assertEqual(status, 200, refreshed_again)
        assert isinstance(refreshed_again, dict)
        status, _, _ = self.fx._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers={"Authorization": f"Bearer {refreshed_again['access_token']}"},
        )
        self.assertEqual(status, 403)


def _pkce_pair():
    from tests.test_oauth_poc import _pkce_pair as _pair

    return _pair()


if __name__ == "__main__":
    unittest.main()
