#!/usr/bin/env python3
"""Deterministic Packet 2 tests for single-user OAuth 2.1 relay auth."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import secrets
import threading
import time
import unittest
from typing import Any
from urllib import error, parse, request

from relay.audit import configure_logging
from relay.config import ConfigError, load_config
from relay.oauth import DEFAULT_SCOPE, OAuthService
from relay.server import create_server

from tests.test_relay_poc import MockUpstream, _free_port


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class OAuthRelayTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.upstream_port = _free_port()
        self.upstream = MockUpstream(("127.0.0.1", self.upstream_port))
        self.upstream_thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.upstream_thread.start()

        self.log_stream = io.StringIO()
        self.logger = configure_logging(logging.INFO)
        handler = logging.StreamHandler(self.log_stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.handlers = [handler]

        self.owner_secret = "owner-approval-secret-32chars!!"
        self.relay_port = _free_port()
        self.public_base = f"http://127.0.0.1:{self.relay_port}"
        self.resource = f"{self.public_base}/mcp"
        env = {
            "DRLINK_RELAY_UPSTREAM_URL": f"http://127.0.0.1:{self.upstream_port}/mcp",
            "DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1",
            "DRLINK_RELAY_UPSTREAM_TOKEN": "upstream-secret-token",
            "DRLINK_RELAY_BIND": "127.0.0.1",
            "DRLINK_RELAY_PORT": str(self.relay_port),
            "DRLINK_RELAY_TIMEOUT_S": "5",
            "DRLINK_RELAY_AUTH_MODE": "oauth",
            "DRLINK_RELAY_PUBLIC_BASE_URL": self.public_base,
            "DRLINK_RELAY_OWNER_APPROVAL_SECRET": self.owner_secret,
            "DRLINK_RELAY_OAUTH_ALLOW_EPHEMERAL": "1",
            # Intentionally set mock token; oauth mode must ignore it.
            "DRLINK_RELAY_MOCK_PLUGIN_TOKEN": "dev-plugin-token",
        }
        self.config = load_config(env)
        self.server = create_server(self.config, self.logger)
        self.relay_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.relay_thread.start()
        self.base = self.public_base

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.upstream.shutdown()
        self.upstream.server_close()

    def _json(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        form: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        data: bytes | None = None
        req_headers = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif form is not None:
            data = parse.urlencode(form).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = request.Request(
            f"{self.base}{path}",
            data=data,
            headers=req_headers,
            method=method,
        )
        try:
            with request.urlopen(req, timeout=5) as resp:
                raw = resp.read()
                payload: Any
                if not raw:
                    payload = None
                else:
                    ctype = resp.headers.get("Content-Type", "")
                    if "application/json" in ctype:
                        payload = json.loads(raw.decode("utf-8"))
                    else:
                        payload = raw.decode("utf-8", errors="replace")
                return resp.status, {k: v for k, v in resp.headers.items()}, payload
        except error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else None
            except json.JSONDecodeError:
                payload = raw.decode("utf-8", errors="replace")
            return exc.code, {k: v for k, v in exc.headers.items()}, payload

    def _register(self, redirect_uri: str = "https://chatgpt.com/connector/oauth/__test__") -> str:
        status, _, body = self._json(
            "POST",
            "/oauth/register",
            body={
                "redirect_uris": [redirect_uri],
                "client_name": "chatgpt-test",
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        self.assertEqual(status, 201)
        assert isinstance(body, dict)
        return str(body["client_id"])

    def _authorize_and_token(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        verifier: str,
        challenge: str,
        resource: str | None = None,
        scope: str = DEFAULT_SCOPE,
        owner_secret: str | None = None,
        method: str = "S256",
    ) -> dict[str, Any]:
        resource = resource if resource is not None else self.resource
        qs = parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "code_challenge_method": method,
                "resource": resource,
                "scope": scope,
                "state": "state-1",
            }
        )
        status, _, html = self._json("GET", f"/oauth/authorize?{qs}")
        self.assertEqual(status, 200)
        self.assertIn("Owner approval secret", str(html))

        oauth: OAuthService = self.server.bindings.oauth  # type: ignore[assignment]
        self.assertTrue(oauth.pending)
        request_id = next(iter(oauth.pending))

        # Follow redirect manually (urllib would need opener).
        class _NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
                return None

        opener = request.build_opener(_NoRedirect)
        data = parse.urlencode(
            {
                "request_id": request_id,
                "owner_secret": owner_secret if owner_secret is not None else self.owner_secret,
                "decision": "approve",
            }
        ).encode("utf-8")
        req = request.Request(
            f"{self.base}/oauth/authorize",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            opener.open(req, timeout=5)
            self.fail("expected redirect")
        except error.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            location = exc.headers.get("Location") or ""
        parsed = parse.urlparse(location)
        params = parse.parse_qs(parsed.query)
        self.assertIn("code", params)
        self.assertEqual(params.get("iss", [None])[0], self.public_base)
        code = params["code"][0]

        status, _, token = self._json(
            "POST",
            "/oauth/token",
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": resource,
            },
        )
        self.assertEqual(status, 200)
        assert isinstance(token, dict)
        return token

    def test_protected_resource_metadata(self) -> None:
        status, _, body = self._json("GET", "/.well-known/oauth-protected-resource")
        self.assertEqual(status, 200)
        assert isinstance(body, dict)
        self.assertEqual(body["resource"], self.resource)
        self.assertEqual(body["authorization_servers"], [self.public_base])
        self.assertIn(DEFAULT_SCOPE, body["scopes_supported"])

    def test_authorization_server_metadata(self) -> None:
        status, _, body = self._json("GET", "/.well-known/oauth-authorization-server")
        self.assertEqual(status, 200)
        assert isinstance(body, dict)
        self.assertEqual(body["issuer"], self.public_base)
        self.assertEqual(body["code_challenge_methods_supported"], ["S256"])
        self.assertIn("registration_endpoint", body)
        self.assertIn("revocation_endpoint", body)
        self.assertEqual(body["token_endpoint_auth_methods_supported"], ["none"])
        self.assertFalse(body.get("client_id_metadata_document_supported"))

    def test_dcr_registration(self) -> None:
        client_id = self._register()
        self.assertTrue(client_id.startswith("client_"))

    def test_authorization_code_pkce_s256_success(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        self.assertIn("access_token", token)
        self.assertIn("refresh_token", token)
        self.assertEqual(token["resource"], self.resource)

    def test_pkce_plain_rejected(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, _ = _pkce_pair()
        qs = parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect,
                "code_challenge": verifier,
                "code_challenge_method": "plain",
                "resource": self.resource,
                "state": "s",
            }
        )
        class _NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
                return None

        opener = request.build_opener(_NoRedirect)
        try:
            opener.open(f"{self.base}/oauth/authorize?{qs}", timeout=5)
            self.fail("expected redirect")
        except error.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            loc = exc.headers.get("Location") or ""
        self.assertIn("error=", loc)
        self.assertIn("invalid_request", loc)

    def test_redirect_uri_mismatch_rejected(self) -> None:
        client_id = self._register("https://chatgpt.com/connector/oauth/a")
        verifier, challenge = _pkce_pair()
        qs = parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://evil.example/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": self.resource,
            }
        )
        status, _, body = self._json("GET", f"/oauth/authorize?{qs}")
        self.assertEqual(status, 400)
        assert isinstance(body, dict)
        self.assertEqual(body["error"], "invalid_request")

    def test_code_replay_rejected(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        # Mint a fresh code then replay manually.
        verifier2, challenge2 = _pkce_pair()
        token2 = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier2,
            challenge=challenge2,
        )
        self.assertNotEqual(token["access_token"], token2["access_token"])

        # Force replay by exchanging an already-consumed code path via service.
        oauth: OAuthService = self.server.bindings.oauth  # type: ignore[assignment]
        # Create code directly then exchange twice.
        from relay.oauth import AuthCode

        code = "code_replay_test"
        oauth.codes[code] = AuthCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect,
            code_challenge=challenge2,
            code_challenge_method="S256",
            resource=self.resource,
            scopes=frozenset({DEFAULT_SCOPE}),
            expires_at=time.time() + 60,
        )
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect,
            "client_id": client_id,
            "code_verifier": verifier2,
            "resource": self.resource,
        }
        status, _, _ = self._json("POST", "/oauth/token", form=form)
        self.assertEqual(status, 200)
        status2, _, body2 = self._json("POST", "/oauth/token", form=form)
        self.assertEqual(status2, 400)
        assert isinstance(body2, dict)
        self.assertEqual(body2["error"], "invalid_grant")

    def test_code_expiry_rejected(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        from relay.oauth import AuthCode

        oauth: OAuthService = self.server.bindings.oauth  # type: ignore[assignment]
        code = "code_expired"
        oauth.codes[code] = AuthCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect,
            code_challenge=challenge,
            code_challenge_method="S256",
            resource=self.resource,
            scopes=frozenset({DEFAULT_SCOPE}),
            expires_at=time.time() - 1,
        )
        status, _, body = self._json(
            "POST",
            "/oauth/token",
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": self.resource,
            },
        )
        self.assertEqual(status, 400)
        assert isinstance(body, dict)
        self.assertEqual(body["error"], "invalid_grant")

    def test_wrong_resource_rejected(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        qs = parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": "https://evil.example/mcp",
                "state": "s",
            }
        )
        class _NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
                return None

        opener = request.build_opener(_NoRedirect)
        try:
            opener.open(f"{self.base}/oauth/authorize?{qs}", timeout=5)
            self.fail("expected redirect")
        except error.HTTPError as exc:
            self.assertEqual(exc.code, 302)
            self.assertIn("invalid_target", exc.headers.get("Location") or "")

    def test_wrong_scope_rejected_on_token_use(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        oauth: OAuthService = self.server.bindings.oauth  # type: ignore[assignment]
        at = oauth.access_tokens[token["access_token"]]
        at.scopes = frozenset()
        status, headers, body = self._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={
                "Authorization": f"Bearer {token['access_token']}",
                "Accept": "application/json",
            },
        )
        self.assertEqual(status, 403)
        www = headers.get("WWW-Authenticate", "")
        self.assertIn("resource_metadata=", www)
        self.assertIn('error="insufficient_scope"', www)
        self.assertIn("error_description=", www)
        assert isinstance(body, dict)
        self.assertEqual(body.get("jsonrpc"), "2.0")
        result = body["result"]
        meta = result["_meta"]["mcp/www_authenticate"]
        self.assertEqual(meta, [www])
        self.assertIn('error="insufficient_scope"', meta[0])
        self.assertIn("error_description=", meta[0])

    def test_expired_access_token_rejected(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        oauth: OAuthService = self.server.bindings.oauth  # type: ignore[assignment]
        oauth.access_tokens[token["access_token"]].expires_at = time.time() - 1
        status, headers, _ = self._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        self.assertEqual(status, 401)
        self.assertIn("resource_metadata=", headers.get("WWW-Authenticate", ""))

    def test_revoked_access_token_rejected(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        status, _, _ = self._json(
            "POST",
            "/oauth/revoke",
            form={"token": token["access_token"], "token_type_hint": "access_token"},
        )
        self.assertEqual(status, 200)
        status2, _, _ = self._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Authorization": f"Bearer {token['access_token']}"},
        )
        self.assertEqual(status2, 401)

    def test_refresh_token_rotation(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        status, _, refreshed = self._json(
            "POST",
            "/oauth/token",
            form={
                "grant_type": "refresh_token",
                "refresh_token": token["refresh_token"],
                "client_id": client_id,
                "resource": self.resource,
            },
        )
        self.assertEqual(status, 200)
        assert isinstance(refreshed, dict)
        self.assertNotEqual(refreshed["refresh_token"], token["refresh_token"])
        # Old refresh token must fail.
        status2, _, body2 = self._json(
            "POST",
            "/oauth/token",
            form={
                "grant_type": "refresh_token",
                "refresh_token": token["refresh_token"],
                "client_id": client_id,
                "resource": self.resource,
            },
        )
        self.assertEqual(status2, 400)
        assert isinstance(body2, dict)
        self.assertEqual(body2["error"], "invalid_grant")

    def test_unauthenticated_mcp_oauth_challenge(self) -> None:
        status, headers, body = self._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        self.assertEqual(status, 401)
        www = headers.get("WWW-Authenticate", "")
        self.assertIn("resource_metadata=", www)
        self.assertIn("/.well-known/oauth-protected-resource", www)
        self.assertIn(f'scope="{DEFAULT_SCOPE}"', www)
        self.assertIn('error="invalid_token"', www)
        self.assertIn("error_description=", www)
        assert isinstance(body, dict)
        self.assertEqual(body["jsonrpc"], "2.0")
        self.assertEqual(body["id"], 1)
        result = body["result"]
        self.assertTrue(result.get("isError"))
        meta = result["_meta"]["mcp/www_authenticate"]
        self.assertEqual(meta, [www])
        self.assertIn('error="invalid_token"', meta[0])
        self.assertIn("error_description=", meta[0])
        # Challenge must not leak token material.
        self.assertNotIn("Bearer upstream-secret", www)
        self.assertNotIn(self.owner_secret, www)

    def test_dcr_redirect_uri_scheme_hardening(self) -> None:
        cases = [
            ("https://chatgpt.com/connector/oauth/ok", True),
            ("http://127.0.0.1:8787/callback", True),
            ("http://localhost/callback", True),
            ("http://[::1]/callback", True),
            ("javascript:alert(1)", False),
            ("data:text/html,hi", False),
            ("com.example.app:/oauth", False),
            ("chatgpt://oauth/callback", False),
            ("http://evil.example/callback", False),
            ("https://chatgpt.com/cb#frag", False),
            ("not-a-url", False),
            ("", False),
        ]
        for uri, ok in cases:
            with self.subTest(uri=uri, ok=ok):
                status, _, body = self._json(
                    "POST",
                    "/oauth/register",
                    body={
                        "redirect_uris": [uri],
                        "client_name": "scheme-test",
                        "token_endpoint_auth_method": "none",
                    },
                )
                if ok:
                    self.assertEqual(status, 201, body)
                else:
                    self.assertEqual(status, 400, body)
                    assert isinstance(body, dict)
                    self.assertEqual(body["error"], "invalid_redirect_uri")

    def test_dcr_redirect_uri_exact_match_still_enforced(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/exact"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        status, _, body = self._json(
            "GET",
            "/oauth/authorize?"
            + parse.urlencode(
                {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect + "-mismatch",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "resource": self.resource,
                }
            ),
        )
        self.assertEqual(status, 400)
        assert isinstance(body, dict)
        self.assertEqual(body["error"], "invalid_request")

    def test_valid_oauth_token_proxies_mcp(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        status, _, body = self._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}},
            headers={
                "Authorization": f"Bearer {token['access_token']}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(status, 200)
        assert isinstance(body, dict)
        self.assertEqual(len(body["result"]["tools"]), 2)

    def test_inbound_oauth_token_not_sent_upstream(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        self._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={
                "Authorization": f"Bearer {token['access_token']}",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
                "Mcp-Name": "tools/list",
            },
        )
        self.assertTrue(self.upstream.requests)
        upstream_headers = self.upstream.requests[-1]["headers"]
        upstream_auth = upstream_headers.get("Authorization")
        self.assertEqual(upstream_auth, "Bearer upstream-secret-token")
        self.assertNotEqual(upstream_auth, f"Bearer {token['access_token']}")
        # DRLink MCP Bridge requires these envelope headers; relay must forward them.
        header_map = {k.lower(): v for k, v in upstream_headers.items()}
        self.assertEqual(header_map.get("mcp-method"), "tools/list")
        self.assertEqual(header_map.get("mcp-name"), "tools/list")
        self.assertEqual(header_map.get("mcp-protocol-version"), "2026-07-28")
        # Client Plugin bearer must never appear on the upstream request.
        self.assertFalse(
            any(
                v == f"Bearer {token['access_token']}"
                for _, v in upstream_headers.items()
            )
        )

    def test_owner_approval_cannot_be_bypassed(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        qs = parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": self.resource,
            }
        )
        status, _, _ = self._json("GET", f"/oauth/authorize?{qs}")
        self.assertEqual(status, 200)
        oauth: OAuthService = self.server.bindings.oauth  # type: ignore[assignment]
        request_id = next(iter(oauth.pending))
        status2, _, html = self._json(
            "POST",
            "/oauth/authorize",
            form={
                "request_id": request_id,
                "owner_secret": "wrong-secret-not-valid!!!",
                "decision": "approve",
            },
        )
        self.assertEqual(status2, 401)
        self.assertIn("authorization denied", str(html).lower())
        self.assertNotIn("invalid owner approval secret", str(html).lower())
        # Pending request still present; no code issued.
        self.assertIn(request_id, oauth.pending)
        self.assertFalse(oauth.codes)

    def test_oauth_secrets_not_in_audit_or_health(self) -> None:
        redirect = "https://chatgpt.com/connector/oauth/__test__"
        client_id = self._register(redirect)
        verifier, challenge = _pkce_pair()
        token = self._authorize_and_token(
            client_id=client_id,
            redirect_uri=redirect,
            verifier=verifier,
            challenge=challenge,
        )
        with request.urlopen(f"{self.base}/health", timeout=5) as resp:
            health = resp.read().decode("utf-8")
        logs = self.log_stream.getvalue()
        blob = health + logs
        self.assertNotIn(self.owner_secret, blob)
        self.assertNotIn(token["access_token"], blob)
        self.assertNotIn(token["refresh_token"], blob)
        self.assertNotIn("upstream-secret-token", blob)
        self.assertNotIn(verifier, blob)

    def test_mock_token_rejected_in_oauth_mode(self) -> None:
        status, _, _ = self._json(
            "POST",
            "/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Authorization": "Bearer dev-plugin-token"},
        )
        self.assertEqual(status, 401)

    def test_oauth_config_requires_owner_secret(self) -> None:
        with self.assertRaises(ConfigError):
            load_config(
                {
                    "DRLINK_RELAY_UPSTREAM_URL": f"http://127.0.0.1:{self.upstream_port}/mcp",
                    "DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1",
                    "DRLINK_RELAY_AUTH_MODE": "oauth",
                    "DRLINK_RELAY_PUBLIC_BASE_URL": "http://127.0.0.1:9",
                    "DRLINK_RELAY_BIND": "127.0.0.1",
                    "DRLINK_RELAY_PORT": "9",
                }
            )

    def test_oauth_mode_on_public_bind_without_mock_override(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            state_path = str(Path(tmp) / "oauth-state.json")
            cfg = load_config(
                {
                    "DRLINK_RELAY_UPSTREAM_URL": f"http://127.0.0.1:{self.upstream_port}/mcp",
                    "DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1",
                    "DRLINK_RELAY_AUTH_MODE": "oauth",
                    "DRLINK_RELAY_PUBLIC_BASE_URL": "https://relay.example",
                    "DRLINK_RELAY_OWNER_APPROVAL_SECRET": "owner-approval-secret-32chars!!",
                    "DRLINK_RELAY_OAUTH_STATE_PATH": state_path,
                    "DRLINK_RELAY_BIND": "0.0.0.0",
                    "DRLINK_RELAY_PORT": str(_free_port()),
                }
            )
            self.assertEqual(cfg.auth_mode, "oauth")
            self.assertEqual(cfg.resource_url, "https://relay.example/mcp")
            self.assertEqual(cfg.oauth_state_path, state_path)

    def test_public_oauth_requires_durable_state_path(self) -> None:
        with self.assertRaises(ConfigError):
            load_config(
                {
                    "DRLINK_RELAY_UPSTREAM_URL": f"http://127.0.0.1:{self.upstream_port}/mcp",
                    "DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1",
                    "DRLINK_RELAY_AUTH_MODE": "oauth",
                    "DRLINK_RELAY_PUBLIC_BASE_URL": "https://relay.example",
                    "DRLINK_RELAY_OWNER_APPROVAL_SECRET": "owner-approval-secret-32chars!!",
                    "DRLINK_RELAY_BIND": "0.0.0.0",
                    "DRLINK_RELAY_PORT": "9",
                }
            )

    def test_loopback_oauth_requires_ephemeral_or_state(self) -> None:
        with self.assertRaises(ConfigError):
            load_config(
                {
                    "DRLINK_RELAY_UPSTREAM_URL": f"http://127.0.0.1:{self.upstream_port}/mcp",
                    "DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1",
                    "DRLINK_RELAY_AUTH_MODE": "oauth",
                    "DRLINK_RELAY_PUBLIC_BASE_URL": "http://127.0.0.1:9",
                    "DRLINK_RELAY_OWNER_APPROVAL_SECRET": "owner-approval-secret-32chars!!",
                    "DRLINK_RELAY_BIND": "127.0.0.1",
                    "DRLINK_RELAY_PORT": "9",
                }
            )


if __name__ == "__main__":
    unittest.main()
