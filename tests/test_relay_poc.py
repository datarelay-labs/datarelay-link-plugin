#!/usr/bin/env python3
"""Focused Packet 1 tests for plugin manifests and MCP relay PoC."""

from __future__ import annotations

import io
import json
import logging
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib import error, request

from jsonschema import Draft202012Validator

from relay.audit import configure_logging, redact_text, sanitize_headers
from relay.binding import MockBindingStore, UpstreamBinding
from relay.config import (
    DEFAULT_MOCK_PLUGIN_TOKEN,
    ConfigError,
    assert_connect_ip_allowed,
    load_config,
    validate_upstream_binding,
    validate_upstream_url,
)
from relay.proxy import UpstreamUnavailable, _pinned_connect_ip, proxy_mcp_request
from relay.server import create_server

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SCHEMA = json.loads((ROOT / "schemas" / "plugin.schema.json").read_text())
MCP_SCHEMA = json.loads((ROOT / "schemas" / "mcp.schema.json").read_text())


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class MockUpstream(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int]) -> None:
        super().__init__(server_address, MockUpstreamHandler)
        self.requests: list[dict[str, Any]] = []
        self.fail_closed = False
        self.tools = [
            {
                "name": "read_file",
                "description": "Read a file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                "annotations": {"readOnlyHint": True, "destructiveHint": False},
            },
            {
                "name": "write_file",
                "description": "Write a file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                },
                "annotations": {"readOnlyHint": False, "destructiveHint": True},
                "securitySchemes": [{"type": "oauth2", "scopes": ["host.write"]}],
            },
        ]


class MockUpstreamHandler(BaseHTTPRequestHandler):
    server: MockUpstream  # type: ignore[assignment]
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _read(self) -> bytes:
        n = int(self.headers.get("Content-Length") or "0")
        return self.rfile.read(n) if n else b""

    def _json(self, status: int, payload: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        raw = self._read()
        headers = {k: v for k, v in self.headers.items()}
        self.server.requests.append({"method": "POST", "path": self.path, "headers": headers, "body": raw})
        if self.server.fail_closed:
            self.send_response(503)
            self.end_headers()
            return
        payload = json.loads(raw.decode("utf-8"))
        method = payload.get("method")
        req_id = payload.get("id")
        if method == "initialize":
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mock-drlink", "version": "0.0.1"},
                    },
                },
                extra_headers={"Mcp-Session-Id": "sess-mock-1"},
            )
            return
        if method == "tools/list":
            self._json(
                200,
                {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.server.tools}},
            )
            return
        if method == "tools/call":
            result: dict[str, Any] = {
                "content": [{"type": "text", "text": "ok"}],
                "structuredContent": {"echo": payload.get("params")},
            }
            extra = getattr(self.server, "call_result_extra", None)
            if isinstance(extra, dict):
                result.update(extra)
            self._json(
                200,
                {"jsonrpc": "2.0", "id": req_id, "result": result},
            )
            return
        if method == "boom":
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": "upstream boom", "data": {"x": 1}},
                },
            )
            return
        self._json(
            200,
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"unknown method {method}"},
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(405)
        self.end_headers()


class RelayTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.upstream_port = _free_port()
        self.upstream = MockUpstream(("127.0.0.1", self.upstream_port))
        self.upstream_thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.upstream_thread.start()

        self.log_stream = io.StringIO()
        self.logger = configure_logging(logging.INFO)
        # Capture audit lines for secret assertions.
        handler = logging.StreamHandler(self.log_stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.handlers = [handler]

        env = {
            "DRLINK_RELAY_UPSTREAM_URL": f"http://127.0.0.1:{self.upstream_port}/mcp",
            "DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1",
            "DRLINK_RELAY_UPSTREAM_TOKEN": "upstream-secret-token",
            "DRLINK_RELAY_MOCK_PLUGIN_TOKEN": "dev-plugin-token",
            "DRLINK_RELAY_BIND": "127.0.0.1",
            "DRLINK_RELAY_PORT": str(_free_port()),
            "DRLINK_RELAY_TIMEOUT_S": "5",
        }
        self.config = load_config(env)
        self.server = create_server(self.config, self.logger)
        self.relay_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.relay_thread.start()
        self.relay_base = f"http://127.0.0.1:{self.config.bind_port}"
        self.auth = {"Authorization": "Bearer dev-plugin-token"}

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.upstream.shutdown()
        self.upstream.server_close()

    def _mcp(self, payload: dict[str, Any], headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], Any]:
        data = json.dumps(payload).encode("utf-8")
        req_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.auth,
        }
        if headers:
            req_headers.update(headers)
        req = request.Request(
            f"{self.relay_base}/mcp",
            data=data,
            headers=req_headers,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=5) as resp:
                body = resp.read()
                return resp.status, {k: v for k, v in resp.headers.items()}, json.loads(body.decode("utf-8"))
        except error.HTTPError as exc:
            body = exc.read()
            try:
                parsed = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                parsed = {"raw": body.decode("utf-8", errors="replace")}
            return exc.code, {k: v for k, v in exc.headers.items()}, parsed

    def test_manifest_schema_validation(self) -> None:
        plugin = json.loads((ROOT / "plugin.json").read_text())
        mcp = json.loads((ROOT / "mcp.json").read_text())
        Draft202012Validator(PLUGIN_SCHEMA).validate(plugin)
        Draft202012Validator(MCP_SCHEMA).validate(mcp)

    def test_initialize_passthrough(self) -> None:
        status, headers, body = self._mcp(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], 7)
        self.assertEqual(body["result"]["serverInfo"]["name"], "mock-drlink")
        self.assertEqual(headers.get("Mcp-Session-Id"), "sess-mock-1")

    def test_tools_list_passthrough_preserves_metadata(self) -> None:
        status, _, body = self._mcp({"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {}})
        self.assertEqual(status, 200)
        tools = body["result"]["tools"]
        self.assertEqual(len(tools), 2)
        self.assertEqual(tools[0]["annotations"]["readOnlyHint"], True)
        self.assertEqual(tools[1]["securitySchemes"][0]["scopes"], ["host.write"])

    def test_tools_metadata_passthrough_is_unmodified(self) -> None:
        read_tool = {
            "name": "read_file",
            "title": "Read file",
            "description": "Read an authorized host file",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            "outputSchema": {
                "type": "object",
                "properties": {"content": {"type": "string"}},
            },
            "annotations": {
                "readOnlyHint": True,
                "openWorldHint": False,
                "destructiveHint": False,
            },
            "securitySchemes": [{"type": "oauth2", "scopes": ["host.read"]}],
            "_meta": {"openai/toolInvocation/invoking": "Reading"},
        }
        write_tool = {
            "name": "write_file",
            "title": "Write file",
            "description": "Write an authorized host file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
            "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}},
            "annotations": {
                "readOnlyHint": False,
                "openWorldHint": False,
                "destructiveHint": True,
            },
            "securitySchemes": [{"type": "oauth2", "scopes": ["host.write"]}],
            "_meta": {"source": "upstream-drlink"},
        }
        self.upstream.tools = [read_tool, write_tool]
        status, _, body = self._mcp(
            {"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["tools"], [read_tool, write_tool])

        challenge = 'Bearer realm="upstream", error="invalid_token"'
        self.upstream.call_result_extra = {
            "_meta": {"mcp/www_authenticate": [challenge]},
            "isError": True,
        }
        status, _, called = self._mcp(
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(called["result"]["_meta"], {"mcp/www_authenticate": [challenge]})
        self.assertTrue(called["result"]["isError"])
        self.assertEqual(
            called["result"]["structuredContent"]["echo"]["name"],
            "read_file",
        )

    def test_tools_call_passthrough(self) -> None:
        status, _, body = self._mcp(
            {
                "jsonrpc": "2.0",
                "id": "call-1",
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}},
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], "call-1")
        self.assertEqual(body["result"]["structuredContent"]["echo"]["name"], "read_file")

    def test_jsonrpc_error_passthrough(self) -> None:
        status, _, body = self._mcp({"jsonrpc": "2.0", "id": 99, "method": "boom", "params": {}})
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], 99)
        self.assertEqual(body["error"]["code"], -32603)
        self.assertEqual(body["error"]["message"], "upstream boom")

    def test_upstream_unavailable_fail_closed(self) -> None:
        self.upstream.shutdown()
        self.upstream.server_close()
        status, _, body = self._mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(status, 502)
        self.assertIn("unavailable", body["error"]["message"])
        self.assertNotIn("result", body)

    def test_health_does_not_expose_secrets(self) -> None:
        with request.urlopen(f"{self.relay_base}/health", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        blob = json.dumps(payload)
        self.assertEqual(payload["status"], "ok")
        self.assertNotIn("upstream-secret-token", blob)
        self.assertNotIn("dev-plugin-token", blob)
        self.assertNotIn("DRLINK_RELAY_UPSTREAM", blob)
        self.assertNotIn(str(self.upstream_port), blob)

    def test_logs_do_not_contain_auth_tokens(self) -> None:
        self._mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        logs = self.log_stream.getvalue()
        self.assertNotIn("upstream-secret-token", logs)
        self.assertNotIn("dev-plugin-token", logs)
        self.assertNotIn("Bearer upstream", logs)
        self.assertIn("[REDACTED]", logs)

    def test_config_rejects_missing_upstream(self) -> None:
        with self.assertRaises(ConfigError):
            load_config({"DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1"})

    def test_config_rejects_http_non_loopback(self) -> None:
        with self.assertRaises(ConfigError):
            validate_upstream_url("http://example.com/mcp", allow_loopback=False)

    def test_config_rejects_embedded_credentials(self) -> None:
        with self.assertRaises(ConfigError):
            validate_upstream_url("https://user:pass@example.com/mcp", allow_loopback=False)

    def test_unbound_identity_denied(self) -> None:
        status, _, body = self._mcp(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Authorization": "Bearer wrong"},
        )
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "unauthorized")

    def test_upstream_receives_binding_token_not_plugin_token(self) -> None:
        self._mcp({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        self.assertTrue(self.upstream.requests)
        auth = self.upstream.requests[-1]["headers"].get("Authorization")
        self.assertEqual(auth, "Bearer upstream-secret-token")

    def test_binding_revoke(self) -> None:
        store = MockBindingStore(self.config)
        store.revoke("mock-binding-1")
        with self.assertRaises(Exception):
            store.resolve("Bearer dev-plugin-token")

    def test_redaction_helpers(self) -> None:
        self.assertIn("[REDACTED]", redact_text("Authorization: Bearer abc.def"))
        cleaned = sanitize_headers({"Authorization": "Bearer secret", "Mcp-Session-Id": "s1"})
        self.assertEqual(cleaned["Authorization"], "[REDACTED]")
        self.assertEqual(cleaned["Mcp-Session-Id"], "s1")

    def test_license_manifest_consistency(self) -> None:
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        plugin = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
        self.assertTrue(
            license_text.startswith("Data Relay Source Available License 1.0"),
            "LICENSE must be Data Relay Source Available License 1.0",
        )
        self.assertNotIn("Apache-2.0", plugin.get("license", ""))
        self.assertEqual(plugin.get("license"), "Data Relay Source Available License 1.0")
        self.assertTrue((ROOT / "LICENSING.md").is_file())

    def test_public_bind_rejects_default_mock_token(self) -> None:
        base = {
            "DRLINK_RELAY_UPSTREAM_URL": f"http://127.0.0.1:{self.upstream_port}/mcp",
            "DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1",
            "DRLINK_RELAY_BIND": "0.0.0.0",
            "DRLINK_RELAY_PORT": str(_free_port()),
        }
        with self.assertRaises(ConfigError) as ctx_missing_override:
            load_config({**base, "DRLINK_RELAY_MOCK_PLUGIN_TOKEN": DEFAULT_MOCK_PLUGIN_TOKEN})
        self.assertIn("oauth", str(ctx_missing_override.exception).lower())

        with self.assertRaises(ConfigError) as ctx_default_token:
            load_config(
                {
                    **base,
                    "DRLINK_RELAY_ALLOW_NON_LOOPBACK_BIND": "1",
                    "DRLINK_RELAY_MOCK_PLUGIN_TOKEN": DEFAULT_MOCK_PLUGIN_TOKEN,
                }
            )
        self.assertIn("default mock plugin token", str(ctx_default_token.exception))

        cfg = load_config(
            {
                **base,
                "DRLINK_RELAY_ALLOW_NON_LOOPBACK_BIND": "1",
                "DRLINK_RELAY_MOCK_PLUGIN_TOKEN": "explicit-strong-dev-token",
            }
        )
        self.assertEqual(cfg.mock_plugin_token, "explicit-strong-dev-token")
        self.assertEqual(cfg.bind_host, "0.0.0.0")
        self.assertEqual(cfg.auth_mode, "mock")

    def test_dns_rebinding_uses_pinned_connect_ip(self) -> None:
        # Bind-time resolution returns a public IP; later hostname rebinding must
        # not change the TCP destination used by the proxy.
        public_ip = "8.8.8.8"
        private_ip = "169.254.169.254"

        def fake_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (public_ip, 0)),
            ]

        with patch("relay.config.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            validated = validate_upstream_binding(
                "https://rebinding.example/mcp", allow_loopback=False
            )
        self.assertEqual(validated.connect_ips, (public_ip,))

        # Simulate post-validation DNS rebinding to a link-local/metadata address.
        def rebound_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (private_ip, 0)),
            ]

        with patch("socket.getaddrinfo", side_effect=rebound_getaddrinfo):
            binding = UpstreamBinding(
                binding_id="mock",
                upstream_url=validated.url,
                upstream_connect_ips=validated.connect_ips,
                allow_loopback_upstream=False,
                upstream_authorization=None,
                plugin_subject="t",
            )
            # Proxy must still select the bind-time public IP, not re-resolved private.
            self.assertEqual(_pinned_connect_ip(binding), public_ip)

            # Connect-time defense: a private pinned IP is rejected.
            bad = UpstreamBinding(
                binding_id="mock",
                upstream_url=validated.url,
                upstream_connect_ips=(private_ip,),
                allow_loopback_upstream=False,
                upstream_authorization=None,
                plugin_subject="t",
            )
            with self.assertRaises(UpstreamUnavailable):
                _pinned_connect_ip(bad)

        with self.assertRaises(ConfigError):
            assert_connect_ip_allowed(private_ip, allow_loopback=False)

        # End-to-end: pinned loopback IP still reaches the mock upstream even if
        # hostname resolution would drift afterward.
        logger = configure_logging(logging.INFO)
        binding = UpstreamBinding(
            binding_id="mock",
            upstream_url=f"http://upstream.example:{self.upstream_port}/mcp",
            upstream_connect_ips=("127.0.0.1",),
            allow_loopback_upstream=True,
            upstream_authorization="Bearer upstream-secret-token",
            plugin_subject="t",
        )
        with patch(
            "socket.getaddrinfo",
            side_effect=AssertionError("hostname must not be re-resolved for TCP connect"),
        ):
            proxied = proxy_mcp_request(
                method="POST",
                binding=binding,
                body=json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                ).encode("utf-8"),
                request_headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout_s=5,
                logger=logger,
            )
        self.assertEqual(proxied.status, 200)
        payload = json.loads(proxied.body.decode("utf-8"))
        self.assertEqual(len(payload["result"]["tools"]), 2)


if __name__ == "__main__":
    unittest.main()
