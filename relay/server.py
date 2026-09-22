"""HTTP server exposing /mcp (Streamable HTTP pass-through) and /health."""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from . import __version__
from .audit import audit_event, configure_logging
from .binding import BindingError, MockBindingStore
from .config import RelayConfig
from .proxy import UpstreamUnavailable, proxy_mcp_request


class RelayHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        config: RelayConfig,
        bindings: MockBindingStore,
        logger: logging.Logger,
    ) -> None:
        super().__init__(server_address, RelayRequestHandler)
        self.relay_config = config
        self.bindings = bindings
        self.audit_logger = logger


class RelayRequestHandler(BaseHTTPRequestHandler):
    server: RelayHTTPServer  # type: ignore[assignment]
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Suppress default access log (may include query strings); use audit events.
        return

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or "0")
        if length < 0 or length > 16 * 1024 * 1024:
            raise ValueError("invalid Content-Length")
        if length == 0:
            return b""
        return self.rfile.read(length)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(
        self, status: int, body: bytes, headers: list[tuple[str, str]] | None = None
    ) -> None:
        self.send_response(status)
        for name, value in headers or []:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            self._handle_health()
            return
        if path == "/mcp":
            self._handle_mcp("GET")
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/mcp":
            self._handle_mcp("POST")
            return
        self._send_json(404, {"error": "not_found"})

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/mcp":
            self._handle_mcp("DELETE")
            return
        self._send_json(404, {"error": "not_found"})

    def _handle_health(self) -> None:
        # Never expose upstream URL, tokens, or binding secrets.
        self._send_json(
            200,
            {
                "status": "ok",
                "service": "datarelay-link-relay",
                "version": __version__,
                "mcp_path": "/mcp",
            },
        )

    def _handle_mcp(self, method: str) -> None:
        config = self.server.relay_config
        logger = self.server.audit_logger
        try:
            body = self._read_body()
        except ValueError:
            self._send_json(400, {"error": "invalid_body"})
            return

        try:
            binding = self.server.bindings.resolve(self.headers.get("Authorization"))
        except BindingError as exc:
            audit_event(
                logger,
                "mcp_binding_denied",
                reason=str(exc),
                method=method,
            )
            self._send_json(401, {"error": "unauthorized", "message": str(exc)})
            return

        request_headers = {k: v for k, v in self.headers.items()}
        try:
            proxied = proxy_mcp_request(
                method=method,
                binding=binding,
                body=body,
                request_headers=request_headers,
                timeout_s=config.request_timeout_s,
                logger=logger,
            )
        except UpstreamUnavailable:
            # Fail closed: do not fabricate MCP tools or success payloads.
            self._send_json(
                502,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32000,
                        "message": "upstream MCP endpoint unavailable",
                    },
                },
            )
            return

        self._send_bytes(proxied.status, proxied.body, proxied.headers)


def create_server(config: RelayConfig, logger: logging.Logger | None = None) -> RelayHTTPServer:
    log = logger or configure_logging()
    bindings = MockBindingStore(config)
    return RelayHTTPServer(
        (config.bind_host, config.bind_port),
        config,
        bindings,
        log,
    )


def serve_forever(config: RelayConfig) -> None:
    logger = configure_logging()
    server = create_server(config, logger)
    audit_event(
        logger,
        "relay_listen",
        bind_host=config.bind_host,
        bind_port=config.bind_port,
        allow_loopback_upstream=config.allow_loopback_upstream,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
