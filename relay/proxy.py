"""HTTP pass-through to a single configured upstream MCP endpoint."""

from __future__ import annotations

import http.client
import ipaddress
import logging
import socket
import ssl
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from .audit import audit_event
from .binding import UpstreamBinding
from .config import ConfigError, assert_connect_ip_allowed

# Headers forwarded from client → upstream (case-insensitive match).
# Authorization is intentionally excluded: upstream auth comes only from the binding.
# Mcp-Method / Mcp-Name are required by DRLink MCP Bridge header/envelope checks.
_FORWARD_REQUEST_HEADERS = {
    "accept",
    "accept-encoding",
    "content-type",
    "mcp-session-id",
    "last-event-id",
    "mcp-protocol-version",
    "mcp-method",
    "mcp-name",
}

# Headers forwarded from upstream → client.
_FORWARD_RESPONSE_HEADERS = {
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
    "cache-control",
}


@dataclass(frozen=True)
class ProxiedResponse:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes


class UpstreamUnavailable(RuntimeError):
    """Upstream MCP endpoint could not be reached or returned a transport failure."""


def _select_headers(
    items: Iterable[tuple[str, str]], allowed: set[str]
) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, value in items:
        if name.lower() in allowed:
            out.append((name, value))
    return out


def _pinned_connect_ip(binding: UpstreamBinding) -> str:
    if not binding.upstream_connect_ips:
        raise UpstreamUnavailable("upstream MCP endpoint unavailable")
    # Connect only to IPs validated at bind time — never re-resolve hostname
    # for the TCP destination (closes DNS-rebinding / TOCTOU SSRF).
    connect_ip = binding.upstream_connect_ips[0]
    try:
        return assert_connect_ip_allowed(
            connect_ip, allow_loopback=binding.allow_loopback_upstream
        )
    except ConfigError as exc:
        raise UpstreamUnavailable("upstream MCP endpoint unavailable") from exc


def _dial_pinned_ip(connect_ip: str, port: int, timeout: float | None) -> socket.socket:
    """Open a TCP socket to a literal IP without calling getaddrinfo on a hostname."""
    ip = ipaddress.ip_address(connect_ip)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    if timeout is not None:
        sock.settimeout(timeout)
    try:
        sock.connect((str(ip), port))
    except OSError:
        sock.close()
        raise
    return sock


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials a pre-validated IP while keeping Host hostname."""

    def __init__(
        self,
        host: str,
        connect_ip: str,
        port: int | None = None,
        timeout: float | None = None,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = _dial_pinned_ip(self._connect_ip, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a pre-validated IP with hostname SNI/certs."""

    def __init__(
        self,
        host: str,
        connect_ip: str,
        port: int | None = None,
        timeout: float | None = None,
        context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        sock = _dial_pinned_ip(self._connect_ip, self.port, self.timeout)
        context = self._context or ssl.create_default_context()
        try:
            self.sock = context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def proxy_mcp_request(
    *,
    method: str,
    binding: UpstreamBinding,
    body: bytes,
    request_headers: dict[str, str],
    timeout_s: float,
    logger: logging.Logger,
) -> ProxiedResponse:
    """Forward one MCP HTTP request to the bound upstream URL.

    Does not reinterpret JSON-RPC payloads. Authorization sent upstream comes
    only from the binding seam, never from raw client Authorization.
    """
    parsed = urlparse(binding.upstream_url)
    assert parsed.hostname is not None
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    headers = {
        name: value
        for name, value in _select_headers(request_headers.items(), _FORWARD_REQUEST_HEADERS)
    }
    if binding.upstream_authorization:
        headers["Authorization"] = binding.upstream_authorization
    if body and "Content-Type" not in {k.title(): v for k, v in headers.items()}:
        # Preserve original content-type if present; otherwise default JSON.
        if "content-type" not in {k.lower() for k in headers}:
            headers["Content-Type"] = "application/json"

    connect_ip = _pinned_connect_ip(binding)

    audit_event(
        logger,
        "mcp_proxy_request",
        binding_id=binding.binding_id,
        plugin_subject=binding.plugin_subject,
        tenant_id=binding.tenant_id or binding.plugin_subject,
        method=method,
        upstream_host=parsed.hostname,
        upstream_connect_ip=connect_ip,
        request_headers=headers,
        body_bytes=len(body or b""),
    )

    connection: http.client.HTTPConnection | http.client.HTTPSConnection
    if parsed.scheme == "https":
        connection = _PinnedHTTPSConnection(
            parsed.hostname,
            connect_ip,
            parsed.port or 443,
            timeout=timeout_s,
            context=ssl.create_default_context(),
        )
    else:
        connection = _PinnedHTTPConnection(
            parsed.hostname,
            connect_ip,
            parsed.port or 80,
            timeout=timeout_s,
        )

    try:
        connection.request(method.upper(), path, body=body or None, headers=headers)
        response = connection.getresponse()
        resp_body = response.read()
        resp_headers = _select_headers(response.getheaders(), _FORWARD_RESPONSE_HEADERS)
        audit_event(
            logger,
            "mcp_proxy_response",
            binding_id=binding.binding_id,
            plugin_subject=binding.plugin_subject,
            tenant_id=binding.tenant_id or binding.plugin_subject,
            status=response.status,
            response_headers=dict(resp_headers),
            body_bytes=len(resp_body),
        )
        return ProxiedResponse(
            status=response.status,
            reason=response.reason,
            headers=resp_headers,
            body=resp_body,
        )
    except (TimeoutError, OSError, http.client.HTTPException, ssl.SSLError) as exc:
        audit_event(
            logger,
            "mcp_proxy_upstream_error",
            binding_id=binding.binding_id,
            error_type=type(exc).__name__,
        )
        raise UpstreamUnavailable("upstream MCP endpoint unavailable") from exc
    finally:
        connection.close()
