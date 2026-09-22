"""HTTP pass-through to a single configured upstream MCP endpoint."""

from __future__ import annotations

import http.client
import logging
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from .audit import audit_event
from .binding import UpstreamBinding

# Headers forwarded from client → upstream (case-insensitive match).
_FORWARD_REQUEST_HEADERS = {
    "accept",
    "accept-encoding",
    "content-type",
    "mcp-session-id",
    "last-event-id",
    "mcp-protocol-version",
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

    audit_event(
        logger,
        "mcp_proxy_request",
        binding_id=binding.binding_id,
        method=method,
        upstream_host=parsed.hostname,
        request_headers=headers,
        body_bytes=len(body or b""),
    )

    connection: http.client.HTTPConnection | http.client.HTTPSConnection
    if parsed.scheme == "https":
        connection = http.client.HTTPSConnection(
            parsed.hostname, parsed.port or 443, timeout=timeout_s
        )
    else:
        connection = http.client.HTTPConnection(
            parsed.hostname, parsed.port or 80, timeout=timeout_s
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
    except (TimeoutError, OSError, http.client.HTTPException) as exc:
        audit_event(
            logger,
            "mcp_proxy_upstream_error",
            binding_id=binding.binding_id,
            error_type=type(exc).__name__,
        )
        raise UpstreamUnavailable("upstream MCP endpoint unavailable") from exc
    finally:
        connection.close()
