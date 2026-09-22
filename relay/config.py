"""Configuration loading and SSRF-resistant upstream URL validation."""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


class ConfigError(ValueError):
    """Invalid or missing relay configuration."""


DEFAULT_MOCK_PLUGIN_TOKEN = "dev-plugin-token"


@dataclass(frozen=True)
class RelayConfig:
    bind_host: str
    bind_port: int
    upstream_url: str
    upstream_connect_ips: tuple[str, ...]
    upstream_token: str | None
    allow_loopback_upstream: bool
    mock_plugin_token: str
    request_timeout_s: float


_BLOCKED_HOSTNAMES = {"metadata.google.internal", "metadata"}


def _is_loopback_host(hostname: str) -> bool:
    host = hostname.strip("[]").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_connect_ip_allowed(ip_str: str, *, allow_loopback: bool) -> str:
    """Return a normalized IP string if it is an allowed upstream destination."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError as exc:
        raise ConfigError(f"invalid upstream connect address: {ip_str}") from exc

    if ip.is_loopback:
        if not allow_loopback:
            raise ConfigError(
                "loopback upstream requires DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM=1"
            )
        return str(ip)

    if (
        ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise ConfigError(
            f"upstream resolves to a non-public address which is blocked: {ip}"
        )
    return str(ip)


def _resolve_allowed_ips(hostname: str, *, allow_loopback: bool) -> tuple[str, ...]:
    if not hostname:
        raise ConfigError("upstream URL hostname is required")
    host = hostname.strip("[]").lower()
    if host in _BLOCKED_HOSTNAMES:
        raise ConfigError("upstream hostname is blocked")

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConfigError(f"upstream hostname cannot be resolved: {host}") from exc

    if not infos:
        raise ConfigError(f"upstream hostname cannot be resolved: {host}")

    allowed: list[str] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        ip_str = assert_connect_ip_allowed(sockaddr[0], allow_loopback=allow_loopback)
        if ip_str not in seen:
            seen.add(ip_str)
            allowed.append(ip_str)

    if not allowed:
        raise ConfigError(f"upstream hostname cannot be resolved: {host}")
    return tuple(allowed)


def validate_upstream_url(url: str, *, allow_loopback: bool) -> str:
    """Return a normalized absolute upstream MCP URL or raise ConfigError."""
    validated = validate_upstream_binding(url, allow_loopback=allow_loopback)
    return validated.url


@dataclass(frozen=True)
class ValidatedUpstream:
    url: str
    hostname: str
    connect_ips: tuple[str, ...]


def validate_upstream_binding(url: str, *, allow_loopback: bool) -> ValidatedUpstream:
    """Validate upstream URL and bind hostname to resolved allowed IP addresses."""
    raw = (url or "").strip()
    if not raw:
        raise ConfigError("DRLINK_RELAY_UPSTREAM_URL is required")

    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ConfigError("upstream URL scheme must be http or https")
    if not parsed.hostname:
        raise ConfigError("upstream URL must include a hostname")
    if parsed.username or parsed.password:
        raise ConfigError("upstream URL must not embed credentials")
    if parsed.fragment:
        raise ConfigError("upstream URL must not include a fragment")

    is_loopback = _is_loopback_host(parsed.hostname)
    if parsed.scheme == "http" and not is_loopback:
        raise ConfigError("non-loopback upstream URLs must use https")
    if is_loopback and not allow_loopback:
        raise ConfigError(
            "loopback upstream requires DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM=1"
        )

    connect_ips = _resolve_allowed_ips(parsed.hostname, allow_loopback=allow_loopback)
    return ValidatedUpstream(
        url=raw.rstrip(),
        hostname=parsed.hostname.strip("[]"),
        connect_ips=connect_ips,
    )


def load_config(environ: dict[str, str] | None = None) -> RelayConfig:
    env = environ if environ is not None else os.environ
    allow_loopback = env.get("DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM", "").strip() in {
        "1",
        "true",
        "TRUE",
        "yes",
        "YES",
    }
    upstream = validate_upstream_binding(
        env.get("DRLINK_RELAY_UPSTREAM_URL", ""),
        allow_loopback=allow_loopback,
    )
    token = env.get("DRLINK_RELAY_UPSTREAM_TOKEN") or None
    if token is not None:
        token = token.strip() or None

    bind_host = (env.get("DRLINK_RELAY_BIND") or "127.0.0.1").strip()
    port_raw = (env.get("DRLINK_RELAY_PORT") or "8741").strip()
    try:
        bind_port = int(port_raw)
    except ValueError as exc:
        raise ConfigError("DRLINK_RELAY_PORT must be an integer") from exc
    if not (1 <= bind_port <= 65535):
        raise ConfigError("DRLINK_RELAY_PORT out of range")

    timeout_raw = (env.get("DRLINK_RELAY_TIMEOUT_S") or "30").strip()
    try:
        timeout_s = float(timeout_raw)
    except ValueError as exc:
        raise ConfigError("DRLINK_RELAY_TIMEOUT_S must be a number") from exc
    if timeout_s <= 0:
        raise ConfigError("DRLINK_RELAY_TIMEOUT_S must be positive")

    explicit_mock_token = env.get("DRLINK_RELAY_MOCK_PLUGIN_TOKEN")
    if explicit_mock_token is None:
        mock_plugin_token = DEFAULT_MOCK_PLUGIN_TOKEN
    else:
        mock_plugin_token = explicit_mock_token.strip()
    if not mock_plugin_token:
        raise ConfigError("DRLINK_RELAY_MOCK_PLUGIN_TOKEN must not be empty")

    allow_non_loopback_bind = env.get(
        "DRLINK_RELAY_ALLOW_NON_LOOPBACK_BIND", ""
    ).strip() in {"1", "true", "TRUE", "yes", "YES"}
    if not _is_loopback_host(bind_host):
        if not allow_non_loopback_bind:
            raise ConfigError(
                "non-loopback bind requires DRLINK_RELAY_ALLOW_NON_LOOPBACK_BIND=1 "
                "(dev-only mock binding is not safe on public interfaces)"
            )
        if mock_plugin_token == DEFAULT_MOCK_PLUGIN_TOKEN:
            raise ConfigError(
                "non-loopback bind rejects the default mock plugin token; "
                "set an explicit strong DRLINK_RELAY_MOCK_PLUGIN_TOKEN"
            )

    return RelayConfig(
        bind_host=bind_host,
        bind_port=bind_port,
        upstream_url=upstream.url,
        upstream_connect_ips=upstream.connect_ips,
        upstream_token=token,
        allow_loopback_upstream=allow_loopback,
        mock_plugin_token=mock_plugin_token,
        request_timeout_s=timeout_s,
    )
