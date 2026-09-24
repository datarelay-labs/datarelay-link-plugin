"""Durable Plugin-subject → DRLink server bindings.

This registry records which DRLink MCP servers an authenticated Plugin subject
explicitly connected. It is not an authorization cache: every proxied tool call
is still decided by the upstream DRLink server.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .binding import BindingError, UpstreamBinding
from .config import ConfigError, assert_connect_ip_allowed, validate_upstream_binding
from .oauth_state import STATE_VERSION, DurableOAuthStore, OAuthStateError

MAX_BINDINGS_PER_SUBJECT = 8
_MAX_UPSTREAM_URL_LEN = 2048
_MAX_UPSTREAM_TOKEN_LEN = 4096


@dataclass
class ServerBindingRecord:
    binding_id: str
    subject: str
    upstream_url: str
    upstream_host: str
    connect_ips: tuple[str, ...]
    allow_loopback: bool
    upstream_bearer: str | None
    connected: bool
    active: bool
    created_at: float


class TenantBindingRegistry:
    """Per-subject connected DRLink servers with restart-durable lifecycle."""

    def __init__(
        self,
        *,
        allow_loopback: bool,
        public_base_url: str | None,
        store: DurableOAuthStore | None,
    ) -> None:
        self._allow_loopback = allow_loopback
        self._public_base_url = public_base_url
        self._store = store
        self._lock = threading.RLock()
        self._records: dict[str, ServerBindingRecord] = {}
        if store is not None:
            try:
                payload = store.load()
            except OAuthStateError:
                raise
            self._load_map(payload.get("server_bindings") or {})

    def snapshot(self) -> dict[str, Any]:
        """Durable map. Includes upstream bearers; never return this on HTTP."""
        with self._lock:
            return {bid: _to_disk(rec) for bid, rec in self._records.items()}

    def connect(
        self,
        *,
        subject: str,
        upstream_url: str,
        upstream_token: str | None,
    ) -> dict[str, Any]:
        url = (upstream_url or "").strip()
        if not url or len(url) > _MAX_UPSTREAM_URL_LEN:
            raise BindingError("invalid upstream URL", status=400)
        token = (upstream_token or "").strip() or None
        if token is not None and len(token) > _MAX_UPSTREAM_TOKEN_LEN:
            raise BindingError("invalid upstream token", status=400)
        self._assert_not_relay(url)
        try:
            validated = validate_upstream_binding(
                url, allow_loopback=self._allow_loopback
            )
        except ConfigError as exc:
            raise BindingError(str(exc), status=400) from exc

        with self._lock:
            owned = [
                rec
                for rec in self._records.values()
                if rec.subject == subject and rec.connected
            ]
            if len(owned) >= MAX_BINDINGS_PER_SUBJECT:
                raise BindingError("binding limit reached", status=400)
            binding_id = _new_binding_id(set(self._records))
            active = not any(rec.active and rec.connected for rec in owned)
            record = ServerBindingRecord(
                binding_id=binding_id,
                subject=subject,
                upstream_url=validated.url,
                upstream_host=validated.hostname,
                connect_ips=validated.connect_ips,
                allow_loopback=self._allow_loopback,
                upstream_bearer=token,
                connected=True,
                active=active,
                created_at=time.time(),
            )
            self._records[binding_id] = record
        try:
            self._persist_from_memory()
        except BindingError:
            with self._lock:
                self._records.pop(binding_id, None)
            raise
        return _public_view(record)

    def list_bindings(self, subject: str) -> list[dict[str, Any]]:
        with self._lock:
            owned = [rec for rec in self._records.values() if rec.subject == subject]
            owned.sort(key=lambda rec: (rec.created_at, rec.binding_id))
            return [_public_view(rec) for rec in owned]

    def disconnect(self, *, subject: str, binding_id: str) -> dict[str, Any]:
        """Revoke the binding, free its slot, and purge the stored bearer."""
        with self._lock:
            self._owned(subject, binding_id)
            removed = self._records.pop(binding_id)
        view = _public_view(removed)
        view["connected"] = False
        view["active"] = False
        try:
            self._persist_from_memory()
        except BindingError:
            with self._lock:
                self._records[binding_id] = removed
            raise
        removed.upstream_bearer = None
        return view

    def activate(self, *, subject: str, binding_id: str) -> dict[str, Any]:
        with self._lock:
            record = self._owned(subject, binding_id)
            if not record.connected:
                raise BindingError("binding unavailable", status=403)
            previous = {
                other.binding_id: other.active
                for other in self._records.values()
                if other.subject == subject
            }
            for other in self._records.values():
                if other.subject == subject:
                    other.active = other.binding_id == record.binding_id
        try:
            self._persist_from_memory()
        except BindingError:
            with self._lock:
                for other_id, was_active in previous.items():
                    other = self._records.get(other_id)
                    if other is not None:
                        other.active = was_active
            raise
        return _public_view(record)

    def resolve(self, *, subject: str, binding_id: str | None) -> UpstreamBinding:
        """Return the connection to dial. Does not cache upstream ALLOW decisions."""
        with self._lock:
            if binding_id:
                record = self._records.get(binding_id)
                if record is None or record.subject != subject or not record.connected:
                    raise BindingError(
                        "binding unavailable",
                        status=403,
                        oauth_error="insufficient_scope",
                        oauth_description="binding unavailable",
                        subject=subject,
                    )
            else:
                matches = [
                    rec
                    for rec in self._records.values()
                    if rec.subject == subject and rec.connected and rec.active
                ]
                if len(matches) != 1:
                    raise BindingError(
                        "no connected DRLink server",
                        status=403,
                        oauth_error="insufficient_scope",
                        oauth_description="no connected DRLink server",
                        subject=subject,
                    )
                record = matches[0]
            return self._to_upstream(record)

    def _normalize_active_locked(self) -> None:
        by_subject: dict[str, list[ServerBindingRecord]] = {}
        for record in self._records.values():
            if not record.connected:
                record.active = False
            by_subject.setdefault(record.subject, []).append(record)
        for owned in by_subject.values():
            active = [rec for rec in owned if rec.connected and rec.active]
            if len(active) <= 1:
                continue
            active.sort(key=lambda rec: (rec.created_at, rec.binding_id))
            keeper = active[-1].binding_id
            for rec in owned:
                rec.active = rec.connected and rec.binding_id == keeper

    def _owned(self, subject: str, binding_id: str) -> ServerBindingRecord:
        record = self._records.get(binding_id)
        if record is None or record.subject != subject:
            raise BindingError("binding unavailable", status=403)
        return record

    def _to_upstream(self, record: ServerBindingRecord) -> UpstreamBinding:
        try:
            ips = tuple(
                assert_connect_ip_allowed(ip, allow_loopback=self._allow_loopback)
                for ip in record.connect_ips
            )
        except ConfigError as exc:
            raise BindingError(
                "binding unavailable",
                status=403,
                oauth_error="insufficient_scope",
                oauth_description="binding unavailable",
                subject=record.subject,
            ) from exc
        if not ips:
            raise BindingError(
                "binding unavailable",
                status=403,
                oauth_error="insufficient_scope",
                oauth_description="binding unavailable",
                subject=record.subject,
            )
        authorization = None
        if record.upstream_bearer:
            authorization = f"Bearer {record.upstream_bearer}"
        return UpstreamBinding(
            binding_id=record.binding_id,
            upstream_url=record.upstream_url,
            upstream_connect_ips=ips,
            allow_loopback_upstream=self._allow_loopback and record.allow_loopback,
            upstream_authorization=authorization,
            plugin_subject=record.subject,
            tenant_id=record.subject,
        )

    def _assert_not_relay(self, url: str) -> None:
        if not self._public_base_url:
            return
        if _origin_key(url) == _origin_key(self._public_base_url):
            raise BindingError("upstream must not target the relay", status=400)

    def _load_map(self, raw: Any) -> None:
        if not isinstance(raw, dict):
            raise OAuthStateError("oauth state server_bindings must be an object")
        loaded: dict[str, ServerBindingRecord] = {}
        for key, value in raw.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                raise OAuthStateError("invalid durable server binding")
            try:
                record = _from_disk(key, value)
            except (KeyError, TypeError, ValueError) as exc:
                raise OAuthStateError("invalid durable server binding") from exc
            if not record.connected:
                # Disconnected rows are revocation tombstones with no lifecycle
                # purpose. Drop them, including any retained upstream bearer.
                continue
            try:
                for ip in record.connect_ips:
                    assert_connect_ip_allowed(ip, allow_loopback=self._allow_loopback)
            except ConfigError as exc:
                raise OAuthStateError("durable server binding has a blocked address") from exc
            loaded[key] = record
        purged = len(loaded) != len(raw)
        self._records = loaded
        self._normalize_active_locked()
        if purged:
            self._persist_from_memory()

    def _persist_from_memory(self) -> None:
        """Write current records. Caller must not hold ``self._lock``."""
        if self._store is None:
            return

        def _mutate(payload: dict[str, Any]) -> None:
            with self._lock:
                payload["server_bindings"] = {
                    bid: _to_disk(rec) for bid, rec in self._records.items()
                }
            payload["version"] = STATE_VERSION

        try:
            self._store.update(_mutate)
        except OAuthStateError as exc:
            raise BindingError("binding state unavailable", status=500) from exc


def _effective_port(scheme: str, port: int | None) -> int | None:
    """Map omitted ports to the scheme default so :443 is the same origin as https."""
    normalized = scheme.lower()
    if port is not None:
        return port
    if normalized == "https":
        return 443
    if normalized == "http":
        return 80
    return None


def _origin_key(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    return scheme, host, _effective_port(scheme, parsed.port)


def _new_binding_id(existing: set[str]) -> str:
    for _ in range(8):
        binding_id = "bnd_" + secrets.token_urlsafe(18)
        if binding_id not in existing:
            return binding_id
    raise BindingError("binding state unavailable", status=500)


def _public_view(record: ServerBindingRecord) -> dict[str, Any]:
    return {
        "binding_id": record.binding_id,
        "upstream_host": record.upstream_host,
        "connected": record.connected,
        "active": record.active,
    }


def _to_disk(record: ServerBindingRecord) -> dict[str, Any]:
    return {
        "binding_id": record.binding_id,
        "subject": record.subject,
        "upstream_url": record.upstream_url,
        "upstream_host": record.upstream_host,
        "connect_ips": list(record.connect_ips),
        "allow_loopback": record.allow_loopback,
        "upstream_bearer": record.upstream_bearer,
        "connected": record.connected,
        "active": record.active,
        "created_at": record.created_at,
    }


def _from_disk(key: str, value: dict[str, Any]) -> ServerBindingRecord:
    binding_id = str(value["binding_id"])
    if binding_id != key:
        raise ValueError("binding id mismatch")
    subject = str(value["subject"])
    if not subject:
        raise ValueError("missing subject")
    ips_raw = value.get("connect_ips")
    if not isinstance(ips_raw, list) or not ips_raw:
        raise ValueError("missing connect ips")
    bearer = value.get("upstream_bearer")
    if bearer is not None:
        bearer = str(bearer)
    return ServerBindingRecord(
        binding_id=binding_id,
        subject=subject,
        upstream_url=str(value["upstream_url"]),
        upstream_host=str(value["upstream_host"]),
        connect_ips=tuple(str(ip) for ip in ips_raw),
        allow_loopback=bool(value.get("allow_loopback", False)),
        upstream_bearer=bearer,
        connected=bool(value.get("connected", False)),
        active=bool(value.get("active", False)),
        created_at=float(value.get("created_at") or 0),
    )
