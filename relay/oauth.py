"""Single-user OAuth 2.1 authorization server + token validation.

Built-in authorization server co-located with the MCP resource. Supports
Authorization Code + PKCE S256, Dynamic Client Registration (public clients),
resource indicators (RFC 8707), refresh-token rotation, revocation, durable
client/refresh state, and public-endpoint abuse controls.
"""

from __future__ import annotations

import base64
import hashlib
import html
import logging
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

from .audit import audit_event
from .config import RelayConfig
from .oauth_state import STATE_VERSION, DurableOAuthStore, OAuthStateError

_AUDIT_LOGGER = logging.getLogger("drlink.relay")

DEFAULT_SCOPE = "mcp:proxy"
CODE_TTL_S = 60
ACCESS_TTL_S = 3600
REFRESH_TTL_S = 30 * 24 * 3600
MAX_DCR_CLIENTS = 64
# Unactivated DCR clients (no live refresh binding) are capped separately and
# expire quickly so unauthenticated registration cannot lock out ChatGPT.
MAX_INACTIVE_DCR_CLIENTS = 16
INACTIVE_CLIENT_TTL_S = 60 * 60
DCR_RATE_LIMIT = 8
DCR_RATE_WINDOW_S = 15 * 60
OWNER_FAIL_LIMIT = 5
OWNER_FAIL_WINDOW_S = 15 * 60


class OAuthError(Exception):
    def __init__(self, error: str, description: str = "", status: int = 400) -> None:
        super().__init__(description or error)
        self.error = error
        self.description = description
        self.status = status


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url(digest)


def _new_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def _exact_redirect_allowed(registered: list[str], redirect_uri: str) -> bool:
    return redirect_uri in registered


def _redirect_uri_safe(uri: str) -> bool:
    """Accept HTTPS redirects, or HTTP only on explicit loopback hosts.

    ChatGPT Plus cloud OAuth uses HTTPS callbacks. Custom schemes (including
    javascript:/data:) and non-loopback HTTP are rejected for this PoC.
    """
    parsed = urlparse(uri)
    if parsed.fragment:
        return False
    if parsed.scheme == "https":
        return bool(parsed.netloc)
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        return host in {"localhost", "127.0.0.1", "::1"}
    return False


@dataclass
class RegisteredClient:
    client_id: str
    redirect_uris: list[str]
    client_name: str | None
    token_endpoint_auth_method: str
    grant_types: list[str]
    response_types: list[str]
    issued_at: int
    last_used_at: float = 0.0


@dataclass
class AuthCode:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    resource: str
    scopes: frozenset[str]
    expires_at: float
    used: bool = False


@dataclass
class AccessToken:
    token: str
    client_id: str
    resource: str
    scopes: frozenset[str]
    expires_at: float
    revoked: bool = False
    subject: str = "relay-owner"


@dataclass
class RefreshToken:
    token: str
    client_id: str
    resource: str
    scopes: frozenset[str]
    expires_at: float
    revoked: bool = False
    subject: str = "relay-owner"


@dataclass
class PendingAuthorization:
    request_id: str
    client_id: str
    redirect_uri: str
    state: str | None
    code_challenge: str
    code_challenge_method: str
    resource: str
    scopes: frozenset[str]
    expires_at: float


@dataclass
class _SlidingWindow:
    max_events: int
    window_s: float
    _events: dict[str, deque[float]] = field(default_factory=lambda: defaultdict(deque))

    def allow(self, key: str, *, now: float | None = None) -> bool:
        ts = time.time() if now is None else now
        bucket = self._events[key]
        cutoff = ts - self.window_s
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket) < self.max_events

    def record(self, key: str, *, now: float | None = None) -> None:
        ts = time.time() if now is None else now
        bucket = self._events[key]
        cutoff = ts - self.window_s
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(ts)


@dataclass
class OAuthService:
    """Single-user OAuth AS + RS validation with optional durable state."""

    config: RelayConfig
    clients: dict[str, RegisteredClient] = field(default_factory=dict)
    codes: dict[str, AuthCode] = field(default_factory=dict)
    access_tokens: dict[str, AccessToken] = field(default_factory=dict)
    refresh_tokens: dict[str, RefreshToken] = field(default_factory=dict)
    pending: dict[str, PendingAuthorization] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _store: DurableOAuthStore | None = field(default=None, init=False, repr=False)
    _dcr_limiter: _SlidingWindow = field(
        default_factory=lambda: _SlidingWindow(DCR_RATE_LIMIT, DCR_RATE_WINDOW_S),
        init=False,
        repr=False,
    )
    _owner_fail_limiter: _SlidingWindow = field(
        default_factory=lambda: _SlidingWindow(OWNER_FAIL_LIMIT, OWNER_FAIL_WINDOW_S),
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.config.oauth_state_path:
            self._store = DurableOAuthStore(self.config.oauth_state_path)
            payload = self._store.load()
            self._load_payload(payload)
            # Persist TTL cleanup so expired inactive clients do not resurrect.
            with self._lock:
                evicted = self._cleanup_inactive_clients_locked(now=time.time(), reserve_slots=0)
                if evicted:
                    self._persist_locked()
                    audit_event(
                        _AUDIT_LOGGER,
                        "oauth_dcr_clients_evicted",
                        reason="inactive_ttl_on_load",
                        count=len(evicted),
                    )

    def _load_payload(self, payload: dict[str, Any]) -> None:
        clients_raw = payload.get("clients") or {}
        refresh_raw = payload.get("refresh_tokens") or {}
        for key, value in clients_raw.items():
            if not isinstance(value, dict):
                raise OAuthStateError("invalid durable client record")
            try:
                client = RegisteredClient(
                    client_id=str(value["client_id"]),
                    redirect_uris=list(value["redirect_uris"]),
                    client_name=value.get("client_name"),
                    token_endpoint_auth_method=str(
                        value.get("token_endpoint_auth_method", "none")
                    ),
                    grant_types=list(
                        value.get("grant_types") or ["authorization_code", "refresh_token"]
                    ),
                    response_types=list(value.get("response_types") or ["code"]),
                    issued_at=int(value["issued_at"]),
                    last_used_at=float(value.get("last_used_at") or value["issued_at"]),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise OAuthStateError("invalid durable client record") from exc
            if client.client_id != key:
                raise OAuthStateError("durable client_id mismatch")
            self.clients[key] = client
        for key, value in refresh_raw.items():
            if not isinstance(value, dict):
                raise OAuthStateError("invalid durable refresh token record")
            try:
                token = RefreshToken(
                    token=str(value["token"]),
                    client_id=str(value["client_id"]),
                    resource=str(value["resource"]),
                    scopes=frozenset(str(s) for s in (value.get("scopes") or [])),
                    expires_at=float(value["expires_at"]),
                    revoked=bool(value.get("revoked", False)),
                    subject=str(value.get("subject") or "relay-owner"),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise OAuthStateError("invalid durable refresh token record") from exc
            if token.token != key:
                raise OAuthStateError("durable refresh token key mismatch")
            self.refresh_tokens[key] = token

    def _persist_locked(self) -> None:
        if self._store is None:
            return
        now = time.time()
        # Drop expired refresh records from durable storage after TTL.
        expired = [
            tid
            for tid, tok in self.refresh_tokens.items()
            if tok.expires_at < now and tok.revoked
        ]
        for tid in expired:
            del self.refresh_tokens[tid]
        payload = {
            "version": STATE_VERSION,
            "clients": {
                cid: {
                    "client_id": c.client_id,
                    "redirect_uris": list(c.redirect_uris),
                    "client_name": c.client_name,
                    "token_endpoint_auth_method": c.token_endpoint_auth_method,
                    "grant_types": list(c.grant_types),
                    "response_types": list(c.response_types),
                    "issued_at": c.issued_at,
                    "last_used_at": c.last_used_at,
                }
                for cid, c in self.clients.items()
            },
            "refresh_tokens": {
                tid: {
                    "token": t.token,
                    "client_id": t.client_id,
                    "resource": t.resource,
                    "scopes": sorted(t.scopes),
                    "expires_at": t.expires_at,
                    "revoked": t.revoked,
                    "subject": t.subject,
                }
                for tid, t in self.refresh_tokens.items()
            },
        }
        try:
            self._store.save(payload)
        except OAuthStateError as exc:
            raise OAuthError("server_error", str(exc), status=500) from exc

    def _client_has_live_refresh(self, client_id: str, *, now: float) -> bool:
        for token in self.refresh_tokens.values():
            if (
                token.client_id == client_id
                and not token.revoked
                and token.expires_at >= now
            ):
                return True
        return False

    def _remove_client_locked(self, client_id: str) -> None:
        stale = [
            tid
            for tid, tok in self.refresh_tokens.items()
            if tok.client_id == client_id
        ]
        for tid in stale:
            del self.refresh_tokens[tid]
        self.clients.pop(client_id, None)

    def _inactive_clients_locked(self, *, now: float) -> list[RegisteredClient]:
        inactive = [
            c
            for c in self.clients.values()
            if not self._client_has_live_refresh(c.client_id, now=now)
        ]
        inactive.sort(key=lambda c: (c.issued_at, c.last_used_at, c.client_id))
        return inactive

    def _cleanup_inactive_clients_locked(
        self, *, now: float, reserve_slots: int = 0
    ) -> list[str]:
        """Evict unactivated/inactive DCR clients; never touch live-refresh clients.

        ``reserve_slots`` leaves room for an incoming registration (typically 1).
        """
        if reserve_slots < 0:
            raise ValueError("reserve_slots must be >= 0")
        evicted: list[str] = []

        # Short TTL for clients that never received (or no longer have) a live refresh.
        for client in list(self.clients.values()):
            if self._client_has_live_refresh(client.client_id, now=now):
                continue
            if (now - client.last_used_at) < INACTIVE_CLIENT_TTL_S:
                continue
            self._remove_client_locked(client.client_id)
            evicted.append(client.client_id)

        inactive_budget = max(0, MAX_INACTIVE_DCR_CLIENTS - reserve_slots)
        total_budget = max(0, MAX_DCR_CLIENTS - reserve_slots)
        while True:
            inactive = self._inactive_clients_locked(now=now)
            over_inactive = len(inactive) > inactive_budget
            over_total = len(self.clients) > total_budget
            if not over_inactive and not over_total:
                break
            if not inactive:
                break
            victim = inactive[0]
            self._remove_client_locked(victim.client_id)
            evicted.append(victim.client_id)
        return evicted

    @property
    def issuer(self) -> str:
        assert self.config.public_base_url is not None
        return self.config.public_base_url

    @property
    def resource(self) -> str:
        assert self.config.resource_url is not None
        return self.config.resource_url

    @property
    def scopes_supported(self) -> list[str]:
        return [DEFAULT_SCOPE]

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": self.scopes_supported,
            "bearer_methods_supported": ["header"],
            "resource_documentation": f"{self.issuer}/health",
        }

    def authorization_server_metadata(self) -> dict[str, Any]:
        base = self.issuer
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "revocation_endpoint": f"{base}/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": self.scopes_supported,
            "authorization_response_iss_parameter_supported": True,
            "revocation_endpoint_auth_methods_supported": ["none"],
            # CIMD deliberately not advertised; DCR is the PoC registration path.
            "client_id_metadata_document_supported": False,
        }

    def register_client(
        self, body: dict[str, Any], *, source: str = "unknown"
    ) -> dict[str, Any]:
        with self._lock:
            if not self._dcr_limiter.allow(source):
                raise OAuthError(
                    "temporarily_unavailable",
                    "client registration rate limit exceeded",
                    status=429,
                )
            now = time.time()
            evicted = self._cleanup_inactive_clients_locked(now=now, reserve_slots=1)
            if evicted:
                audit_event(
                    _AUDIT_LOGGER,
                    "oauth_dcr_clients_evicted",
                    reason="inactive_capacity",
                    count=len(evicted),
                )
            if len(self.clients) >= MAX_DCR_CLIENTS:
                audit_event(
                    _AUDIT_LOGGER,
                    "oauth_dcr_registration_exhausted",
                    reason="active_client_capacity",
                    active_clients=sum(
                        1
                        for cid in self.clients
                        if self._client_has_live_refresh(cid, now=now)
                    ),
                    total_clients=len(self.clients),
                )
                raise OAuthError(
                    "invalid_client_metadata",
                    "client registration limit reached",
                    status=400,
                )

            redirect_uris = body.get("redirect_uris")
            if not isinstance(redirect_uris, list) or not redirect_uris:
                raise OAuthError(
                    "invalid_redirect_uri",
                    "redirect_uris required",
                    status=400,
                )
            cleaned: list[str] = []
            for uri in redirect_uris:
                if not isinstance(uri, str) or not _redirect_uri_safe(uri):
                    raise OAuthError(
                        "invalid_redirect_uri",
                        "redirect_uri must be https or loopback http",
                        status=400,
                    )
                cleaned.append(uri)

            auth_method = body.get("token_endpoint_auth_method", "none")
            if auth_method != "none":
                raise OAuthError(
                    "invalid_client_metadata",
                    "only public clients (token_endpoint_auth_method=none) are supported",
                    status=400,
                )

            grant_types = body.get("grant_types") or ["authorization_code", "refresh_token"]
            if not isinstance(grant_types, list):
                raise OAuthError("invalid_client_metadata", "grant_types invalid", status=400)
            allowed_grants = {"authorization_code", "refresh_token"}
            if any(g not in allowed_grants for g in grant_types):
                raise OAuthError("invalid_client_metadata", "unsupported grant_type", status=400)

            response_types = body.get("response_types") or ["code"]
            if response_types != ["code"] and set(response_types) != {"code"}:
                raise OAuthError("invalid_client_metadata", "only response_type=code", status=400)

            client_id = _new_token("client")
            issued_at = int(now)
            name = body.get("client_name")
            client = RegisteredClient(
                client_id=client_id,
                redirect_uris=cleaned,
                client_name=name if isinstance(name, str) else None,
                token_endpoint_auth_method="none",
                grant_types=list(grant_types),
                response_types=["code"],
                issued_at=issued_at,
                last_used_at=now,
            )
            self.clients[client_id] = client
            self._dcr_limiter.record(source, now=now)
            self._persist_locked()
            return {
                "client_id": client_id,
                "client_id_issued_at": issued_at,
                "redirect_uris": cleaned,
                "token_endpoint_auth_method": "none",
                "grant_types": list(grant_types),
                "response_types": ["code"],
                "client_name": client.client_name,
            }

    def _parse_scopes(self, scope: str | None) -> frozenset[str]:
        if not scope or not scope.strip():
            return frozenset(self.scopes_supported)
        requested = frozenset(scope.split())
        supported = frozenset(self.scopes_supported)
        if not requested.issubset(supported):
            raise OAuthError("invalid_scope", "unsupported scope requested")
        return requested

    def begin_authorization(self, params: dict[str, str]) -> PendingAuthorization | dict[str, str]:
        """Validate authorize query. Returns pending auth or error redirect params."""
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        response_type = params.get("response_type", "")
        state = params.get("state")
        challenge = params.get("code_challenge", "")
        method = params.get("code_challenge_method", "")
        resource = params.get("resource", "")
        scope = params.get("scope")

        def error_redirect(error: str, description: str) -> dict[str, str] | PendingAuthorization:
            if not redirect_uri or not client_id:
                raise OAuthError(error, description)
            with self._lock:
                client = self.clients.get(client_id)
            if client is None or not _exact_redirect_allowed(client.redirect_uris, redirect_uri):
                raise OAuthError(error, description)
            out = {"error": error, "error_description": description, "iss": self.issuer}
            if state is not None:
                out["state"] = state
            return out

        with self._lock:
            client = self.clients.get(client_id)
            if client is None:
                raise OAuthError("unauthorized_client", "unknown client_id")
            if not _exact_redirect_allowed(client.redirect_uris, redirect_uri):
                raise OAuthError("invalid_request", "redirect_uri mismatch")
        if response_type != "code":
            return error_redirect("unsupported_response_type", "only code is supported")  # type: ignore[return-value]
        if method != "S256":
            return error_redirect("invalid_request", "code_challenge_method must be S256")  # type: ignore[return-value]
        if not challenge:
            return error_redirect("invalid_request", "code_challenge required")  # type: ignore[return-value]
        if resource != self.resource:
            return error_redirect("invalid_target", "resource does not match MCP resource")  # type: ignore[return-value]
        try:
            scopes = self._parse_scopes(scope)
        except OAuthError as exc:
            return error_redirect(exc.error, exc.description)  # type: ignore[return-value]

        request_id = _new_token("authreq")
        pending = PendingAuthorization(
            request_id=request_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=challenge,
            code_challenge_method=method,
            resource=resource,
            scopes=scopes,
            expires_at=time.time() + CODE_TTL_S,
        )
        with self._lock:
            client.last_used_at = time.time()
            self.pending[request_id] = pending
            self._persist_locked()
        return pending

    def consent_html(self, pending: PendingAuthorization, error: str | None = None) -> str:
        client = self.clients.get(pending.client_id)
        name = (client.client_name if client and client.client_name else pending.client_id)
        err = f"<p class='err'>{html.escape(error)}</p>" if error else ""
        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>DataRelay Link Plugin — Authorize</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem}}
.err{{color:#b00020}} label{{display:block;margin:.75rem 0 .25rem}}
input[type=password]{{width:100%;padding:.5rem}} button{{margin-top:1rem;padding:.5rem 1rem}}
</style></head><body>
<h1>Authorize DataRelay Link Plugin</h1>
<p>Client <strong>{html.escape(str(name))}</strong> requests scope
<code>{html.escape(' '.join(sorted(pending.scopes)))}</code> for resource
<code>{html.escape(pending.resource)}</code>.</p>
<p>Approve only if you are the configured relay owner. Upstream DRLink credentials are never shared with ChatGPT.</p>
{err}
<form method="post" action="/oauth/authorize">
<input type="hidden" name="request_id" value="{html.escape(pending.request_id)}"/>
<label for="owner_secret">Owner approval secret</label>
<input id="owner_secret" name="owner_secret" type="password" autocomplete="current-password" required/>
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form>
</body></html>"""

    def complete_authorization(
        self,
        *,
        request_id: str,
        owner_secret: str,
        decision: str,
        source: str = "unknown",
    ) -> str:
        """Return redirect Location URL after owner decision."""
        with self._lock:
            pending = self.pending.pop(request_id, None)
        if pending is None or time.time() > pending.expires_at:
            raise OAuthError("invalid_request", "authorization request expired or unknown")

        def redirect(params: dict[str, str]) -> str:
            parsed = urlparse(pending.redirect_uri)
            # Append query params (preserve existing query).
            q = params.copy()
            if pending.state is not None:
                q.setdefault("state", pending.state)
            q["iss"] = self.issuer
            extra = urlencode(q)
            existing = parsed.query
            new_query = f"{existing}&{extra}" if existing else extra
            return urlunparse(parsed._replace(query=new_query))

        if decision != "approve":
            return redirect(
                {"error": "access_denied", "error_description": "owner denied authorization"}
            )

        # Uniform denial message: do not leak lockout vs wrong-secret vs prefix guesses.
        denial = "authorization denied"
        with self._lock:
            if not self._owner_fail_limiter.allow(source):
                self.pending[request_id] = pending
                raise OAuthError("access_denied", denial, status=401)

            expected = self.config.owner_approval_secret or ""
            if not expected or not secrets.compare_digest(owner_secret, expected):
                self._owner_fail_limiter.record(source)
                self.pending[request_id] = pending
                raise OAuthError("access_denied", denial, status=401)

            client = self.clients.get(pending.client_id)
            if client is not None:
                client.last_used_at = time.time()

        code_value = _new_token("code")
        auth_code = AuthCode(
            code=code_value,
            client_id=pending.client_id,
            redirect_uri=pending.redirect_uri,
            code_challenge=pending.code_challenge,
            code_challenge_method=pending.code_challenge_method,
            resource=pending.resource,
            scopes=pending.scopes,
            expires_at=time.time() + CODE_TTL_S,
        )
        with self._lock:
            self.codes[code_value] = auth_code
            self._persist_locked()
        return redirect({"code": code_value})

    def exchange_token(self, form: dict[str, str]) -> dict[str, Any]:
        grant_type = form.get("grant_type", "")
        if grant_type == "authorization_code":
            return self._exchange_authorization_code(form)
        if grant_type == "refresh_token":
            return self._exchange_refresh_token(form)
        raise OAuthError("unsupported_grant_type", "unsupported grant_type")

    def _exchange_authorization_code(self, form: dict[str, str]) -> dict[str, Any]:
        code = form.get("code", "")
        redirect_uri = form.get("redirect_uri", "")
        client_id = form.get("client_id", "")
        verifier = form.get("code_verifier", "")
        resource = form.get("resource", "")

        with self._lock:
            record = self.codes.get(code)
            if record is None:
                raise OAuthError("invalid_grant", "unknown authorization code")
            # Consume immediately to prevent replay (including failed PKCE attempts).
            del self.codes[code]
            if record.used or time.time() > record.expires_at:
                raise OAuthError("invalid_grant", "authorization code expired or used")
            record.used = True

            if record.client_id != client_id:
                raise OAuthError("invalid_grant", "client_id mismatch")
            client = self.clients.get(client_id)
            if client is None:
                raise OAuthError("unauthorized_client", "unknown client")
            if record.redirect_uri != redirect_uri:
                raise OAuthError("invalid_grant", "redirect_uri mismatch")
            if resource != record.resource or resource != self.resource:
                raise OAuthError("invalid_target", "resource mismatch")
            if record.code_challenge_method != "S256":
                raise OAuthError("invalid_grant", "PKCE method not S256")
            if not verifier or _pkce_s256(verifier) != record.code_challenge:
                raise OAuthError("invalid_grant", "PKCE verification failed")

            client.last_used_at = time.time()
            return self._issue_tokens(
                client_id=client_id,
                resource=record.resource,
                scopes=record.scopes,
            )

    def _exchange_refresh_token(self, form: dict[str, str]) -> dict[str, Any]:
        refresh = form.get("refresh_token", "")
        client_id = form.get("client_id", "")
        resource = form.get("resource", "")
        scope = form.get("scope")

        with self._lock:
            record = self.refresh_tokens.get(refresh)
            if record is None or record.revoked or time.time() > record.expires_at:
                raise OAuthError("invalid_grant", "invalid refresh token")
            if record.client_id != client_id:
                raise OAuthError("invalid_grant", "client_id mismatch")
            if resource and resource != record.resource:
                raise OAuthError("invalid_target", "resource mismatch")
            if resource and resource != self.resource:
                raise OAuthError("invalid_target", "resource mismatch")
            # Rotate: revoke old refresh token.
            record.revoked = True
            scopes = record.scopes
            if scope:
                requested = self._parse_scopes(scope)
                if not requested.issubset(record.scopes):
                    raise OAuthError("invalid_scope", "cannot expand scopes on refresh")
                scopes = requested
            client = self.clients.get(client_id)
            if client is not None:
                client.last_used_at = time.time()
            return self._issue_tokens(
                client_id=client_id,
                resource=record.resource,
                scopes=scopes,
            )

    def _issue_tokens(
        self, *, client_id: str, resource: str, scopes: frozenset[str]
    ) -> dict[str, Any]:
        now = time.time()
        access = AccessToken(
            token=_new_token("atk"),
            client_id=client_id,
            resource=resource,
            scopes=scopes,
            expires_at=now + ACCESS_TTL_S,
        )
        refresh = RefreshToken(
            token=_new_token("rtk"),
            client_id=client_id,
            resource=resource,
            scopes=scopes,
            expires_at=now + REFRESH_TTL_S,
        )
        self.access_tokens[access.token] = access
        self.refresh_tokens[refresh.token] = refresh
        self._persist_locked()
        return {
            "access_token": access.token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL_S,
            "refresh_token": refresh.token,
            "scope": " ".join(sorted(scopes)),
            "resource": resource,
        }

    def revoke(self, form: dict[str, str]) -> None:
        token = form.get("token", "")
        hint = form.get("token_type_hint", "")
        with self._lock:
            if hint in {"", "access_token"} and token in self.access_tokens:
                self.access_tokens[token].revoked = True
                self._persist_locked()
                return
            if hint in {"", "refresh_token"} and token in self.refresh_tokens:
                self.refresh_tokens[token].revoked = True
                self._persist_locked()
                return
            if token in self.access_tokens:
                self.access_tokens[token].revoked = True
            if token in self.refresh_tokens:
                self.refresh_tokens[token].revoked = True
            self._persist_locked()
            # RFC 7009: invalid tokens still return 200.

    def validate_bearer(
        self, authorization_header: str | None, *, required_scopes: frozenset[str] | None = None
    ) -> AccessToken:
        if not authorization_header or not authorization_header.startswith("Bearer "):
            raise OAuthError("invalid_token", "missing bearer token", status=401)
        token_value = authorization_header[len("Bearer ") :].strip()
        if not token_value:
            raise OAuthError("invalid_token", "missing bearer token", status=401)
        required = required_scopes or frozenset(self.scopes_supported)
        with self._lock:
            record = self.access_tokens.get(token_value)
            if record is None or record.revoked:
                raise OAuthError("invalid_token", "token revoked or unknown", status=401)
            if time.time() > record.expires_at:
                raise OAuthError("invalid_token", "token expired", status=401)
            if record.resource != self.resource:
                raise OAuthError("invalid_token", "wrong resource audience", status=401)
            if not required.issubset(record.scopes):
                raise OAuthError("insufficient_scope", "missing required scope", status=403)
            return record

    def www_authenticate(
        self,
        *,
        error: str | None = None,
        error_description: str | None = None,
        scope: str | None = None,
    ) -> str:
        """Build a Bearer WWW-Authenticate challenge for HTTP and MCP `_meta`.

        When ``error`` is set, both ``error`` and a safe ``error_description``
        are included so ChatGPT can surface the connect/reconnect UI.
        """
        metadata = f"{self.issuer}/.well-known/oauth-protected-resource"
        parts = [f'Bearer resource_metadata="{metadata}"']
        parts.append(f'scope="{scope or DEFAULT_SCOPE}"')
        if error:
            safe_error = error.replace("\\", "").replace('"', "")
            parts.append(f'error="{safe_error}"')
            desc = error_description or _default_error_description(error)
            # Prevent header/meta injection via quotes or control chars.
            safe_desc = (
                "".join(ch for ch in desc if ch.isprintable() and ch not in {'"', "\\"})
                .strip()
                or _default_error_description(error)
            )
            parts.append(f'error_description="{safe_desc}"')
        return ", ".join(parts)


def _default_error_description(error: str) -> str:
    if error == "insufficient_scope":
        return "missing required scope"
    if error == "invalid_token":
        return "authentication required"
    return "authentication required"
