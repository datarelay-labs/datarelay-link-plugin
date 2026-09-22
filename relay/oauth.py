"""Single-user OAuth 2.1 authorization server + token validation (Packet 2 PoC).

Built-in authorization server co-located with the MCP resource. Supports
Authorization Code + PKCE S256, Dynamic Client Registration (public clients),
resource indicators (RFC 8707), refresh-token rotation, and revocation.
"""

from __future__ import annotations

import base64
import hashlib
import html
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

from .config import RelayConfig

DEFAULT_SCOPE = "mcp:proxy"
CODE_TTL_S = 60
ACCESS_TTL_S = 3600
REFRESH_TTL_S = 30 * 24 * 3600
MAX_DCR_CLIENTS = 64


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
    parsed = urlparse(uri)
    if parsed.scheme == "https":
        return bool(parsed.netloc) and not parsed.fragment
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        return host in {"localhost", "127.0.0.1", "::1"} and not parsed.fragment
    # Custom schemes used by some native clients (ChatGPT uses https callbacks).
    return bool(parsed.scheme) and bool(parsed.netloc or parsed.path) and not parsed.fragment


@dataclass
class RegisteredClient:
    client_id: str
    redirect_uris: list[str]
    client_name: str | None
    token_endpoint_auth_method: str
    grant_types: list[str]
    response_types: list[str]
    issued_at: int


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
class OAuthService:
    """In-memory single-user OAuth AS + RS validation store."""

    config: RelayConfig
    clients: dict[str, RegisteredClient] = field(default_factory=dict)
    codes: dict[str, AuthCode] = field(default_factory=dict)
    access_tokens: dict[str, AccessToken] = field(default_factory=dict)
    refresh_tokens: dict[str, RefreshToken] = field(default_factory=dict)
    pending: dict[str, PendingAuthorization] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

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

    def register_client(self, body: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if len(self.clients) >= MAX_DCR_CLIENTS:
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
            issued_at = int(time.time())
            name = body.get("client_name")
            client = RegisteredClient(
                client_id=client_id,
                redirect_uris=cleaned,
                client_name=name if isinstance(name, str) else None,
                token_endpoint_auth_method="none",
                grant_types=list(grant_types),
                response_types=["code"],
                issued_at=issued_at,
            )
            self.clients[client_id] = client
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
            self.pending[request_id] = pending
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
        self, *, request_id: str, owner_secret: str, decision: str
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

        expected = self.config.owner_approval_secret or ""
        if not expected or not secrets.compare_digest(owner_secret, expected):
            # Re-queue so a typo does not burn the request; recreate pending.
            with self._lock:
                self.pending[request_id] = pending
            raise OAuthError("access_denied", "invalid owner approval secret", status=401)

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
                return
            if hint in {"", "refresh_token"} and token in self.refresh_tokens:
                self.refresh_tokens[token].revoked = True
                return
            if token in self.access_tokens:
                self.access_tokens[token].revoked = True
            if token in self.refresh_tokens:
                self.refresh_tokens[token].revoked = True
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

    def www_authenticate(self, *, error: str | None = None, scope: str | None = None) -> str:
        metadata = f"{self.issuer}/.well-known/oauth-protected-resource"
        parts = [f'Bearer resource_metadata="{metadata}"']
        parts.append(f'scope="{scope or DEFAULT_SCOPE}"')
        if error:
            parts.append(f'error="{error}"')
        return ", ".join(parts)
