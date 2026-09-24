"""HTTP server exposing /mcp, OAuth discovery/endpoints, and /health."""

from __future__ import annotations

import json
import logging
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .audit import audit_event, configure_logging
from .binding import BindingError, BindingResolver
from .config import AUTH_MODE_OAUTH, RelayConfig
from .oauth import OAuthError, OAuthService, PendingAuthorization
from .proxy import UpstreamUnavailable, proxy_mcp_request
from .tenant_bindings import TenantBindingRegistry

_BINDING_ID_RE = re.compile(r"^bnd_[A-Za-z0-9_-]{8,128}$")
_BINDING_BODY_LIMIT = 8192


class RelayHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        config: RelayConfig,
        bindings: BindingResolver,
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

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

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

    def _send_redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _oauth(self) -> OAuthService | None:
        return self.server.bindings.oauth

    def _require_oauth(self) -> OAuthService:
        oauth = self._oauth()
        if oauth is None:
            raise OAuthError("invalid_request", "oauth not enabled", status=404)
        return oauth

    def _parse_form(self, raw: bytes) -> dict[str, str]:
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type == "application/json":
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError as exc:
                raise OAuthError("invalid_request", "malformed JSON body") from exc
            if not isinstance(payload, dict):
                raise OAuthError("invalid_request", "JSON body must be an object")
            return {str(k): "" if v is None else str(v) for k, v in payload.items()}
        # Default: application/x-www-form-urlencoded
        parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        return {k: (v[-1] if v else "") for k, v in parsed.items()}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._handle_health()
            return
        if path == "/.well-known/oauth-protected-resource":
            self._handle_protected_resource_metadata()
            return
        if path == "/.well-known/oauth-authorization-server":
            self._handle_authorization_server_metadata()
            return
        if path == "/oauth/authorize":
            self._handle_authorize_get(parse_qs(parsed.query))
            return
        if path == "/mcp":
            self._handle_mcp("GET")
            return
        if path == "/bindings":
            self._handle_bindings_list()
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/oauth/register":
            self._handle_register()
            return
        if path == "/oauth/authorize":
            self._handle_authorize_post()
            return
        if path == "/oauth/token":
            self._handle_token()
            return
        if path == "/oauth/revoke":
            self._handle_revoke()
            return
        if path == "/mcp":
            self._handle_mcp("POST")
            return
        if path == "/bindings":
            self._handle_bindings_connect()
            return
        action = _binding_action(path)
        if action is not None:
            binding_id, name = action
            self._handle_binding_action(binding_id, name)
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
        config = self.server.relay_config
        self._send_json(
            200,
            {
                "status": "ok",
                "service": "datarelay-link-relay",
                "version": __version__,
                "mcp_path": "/mcp",
                "auth_mode": config.auth_mode,
            },
        )

    def _handle_protected_resource_metadata(self) -> None:
        try:
            oauth = self._require_oauth()
        except OAuthError:
            self._send_json(404, {"error": "not_found"})
            return
        self._send_json(200, oauth.protected_resource_metadata())

    def _handle_authorization_server_metadata(self) -> None:
        try:
            oauth = self._require_oauth()
        except OAuthError:
            self._send_json(404, {"error": "not_found"})
            return
        self._send_json(200, oauth.authorization_server_metadata())

    def _client_source(self) -> str:
        host = self.client_address[0] if self.client_address else "unknown"
        return host or "unknown"

    def _handle_register(self) -> None:
        logger = self.server.audit_logger
        try:
            oauth = self._require_oauth()
            raw = self._read_body()
            form = self._parse_form(raw)
            # DCR expects JSON; accept form too for robustness.
            if "redirect_uris" in form and isinstance(form["redirect_uris"], str):
                # If JSON was parsed, redirect_uris may already be list via json path.
                pass
            # Prefer raw JSON object for list fields.
            content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if content_type == "application/json":
                body = json.loads(raw.decode("utf-8") or "{}")
            else:
                body = {
                    "redirect_uris": [
                        u for u in form.get("redirect_uris", "").split() if u
                    ],
                    "client_name": form.get("client_name") or None,
                    "token_endpoint_auth_method": form.get(
                        "token_endpoint_auth_method", "none"
                    ),
                }
            result = oauth.register_client(
                body if isinstance(body, dict) else {},
                source=self._client_source(),
            )
            audit_event(logger, "oauth_client_registered", client_id=result["client_id"])
            self._send_json(201, result)
        except OAuthError as exc:
            audit_event(
                logger,
                "oauth_register_denied",
                reason=exc.error,
                source=self._client_source(),
            )
            self._send_json(
                exc.status,
                {"error": exc.error, "error_description": exc.description},
            )
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"error": "invalid_request"})

    def _qs_first(self, qs: dict[str, list[str]]) -> dict[str, str]:
        return {k: (v[-1] if v else "") for k, v in qs.items()}

    def _handle_authorize_get(self, qs: dict[str, list[str]]) -> None:
        logger = self.server.audit_logger
        try:
            oauth = self._require_oauth()
            params = self._qs_first(qs)
            result = oauth.begin_authorization(params, source=self._client_source())
            if isinstance(result, dict):
                # Error redirect to client.
                from urllib.parse import urlencode, urlparse, urlunparse

                redirect_uri = params.get("redirect_uri", "")
                parsed = urlparse(redirect_uri)
                extra = urlencode(result)
                new_q = f"{parsed.query}&{extra}" if parsed.query else extra
                self._send_redirect(urlunparse(parsed._replace(query=new_q)))
                return
            assert isinstance(result, PendingAuthorization)
            audit_event(
                logger,
                "oauth_authorize_prompt",
                client_id=result.client_id,
                request_id=result.request_id,
            )
            self._send_html(200, oauth.consent_html(result))
        except OAuthError as exc:
            audit_event(logger, "oauth_authorize_denied", reason=exc.error)
            self._send_json(
                exc.status,
                {"error": exc.error, "error_description": exc.description},
            )

    def _handle_authorize_post(self) -> None:
        logger = self.server.audit_logger
        form: dict[str, str] = {}
        try:
            oauth = self._require_oauth()
            form = self._parse_form(self._read_body())
            request_id = form.get("request_id", "")
            decision = form.get("decision", "deny")
            owner_secret = form.get("owner_secret", "")
            location = oauth.complete_authorization(
                request_id=request_id,
                owner_secret=owner_secret,
                decision=decision,
                source=self._client_source(),
            )
            audit_event(
                logger,
                "oauth_authorize_completed",
                request_id=request_id,
                decision="deny" if decision != "approve" else "approve",
            )
            self._send_redirect(location)
        except OAuthError as exc:
            oauth = self._oauth()
            request_id = form.get("request_id", "")
            pending = oauth.pending.get(request_id) if oauth and request_id else None
            if pending is not None and exc.error == "access_denied":
                audit_event(
                    logger,
                    "oauth_owner_auth_failed",
                    request_id=request_id,
                    source=self._client_source(),
                )
                self._send_html(401, oauth.consent_html(pending, error=exc.description))
                return
            audit_event(logger, "oauth_authorize_post_denied", reason=exc.error)
            self._send_json(
                exc.status,
                {"error": exc.error, "error_description": exc.description},
            )
        except ValueError:
            self._send_json(400, {"error": "invalid_request"})

    def _handle_token(self) -> None:
        logger = self.server.audit_logger
        try:
            oauth = self._require_oauth()
            form = self._parse_form(self._read_body())
            result = oauth.exchange_token(form)
            audit_event(
                logger,
                "oauth_token_issued",
                grant_type=form.get("grant_type", ""),
                client_id=form.get("client_id", ""),
            )
            self._send_json(200, result)
        except OAuthError as exc:
            audit_event(logger, "oauth_token_denied", reason=exc.error)
            self._send_json(
                exc.status,
                {"error": exc.error, "error_description": exc.description},
            )
        except ValueError:
            self._send_json(400, {"error": "invalid_request"})

    def _handle_revoke(self) -> None:
        logger = self.server.audit_logger
        try:
            oauth = self._require_oauth()
            form = self._parse_form(self._read_body())
            oauth.revoke(form)
            audit_event(logger, "oauth_token_revoked", hint=form.get("token_type_hint", ""))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except OAuthError as exc:
            self._send_json(
                exc.status,
                {"error": exc.error, "error_description": exc.description},
            )
        except ValueError:
            self._send_json(400, {"error": "invalid_request"})

    def _mcp_auth_challenge_payload(
        self,
        body: bytes,
        *,
        challenge: str,
        description: str,
    ) -> dict[str, Any] | None:
        """Return JSON-RPC auth challenge with `_meta["mcp/www_authenticate"]`.

        Used when an MCP JSON-RPC request is rejected so ChatGPT can surface the
        tool-level connect UI together with upstream ``securitySchemes``.
        Non-JSON-RPC bodies return None (HTTP 401 + WWW-Authenticate only).
        """
        try:
            parsed = json.loads(body.decode("utf-8") or "null")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(parsed, dict) or parsed.get("jsonrpc") != "2.0":
            return None
        text = description.strip() or "authentication required"
        return {
            "jsonrpc": "2.0",
            "id": parsed.get("id"),
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": True,
                "_meta": {"mcp/www_authenticate": [challenge]},
            },
        }

    def _authenticated_subject(self) -> str:
        try:
            return self.server.bindings.require_subject(self.headers.get("Authorization"))
        except BindingError as exc:
            self._send_binding_denied(exc, body=b"")
            return ""

    def _send_binding_denied(self, exc: BindingError, *, body: bytes) -> None:
        config = self.server.relay_config
        logger = self.server.audit_logger
        audit_event(
            logger,
            "binding_access_denied",
            reason=str(exc),
            plugin_subject=exc.subject or "",
            tenant_id=exc.subject or "",
        )
        extra: list[tuple[str, str]] = []
        oauth = self._oauth()
        if config.auth_mode == AUTH_MODE_OAUTH and oauth is not None:
            error = exc.oauth_error or (
                "insufficient_scope" if exc.status == 403 else "invalid_token"
            )
            description = exc.oauth_description or str(exc)
            extra.append(
                (
                    "WWW-Authenticate",
                    oauth.www_authenticate(error=error, error_description=description),
                )
            )
        self._send_json(
            exc.status,
            {"error": "unauthorized", "message": str(exc)},
            extra_headers=extra,
        )

    def _require_tenants(self) -> TenantBindingRegistry | None:
        tenants = self.server.bindings.tenants
        if tenants is None:
            self._send_json(404, {"error": "not_found"})
        return tenants

    def _handle_bindings_list(self) -> None:
        tenants = self._require_tenants()
        if tenants is None:
            return
        subject = self._authenticated_subject()
        if not subject:
            return
        self._send_json(200, {"bindings": tenants.list_bindings(subject)})

    def _handle_bindings_connect(self) -> None:
        logger = self.server.audit_logger
        tenants = self._require_tenants()
        if tenants is None:
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._send_json(400, {"error": "invalid_body"})
            return
        if length < 0 or length > _BINDING_BODY_LIMIT:
            self._send_json(400, {"error": "invalid_body"})
            return
        try:
            raw = self.rfile.read(length) if length else b""
        except ValueError:
            self._send_json(400, {"error": "invalid_body"})
            return
        subject = self._authenticated_subject()
        if not subject:
            return
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeError, json.JSONDecodeError, ValueError):
            self._send_json(400, {"error": "invalid_body"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "invalid_body"})
            return
        allowed = {"upstream_url", "upstream_token"}
        if not set(payload).issubset(allowed) or "upstream_url" not in payload:
            self._send_json(400, {"error": "invalid_body"})
            return
        token = payload.get("upstream_token")
        if token is not None and not isinstance(token, str):
            self._send_json(400, {"error": "invalid_body"})
            return
        url = payload.get("upstream_url")
        if not isinstance(url, str):
            self._send_json(400, {"error": "invalid_body"})
            return
        try:
            view = tenants.connect(
                subject=subject,
                upstream_url=url,
                upstream_token=token,
            )
        except BindingError as exc:
            audit_event(
                logger,
                "binding_connect_denied",
                reason=str(exc),
                plugin_subject=subject,
                tenant_id=subject,
            )
            self._send_json(exc.status, {"error": "invalid_upstream", "message": str(exc)})
            return
        audit_event(
            logger,
            "binding_connected",
            plugin_subject=subject,
            tenant_id=subject,
            binding_id=view["binding_id"],
            upstream_host=view["upstream_host"],
        )
        self._send_json(201, view)

    def _handle_binding_action(self, binding_id: str, action: str) -> None:
        logger = self.server.audit_logger
        tenants = self._require_tenants()
        if tenants is None:
            return
        subject = self._authenticated_subject()
        if not subject:
            return
        try:
            if action == "disconnect":
                view = tenants.disconnect(subject=subject, binding_id=binding_id)
                event = "binding_disconnected"
            else:
                view = tenants.activate(subject=subject, binding_id=binding_id)
                event = "binding_activated"
        except BindingError as exc:
            audit_event(
                logger,
                "binding_action_denied",
                reason=str(exc),
                plugin_subject=subject,
                tenant_id=subject,
                binding_id=binding_id,
            )
            self._send_json(
                exc.status,
                {"error": "binding_unavailable", "message": str(exc)},
            )
            return
        audit_event(
            logger,
            event,
            plugin_subject=subject,
            tenant_id=subject,
            binding_id=binding_id,
            upstream_host=view["upstream_host"],
        )
        self._send_json(200, view)

    def _handle_mcp(self, method: str) -> None:
        config = self.server.relay_config
        logger = self.server.audit_logger
        try:
            body = self._read_body()
        except ValueError:
            self._send_json(400, {"error": "invalid_body"})
            return

        selector = (self.headers.get("X-DRLink-Server-Binding") or "").strip() or None
        try:
            binding = self.server.bindings.resolve(
                self.headers.get("Authorization"),
                binding_selector=selector,
            )
        except BindingError as exc:
            audit_event(
                logger,
                "mcp_binding_denied",
                reason=str(exc),
                method=method,
                plugin_subject=exc.subject or "",
                tenant_id=exc.subject or "",
            )
            extra: list[tuple[str, str]] = []
            oauth = self._oauth()
            if config.auth_mode == AUTH_MODE_OAUTH and oauth is not None:
                error = exc.oauth_error or (
                    "insufficient_scope" if exc.status == 403 else "invalid_token"
                )
                description = exc.oauth_description or str(exc)
                challenge = oauth.www_authenticate(
                    error=error, error_description=description
                )
                extra.append(("WWW-Authenticate", challenge))
                rpc_payload = self._mcp_auth_challenge_payload(
                    body, challenge=challenge, description=description
                )
                if rpc_payload is not None:
                    self._send_json(exc.status, rpc_payload, extra_headers=extra)
                    return
            self._send_json(
                exc.status,
                {"error": "unauthorized", "message": str(exc)},
                extra_headers=extra,
            )
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


def _binding_action(path: str) -> tuple[str, str] | None:
    parts = path.split("/")
    if len(parts) != 4 or parts[1] != "bindings":
        return None
    if parts[3] not in {"disconnect", "activate"}:
        return None
    if not _BINDING_ID_RE.fullmatch(parts[2]):
        return None
    return parts[2], parts[3]


def create_server(config: RelayConfig, logger: logging.Logger | None = None) -> RelayHTTPServer:
    log = logger or configure_logging()
    oauth = OAuthService(config) if config.auth_mode == AUTH_MODE_OAUTH else None
    tenants = None
    if oauth is not None:
        tenants = TenantBindingRegistry(
            allow_loopback=config.allow_loopback_upstream,
            public_base_url=config.public_base_url,
            store=oauth.store,
        )
        oauth.attach_binding_snapshot(tenants.snapshot)
    bindings = BindingResolver(config, oauth, tenants)
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
        auth_mode=config.auth_mode,
        allow_loopback_upstream=config.allow_loopback_upstream,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
