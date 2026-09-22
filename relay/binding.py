"""Plugin identity ↔ upstream binding seam (mock + OAuth)."""

from __future__ import annotations

from dataclasses import dataclass

from .config import AUTH_MODE_MOCK, AUTH_MODE_OAUTH, RelayConfig
from .oauth import OAuthError, OAuthService


class BindingError(PermissionError):
    """Inbound identity is not bound to an upstream."""

    def __init__(self, message: str, *, status: int = 401) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class UpstreamBinding:
    binding_id: str
    upstream_url: str
    upstream_connect_ips: tuple[str, ...]
    allow_loopback_upstream: bool
    upstream_authorization: str | None
    plugin_subject: str


def _upstream_binding(config: RelayConfig, *, binding_id: str, subject: str) -> UpstreamBinding:
    upstream_auth = None
    if config.upstream_token:
        upstream_auth = f"Bearer {config.upstream_token}"
    return UpstreamBinding(
        binding_id=binding_id,
        upstream_url=config.upstream_url,
        upstream_connect_ips=config.upstream_connect_ips,
        allow_loopback_upstream=config.allow_loopback_upstream,
        upstream_authorization=upstream_auth,
        plugin_subject=subject,
    )


class MockBindingStore:
    """Single-user mock binding for local PoC only.

    This is intentionally impossible to mistake for production: it only accepts
    a configured mock plugin token and returns the configured upstream.
    """

    def __init__(self, config: RelayConfig) -> None:
        self._config = config
        self._revoked: set[str] = set()
        self._binding_id = "mock-binding-1"
        self._subject = "mock-plugin-user"

    def resolve(self, authorization_header: str | None) -> UpstreamBinding:
        if self._binding_id in self._revoked:
            raise BindingError("binding revoked")

        expected = f"Bearer {self._config.mock_plugin_token}"
        # Local PoC also allows missing Authorization when using the mock token
        # as an explicit anonymous local mode is unsafe; require the mock bearer.
        if authorization_header != expected:
            raise BindingError("unbound or invalid plugin identity")

        return _upstream_binding(
            self._config, binding_id=self._binding_id, subject=self._subject
        )

    def revoke(self, binding_id: str) -> None:
        self._revoked.add(binding_id)

    def reconnect(self, binding_id: str) -> None:
        self._revoked.discard(binding_id)


class BindingResolver:
    """Resolve inbound ChatGPT/Plugin credentials to the single upstream binding.

    OAuth mode never falls back to the mock plugin token.
    """

    def __init__(self, config: RelayConfig, oauth: OAuthService | None = None) -> None:
        self._config = config
        self._mock = MockBindingStore(config)
        self._oauth = oauth

    @property
    def mock(self) -> MockBindingStore:
        return self._mock

    @property
    def oauth(self) -> OAuthService | None:
        return self._oauth

    def resolve(self, authorization_header: str | None) -> UpstreamBinding:
        if self._config.auth_mode == AUTH_MODE_OAUTH:
            if self._oauth is None:
                raise BindingError("oauth not configured")
            # Never accept mock bearer tokens in production OAuth mode.
            try:
                token = self._oauth.validate_bearer(authorization_header)
            except OAuthError as exc:
                raise BindingError(str(exc), status=exc.status) from exc
            return _upstream_binding(
                self._config,
                binding_id="oauth-binding-1",
                subject=token.subject,
            )

        if self._config.auth_mode == AUTH_MODE_MOCK:
            return self._mock.resolve(authorization_header)

        raise BindingError("unsupported auth mode")
