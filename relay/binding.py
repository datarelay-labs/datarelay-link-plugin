"""Dev-only Plugin identity ↔ upstream binding seam."""

from __future__ import annotations

from dataclasses import dataclass

from .config import RelayConfig


class BindingError(PermissionError):
    """Inbound identity is not bound to an upstream."""


@dataclass(frozen=True)
class UpstreamBinding:
    binding_id: str
    upstream_url: str
    upstream_authorization: str | None
    plugin_subject: str


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

        upstream_auth = None
        if self._config.upstream_token:
            upstream_auth = f"Bearer {self._config.upstream_token}"

        return UpstreamBinding(
            binding_id=self._binding_id,
            upstream_url=self._config.upstream_url,
            upstream_authorization=upstream_auth,
            plugin_subject=self._subject,
        )

    def revoke(self, binding_id: str) -> None:
        self._revoked.add(binding_id)

    def reconnect(self, binding_id: str) -> None:
        self._revoked.discard(binding_id)
