# Auth design seam

This module defines the **binding seam** between ChatGPT/Plugin identity and a
single upstream DRLink MCP server.

## Modes

| Mode | Env | Intended use |
| --- | --- | --- |
| `mock` (default) | `DRLINK_RELAY_AUTH_MODE=mock` | Loopback / local tests with `DRLINK_RELAY_MOCK_PLUGIN_TOKEN` |
| `oauth` | `DRLINK_RELAY_AUTH_MODE=oauth` | Single-user OAuth 2.1 PoC for ChatGPT Plus connection |

Future multi-user / production identity service is out of scope.

## Responsibilities

- Map an inbound Plugin / ChatGPT credential to exactly one upstream binding.
- Supply upstream Authorization credentials without exposing DRLink private
  keys or long-lived server secrets to ChatGPT.
- In OAuth mode: host protected-resource metadata, a built-in authorization
  server (Authorization Code + PKCE S256 + DCR), and per-request token
  validation (issuer/resource/expiry/scope).
- Support disconnect/revoke of the mock binding; OAuth access/refresh revoke
  via `/oauth/revoke`.

## Non-responsibilities

- DRLink AI Access evaluation (owned by upstream DRLink Server).
- Inventing or filtering tools.
- Caching authorization decisions across tool calls.
- Multi-tenant account brokerage or billing.

## OAuth PoC constraints

- Exactly one configured owner approval secret (`DRLINK_RELAY_OWNER_APPROVAL_SECRET`).
- Exactly one configured upstream DRLink binding.
- No tenant database; in-memory clients/tokens for PoC only.
- Production OAuth mode never falls back to mock bearer tokens.
- Non-loopback listeners should use `oauth` mode; mock on public bind remains a
  Packet 1 unsafe override only (`DRLINK_RELAY_ALLOW_NON_LOOPBACK_BIND=1` +
  explicit non-default mock token).
- CIMD is deferred; this PoC advertises DCR only.
