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
- Durable OAuth state (`DRLINK_RELAY_OAUTH_STATE_PATH`) persists DCR clients and
  refresh/revocation records across restarts; public/non-loopback OAuth requires it.
- Loopback OAuth tests may set `DRLINK_RELAY_OAUTH_ALLOW_EPHEMERAL=1` instead of a
  state file; ephemeral mode is not allowed for public listeners.
- Access tokens and authorization codes remain short-lived/ephemeral; reconnect
  uses persisted refresh tokens.
- Unactivated DCR clients (no live refresh binding) have a short TTL, a separate
  inactive-client cap, and are evicted oldest-first at capacity; clients with a
  live non-revoked refresh token are not evicted by ordinary cleanup.
- Pending authorize requests are in-memory only, expire with the auth-code TTL,
  are swept before admit, and are capped with oldest-first eviction so
  unauthenticated authorize churn cannot grow memory or lock out ChatGPT.
- Authorize validation does not update durable `last_used_at` / fsync state;
  durable client touch happens on successful owner approval and token issuance.
- DCR registration and owner-approval failures are rate-limited per source address;
  idle rate-limit source buckets are pruned and the distinct-source map is capped.
- Production OAuth mode never falls back to mock bearer tokens.
- Non-loopback listeners should use `oauth` mode; mock on public bind remains a
  Packet 1 unsafe override only (`DRLINK_RELAY_ALLOW_NON_LOOPBACK_BIND=1` +
  explicit non-default mock token).
- CIMD is deferred; this PoC advertises DCR only.
