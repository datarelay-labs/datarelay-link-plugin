# Auth design seam

This module defines the **binding seam** between ChatGPT/Plugin identity and
explicitly connected upstream DRLink MCP servers.

## Modes

| Mode | Env | Intended use |
| --- | --- | --- |
| `mock` (default) | `DRLINK_RELAY_AUTH_MODE=mock` | Loopback / local tests with `DRLINK_RELAY_MOCK_PLUGIN_TOKEN` |
| `oauth` | `DRLINK_RELAY_AUTH_MODE=oauth` | OAuth 2.1 for ChatGPT Plus. Each approval mints a Plugin subject. |

## Responsibilities

- Map an inbound Plugin / ChatGPT credential to that subject's active connected DRLink server.
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
- Account brokerage or billing. Subject bindings are connection state only.

## OAuth PoC constraints

- Exactly one configured owner approval secret (`DRLINK_RELAY_OWNER_APPROVAL_SECRET`).
- OAuth mode does not read `DRLINK_RELAY_UPSTREAM_URL`, its resolved addresses,
  or `DRLINK_RELAY_UPSTREAM_TOKEN`. Those settings are mock-mode-only.
  A subject with no connected server fails closed. There is no process-global
  upstream fallback.
  A subject connects a server with `POST /bindings` (`upstream_url`, optional
  `upstream_token`). The relay pins that server's addresses, stores the bearer
  only in the durable state file, and never returns it. `GET /bindings` lists
  id, host, connected, and active. `POST /bindings/{id}/activate` selects the
  server used when `X-DRLink-Server-Binding` is absent.
  `POST /bindings/{id}/disconnect` deletes that binding, frees its slot, and
  purges the stored upstream bearer. The denial survives restart because the
  record is gone.
  A subject cannot resolve, activate, or disconnect another subject's binding.
- Mock mode requires `DRLINK_RELAY_UPSTREAM_URL` at process start. OAuth mode
  starts without it.
- Durable state schema v2 (`DRLINK_RELAY_OAUTH_STATE_PATH`) persists DCR
  clients, refresh/revocation records, and `server_bindings`. v1 files load as
  v2 with an empty binding map and are rewritten on the next save.
  Public/non-loopback OAuth requires the state file.
- Loopback OAuth tests may set `DRLINK_RELAY_OAUTH_ALLOW_EPHEMERAL=1` instead of a
  state file; ephemeral mode is not allowed for public listeners.
- Access tokens and authorization codes remain short-lived/ephemeral; reconnect
  uses persisted refresh tokens.
- Unactivated DCR clients (no live refresh binding) have a short TTL, a separate
  inactive-client cap, and are evicted oldest-first at capacity; clients with a
  live non-revoked refresh token are not evicted by ordinary cleanup.
- Pending authorize requests are in-memory only, expire with the auth-code TTL,
  are swept before admit, and are capped globally and per-client. Unexpired
  pending is never evicted to admit a new unauthenticated authorize (including
  same-public-client churn); excess requests are rejected/throttled so a live
  owner consent remains approvable. Per-source authorize create rate limits
  further bound churn.
- Clients referenced by an unexpired pending authorization are not removed by
  inactive DCR cleanup (no durable authorize touch / fsync).
- Authorize validation does not update durable `last_used_at` / fsync state;
  durable client touch happens on successful owner approval and token issuance.
- DCR registration and owner-approval failures are rate-limited per source address;
  idle rate-limit source buckets are pruned and the distinct-source map is capped.
- Production OAuth mode never falls back to mock bearer tokens.
- Non-loopback listeners should use `oauth` mode; mock on public bind remains a
  Packet 1 unsafe override only (`DRLINK_RELAY_ALLOW_NON_LOOPBACK_BIND=1` +
  explicit non-default mock token).
- CIMD is deferred; this PoC advertises DCR only.
