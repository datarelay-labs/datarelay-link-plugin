# datarelay-link-plugin

ChatGPT Plus / Codex **Agent Plugins** package and MCP relay for [DataRelay Link](https://github.com/datarelay-labs/datarelay-link).

> **License — Source Available:** licensed under the **Data Relay Source Available License 1.0** (not Apache-2.0 / not OSI open source). See [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md).

Core DRLink continues to work without this repository. Direct DRLink MCP remains supported for clients that allow arbitrary remote MCP endpoints. This repo exists so **ChatGPT Plus** can use DataRelay Link through a published Plugin/App path.

## Architecture

```
ChatGPT Plus
  -> DataRelay Link Plugin
  -> MCP relay (this repo)
  -> bound DRLink Server MCP
  -> DRLink AI Access
  -> Managed Host
```

The relay is transport/binding only. **DRLink Server remains the final authorization source of truth on every tool call.**

See [docs/architecture.md](docs/architecture.md) and [docs/openai-plugin-assumptions.md](docs/openai-plugin-assumptions.md).

## Repository layout

| Path | Purpose |
| --- | --- |
| `plugin.json` | Canonical portable Agent Plugins manifest. OpenAI settings are under `extensions.com.openai` |
| `.codex-plugin/plugin.json` | Compatibility fallback. OpenAI ignores it when the root extension object is present |
| `mcp.json` | Portable MCP configuration (`streamable-http`). The committed URL is the local PoC |
| `docs/submission/review-cases.json` | Exactly 5 positive and 3 negative reviewer fixtures |
| `relay/` | Streamable HTTP MCP relay. Mock mode is single-upstream; OAuth mode binds each Plugin subject to explicitly connected DRLink servers. |
| `schemas/` | Vendored Agent Plugins JSON Schemas for local validation |
| `docs/` | Architecture, auth seam, verified OpenAI assumptions |
| `.engineering/` | DataRelay Engineering System adoption |

## Local relay (PoC)

### Mock mode (loopback / local tests)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export DRLINK_RELAY_UPSTREAM_URL="http://127.0.0.1:9000/mcp"
export DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM=1
export DRLINK_RELAY_UPSTREAM_TOKEN="replace-me"
export DRLINK_RELAY_AUTH_MODE=mock
export DRLINK_RELAY_MOCK_PLUGIN_TOKEN="dev-plugin-token"
export DRLINK_RELAY_BIND=127.0.0.1
export DRLINK_RELAY_PORT=8741

PYTHONPATH=. python3 -m relay
```

MCP: `POST http://127.0.0.1:8741/mcp` with `Authorization: Bearer dev-plugin-token`

### OAuth mode

OAuth does not use a process-global upstream URL or token. Each Plugin subject
connects its own DRLink server after authentication. Set
`DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM=1` only when a subject will connect a
loopback DRLink server.

```bash
export DRLINK_RELAY_AUTH_MODE=oauth
export DRLINK_RELAY_PUBLIC_BASE_URL="http://127.0.0.1:8741"
export DRLINK_RELAY_OWNER_APPROVAL_SECRET="replace-with-long-runtime-secret"
export DRLINK_RELAY_OAUTH_STATE_PATH="/var/lib/datarelay-link-plugin/oauth-state.json"
export DRLINK_RELAY_BIND=127.0.0.1
export DRLINK_RELAY_PORT=8741

PYTHONPATH=. python3 -m relay
```

For local ephemeral tests only (loopback), set
`DRLINK_RELAY_OAUTH_ALLOW_EPHEMERAL=1` instead of a state path. Public / non-loopback
OAuth always requires a durable state file (mode `0600`, parent dir not
group/world-writable).

Discovery:

- `GET /.well-known/oauth-protected-resource`
- `GET /.well-known/oauth-authorization-server`

Owner consent uses the runtime approval secret (never commit it). After the
Plugin subject has an access token, connect that subject's DRLink server:

```bash
curl -sS -X POST "$DRLINK_RELAY_PUBLIC_BASE_URL/bindings" \
  -H "Authorization: Bearer $PLUGIN_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"upstream_url":"https://customer-drlink.example/mcp","upstream_token":"replace-me"}'
```

OAuth `/mcp` calls use that connected server. A subject with no connected
server is rejected. `DRLINK_RELAY_UPSTREAM_URL` and
`DRLINK_RELAY_UPSTREAM_TOKEN` are mock-mode settings and are not read in OAuth
mode. Public HTTPS
deployment URLs remain configurable; this repo does not claim public Plugin
availability.

Health: `GET /health` (reports `auth_mode`, never secrets).

The default mock token is loopback-only. Non-loopback bind should use `oauth`
mode. Legacy mock-on-public requires both `DRLINK_RELAY_ALLOW_NON_LOOPBACK_BIND=1`
and an explicit non-default `DRLINK_RELAY_MOCK_PLUGIN_TOKEN`.

`mcp.json` points at the local PoC relay URL and declares `streamable-http`.
There is no `.mcp.json` and no `.app.json`. This repository does not invent a
`plugin_asdk_app` id. Production HTTPS and Plugin Directory submission are not
performed from this repository. Check readiness without contacting OpenAI:

```bash
python3 scripts/submission-readiness.py --mode local
python3 scripts/submission-readiness.py --mode submission
python3 scripts/submission-readiness.py --mode submission --mcp-url https://mcp.example/mcp
```

Repository-controlled checks can pass while owner and platform gates stay
BLOCKED. The process exits 0 only when `submission_ready` is true. A missing
production MCP URL is BLOCKED. A supplied URL fails when it is not public HTTPS
`/mcp` without a query, fragment, credential, or private literal address.
Hostname reachability is not probed.
`overall_status` stays BLOCKED while any submission prerequisite is BLOCKED.
Domain verification, when a portal token is provided at runtime only, is
`GET /.well-known/openai-apps-challenge`
(`DRLINK_RELAY_OPENAI_APPS_CHALLENGE`). No token is committed.

## Tests

```bash
pip install -r requirements-dev.txt
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

## Auth seam

See [docs/auth-seam.md](docs/auth-seam.md) for mock vs single-user OAuth PoC vs
future multi-user identity. Do not treat mock tokens as production credentials.

## Security constraints

- Never commit OAuth client secrets, upstream tokens, or DRLink private keys.
- Relay audit logs redact `Authorization` and token-like fields.
- Upstream URL is an explicit allowlisted binding with SSRF-resistant validation.
- Upstream TCP connects use bind-time resolved IPs (DNS-rebinding / TOCTOU resistant); HTTPS keeps hostname SNI/certificate verification.
- No generic open proxy; unbound identities are rejected.
