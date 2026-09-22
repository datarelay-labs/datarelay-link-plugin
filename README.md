# datarelay-link-plugin

ChatGPT Plus / Codex **Agent Plugins** package and single-user MCP relay PoC for [DataRelay Link](https://github.com/datarelay-labs/datarelay-link).

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
| `plugin.json` / `mcp.json` | Portable Agent Plugins package (Remote MCP-only) |
| `relay/` | Single-user Streamable HTTP MCP relay PoC |
| `schemas/` | Vendored Agent Plugins JSON Schemas for local validation |
| `docs/` | Architecture, auth seam, verified OpenAI assumptions |
| `.engineering/` | DataRelay Engineering System adoption |

## Local relay (PoC)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Terminal A: mock or real upstream MCP (example uses tests' contract)
export DRLINK_RELAY_UPSTREAM_URL="http://127.0.0.1:9000/mcp"
export DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM=1
export DRLINK_RELAY_UPSTREAM_TOKEN="replace-me"
export DRLINK_RELAY_MOCK_PLUGIN_TOKEN="dev-plugin-token"
export DRLINK_RELAY_BIND=127.0.0.1
export DRLINK_RELAY_PORT=8741

PYTHONPATH=. python3 -m relay
```

Health: `GET http://127.0.0.1:8741/health`

MCP: `POST http://127.0.0.1:8741/mcp` with `Authorization: Bearer dev-plugin-token`

The default mock token is loopback-only. Non-loopback bind requires both `DRLINK_RELAY_ALLOW_NON_LOOPBACK_BIND=1` and an explicit non-default `DRLINK_RELAY_MOCK_PLUGIN_TOKEN`.

`mcp.json` points at the local PoC relay URL. Production HTTPS (`mcp.datarelay.run`) is out of scope for Packet 1.

## Tests

```bash
pip install -r requirements-dev.txt
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

## Auth seam

Packet 1 includes a **dev-only mock binding** (`relay/binding.py`). See [docs/auth-seam.md](docs/auth-seam.md). Do not treat mock tokens as production credentials.

## Security constraints

- Never commit OAuth client secrets, upstream tokens, or DRLink private keys.
- Relay audit logs redact `Authorization` and token-like fields.
- Upstream URL is an explicit allowlisted binding with SSRF-resistant validation.
- Upstream TCP connects use bind-time resolved IPs (DNS-rebinding / TOCTOU resistant); HTTPS keeps hostname SNI/certificate verification.
- No generic open proxy; unbound identities are rejected.
