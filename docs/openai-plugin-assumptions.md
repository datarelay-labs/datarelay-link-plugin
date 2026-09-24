# Verified OpenAI / Agent Plugins assumptions

Sources consulted (official only):

- [Package your plugin](https://developers.openai.com/plugins/build/plugins) (OpenAI Developers)
- [Build an MCP server](https://developers.openai.com/plugins/build/mcp-server) (OpenAI Developers)
- [Authentication (Apps SDK / Plugins)](https://developers.openai.com/apps-sdk/build/auth) (OpenAI Developers)
- [Apps SDK quickstart](https://developers.openai.com/apps-sdk/quickstart) (OpenAI Developers)
- [Agent Plugins specification 1.0.0](https://agent-plugins.org/specification)
- [MCP Authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)

Recorded: 2026-09-24 from the official Package your plugin page.

## Packaging

Fetched page behavior:

1. The portable package entry is root `plugin.json` plus optional root `mcp.json`. OpenAI install-surface metadata may live in `extensions.com.openai.interface`, including `defaultPrompt`.
2. `.codex-plugin/plugin.json` is the plugin-creator compatibility overlay. It supplies OpenAI settings only when root `plugin.json` has no `extensions.com.openai` object. When that object is present, it replaces the overlay entirely; the two are not merged.
3. The scaffold can also emit root `.mcp.json` and `.app.json`. `.app.json` maps a portal-registered `plugin_asdk_app` id. Portable `mcp.json` must declare a transport `type`. Renaming `.mcp.json` to `mcp.json` without `type` drops the transport.
4. Public submission uses one Universal public HTTPS MCP URL. This product does not use a template URL.

Repository contract for this phase:

1. OpenAI install-surface metadata is `.codex-plugin/plugin.json` with documented top-level `interface` fields. Root `plugin.json` omits `extensions` so that overlay stays active.
2. The overlay does not set `apps` or `mcpServers`. Current docs use `apps` for a real `.app.json` mapping created only after ChatGPT developer mode registers an MCP connection and returns a `plugin_asdk_app` id. This repository does not invent that id, and it does not commit `.app.json`.
3. Current docs do not show a remote `streamable-http` object inside `.mcp.json`. That file is omitted. Portable remote MCP, including transport `type`, is root `mcp.json`. The committed URL is the local PoC (`http://127.0.0.1:8741/mcp`).
4. A production URL is an input to `scripts/submission-readiness.py`. Missing owner input is BLOCKED. An explicitly supplied URL is FAIL when it is not HTTPS, not exactly `/mcp`, has a query or fragment, embeds credentials, or uses a loopback, private, link-local, metadata, or reserved literal address. The checker does not probe DNS. Hostname reachability stays BLOCKED.
5. `package_layout` is PASS only when that registered app mapping is actually wired. Until then it stays OWNER/PLATFORM BLOCKED. `repository_checks_ok` can still be true. `submission_ready` stays false, and `overall_status` stays BLOCKED, while any submission prerequisite is BLOCKED.
6. `privacyPolicyURL` and `termsOfServiceURL` are omitted until the owner approves public legal pages.
7. This repository does not create DNS, activate a live challenge token, or submit the plugin. It ships no skills and no custom UI.

## MCP wire behavior

1. Streamable HTTP uses a single endpoint supporting `POST` (and optionally `GET` for SSE).
2. Clients send `Accept: application/json, text/event-stream`.
3. Session continuity uses `Mcp-Session-Id` when returned on initialize.
4. Tool metadata (name, description, inputSchema, annotations, securitySchemes) is part of the contract and must pass through unchanged by a relay.
5. Authorization is enforced by the MCP server on every tool call; a relay must not reinterpret or cache authz decisions.

## OAuth / authentication (Packet 2)

1. Authenticated remote MCP servers must implement OAuth 2.1 per the MCP authorization spec.
2. Host protected resource metadata at `/.well-known/oauth-protected-resource` (and/or advertise it via `WWW-Authenticate` on `401`).
3. Publish authorization-server metadata (`/.well-known/oauth-authorization-server` or OIDC discovery).
4. Authorization Code + PKCE with `S256` is required; advertise `code_challenge_methods_supported: ["S256"]`.
5. Echo the `resource` parameter (RFC 8707) through authorize and token requests; validate audience on each MCP request.
6. Client identification options: CIMD, DCR, or predefined clients. This PoC implements **DCR** only; CIMD is a later optimization.
7. ChatGPT tool linking also expects per-tool `securitySchemes` plus runtime `_meta["mcp/www_authenticate"]` from the **upstream** MCP server for tool-level linking UI; the relay must pass those through unchanged. When the relay itself rejects an unauthenticated/insufficient-scope MCP JSON-RPC request, it emits HTTP 401/403 with a Bearer `WWW-Authenticate` challenge (`resource_metadata`, `scope`, `error`, `error_description`) and a coherent `_meta["mcp/www_authenticate"]` payload so ChatGPT can surface connect/reconnect UI.

## DataRelay Link Plugin implications

1. This repository publishes the ChatGPT Plus-facing Plugin package and a public relay seam.
2. Upstream DRLink Server remains the authorization source of truth on every `tools/call`.
3. The committed package URL is the local PoC. Production HTTPS and Plugin Directory submission stay owner-gated. `scripts/submission-readiness.py` reports those gates as BLOCKED until the owner supplies them.
