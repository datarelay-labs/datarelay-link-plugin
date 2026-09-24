# Verified OpenAI / Agent Plugins assumptions

Sources consulted (official only):

- [Package your plugin](https://developers.openai.com/plugins/build/plugins) (OpenAI Developers)
- [Plugin submission errors](https://developers.openai.com/plugins/deploy/submission-errors) (OpenAI Developers)
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

1. The canonical package is root `plugin.json` with the Agent Plugins `$schema`. OpenAI presentation lives under `extensions.com.openai.interface`. `privacyPolicyURL` and `termsOfServiceURL` stay omitted until the owner approves public legal pages.
2. `.codex-plugin/plugin.json` is a compatibility fallback. Its top-level `interface` matches the canonical interface. When `extensions.com.openai` is present, OpenAI replaces the overlay with that object and does not merge the two files. The readiness checker reads interface fields only from the root extension.
3. The extension and the fallback do not set `apps` or `mcpServers`. This repository does not invent a `plugin_asdk_app` id and does not commit `.app.json` or `.mcp.json`.
4. Portable remote MCP is root `mcp.json` with the Agent Plugins MCP schema and `type: streamable-http`. The committed URL is the local PoC (`http://127.0.0.1:8741/mcp`).
5. A production URL is an input to `scripts/submission-readiness.py`. Missing owner input is BLOCKED. An explicitly supplied URL is FAIL when it is not HTTPS, not exactly `/mcp`, has a query or fragment, embeds credentials, or uses a loopback, private, link-local, metadata, or reserved literal address. The checker does not probe DNS. Hostname reachability stays BLOCKED.
6. `package_layout` and `mcp_package_wiring` PASS when that portable contract holds. `repository_checks_ok` can be true while `submission_ready` stays false and `overall_status` stays BLOCKED, because owner and platform prerequisites remain BLOCKED.
7. This repository does not create DNS, activate a live challenge token, or submit the plugin. It ships no skills and no custom UI.
8. Remote MCP final submission requires a demo-recording URL. `demo_recording_url` stays BLOCKED. This repository does not invent a URL or a recording.
9. Reviewer fixtures are exactly five positive cases and three negative cases. Six positive or four negative cases fail the readiness check.
10. `tool_metadata_passthrough` PASS means `RelayTestCase.test_tools_metadata_passthrough_is_unmodified` passed. The checker does not scan source text for annotation names. That result is repository behavioral evidence only.
11. Final MCP submission errors `scan_required`, `annotations_required`, and `justification_required` are separate submission gates. They stay BLOCKED until the owner supplies a tool-scan JSON document. PASS requires `scan_status=success`, a timezone-aware `scanned_at` that is not in the future, the same production MCP URL passed to the checker, a non-empty `tools` list, boolean `readOnlyHint`, `openWorldHint`, and `destructiveHint` on every tool, and a non-empty justification for each of those hints. The checker does not contact the production server and does not treat unit tests or source text as a scan.

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
