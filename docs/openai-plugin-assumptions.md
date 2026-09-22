# Verified OpenAI / Agent Plugins assumptions (Packet 1)

Sources consulted (official only):

- [Package your plugin](https://developers.openai.com/plugins/build/plugins) (OpenAI Developers)
- [Build an MCP server](https://developers.openai.com/plugins/build/mcp-server) (OpenAI Developers)
- [Apps SDK quickstart](https://developers.openai.com/apps-sdk/quickstart) (OpenAI Developers)
- [Agent Plugins specification 1.0.0](https://agent-plugins.org/specification)
- [MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)

Recorded: 2026-09-22.

## Packaging

1. **Portable Agent Plugins** is the current packaging floor: root `plugin.json` + optional `mcp.json` + optional `skills/`.
2. Do **not** assume legacy ChatGPT Plugin format (`ai-plugin.json` + OpenAPI) unless a future official doc requires it. Current docs use Agent Plugins / Apps SDK MCP.
3. OpenAI-specific install-surface metadata lives under `extensions.com.openai` in root `plugin.json` (or legacy `.codex-plugin/plugin.json` as fallback).
4. Remote MCP servers are declared in root `mcp.json` with `type: "streamable-http"` and an absolute `url`.
5. Literal credentials must **not** appear in `mcp.json` headers; OAuth / credential storage is client-managed in Agent Plugins v1.
6. Public submission requires a stable public **HTTPS** MCP endpoint (typically ending in `/mcp`). Local/dev may use loopback HTTP for PoC only.
7. Custom UI / skills are optional for Remote MCP-only plugins. Packet 1 ships no skills and no custom UI.

## MCP wire behavior

1. Streamable HTTP uses a single endpoint supporting `POST` (and optionally `GET` for SSE).
2. Clients send `Accept: application/json, text/event-stream`.
3. Session continuity uses `Mcp-Session-Id` when returned on initialize.
4. Tool metadata (name, description, inputSchema, annotations, securitySchemes) is part of the contract and must pass through unchanged by a relay.
5. Authorization is enforced by the MCP server on every tool call; a relay must not reinterpret or cache authz decisions.

## DataRelay Link Plugin implications

1. This repository publishes the ChatGPT Plus-facing Plugin package and a public relay seam.
2. Upstream DRLink Server remains the authorization source of truth on every `tools/call`.
3. Packet 1 points the package at a **local/dev relay URL**; production `mcp.datarelay.run` and Plugin Directory submission are out of scope.
