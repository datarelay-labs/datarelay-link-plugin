# Architecture — ChatGPT Plus Plugin + MCP relay

```
ChatGPT Plus
  -> DataRelay Link Plugin (this repo: plugin.json / mcp.json)
  -> shared public DataRelay MCP relay (PoC: local relay; future: mcp.datarelay.run)
  -> bound customer DRLink Server (upstream MCP)
  -> DRLink AI Identity / AI Access
  -> Managed Host
```

## Boundaries

| Layer | Owns | Does not own |
| --- | --- | --- |
| Plugin package | Install identity, remote MCP declaration | Authorization, host access |
| Relay (this repo) | Transport, single-user binding seam, audit | Tool invention, authz decisions |
| DRLink Server (`datarelay-labs/datarelay-link`) | Final per-call AI Access | ChatGPT packaging |

This repository must not modify `datarelay-labs/datarelay-link`. Core MCP interoperability (initialize, annotations, OAuth securitySchemes, challenge metadata) continues in that repo (tracked separately, e.g. issue #47). The relay treats upstream as an opaque Streamable HTTP MCP peer.

## Packet 1 relay contract

- Exactly one configured upstream DRLink MCP URL.
- Pass-through of `initialize`, `tools/list`, `tools/call`, and JSON-RPC errors.
- Preserve JSON-RPC `id` / result / error payloads.
- Preserve/forward MCP protocol headers (`Mcp-Session-Id`, `Last-Event-ID`, `Accept`, `Content-Type`).
- Fail closed when upstream is missing, invalid, or unreachable.
- Health endpoint is separate from `/mcp` and never exposes secrets.
- Auth seam: Plugin-side identity → binding → upstream credential exchange.

## Packet 2 auth contract (single-user OAuth 2.1)

- Auth modes: `mock` (loopback/local) and `oauth` (ChatGPT-compatible PoC).
- OAuth mode hosts `/.well-known/oauth-protected-resource` and
  `/.well-known/oauth-authorization-server` on the relay origin.
- Built-in AS: Authorization Code + PKCE S256, DCR (public clients), token +
  revoke endpoints, durable client/refresh state, per-source abuse limits, and
  owner consent UI gated by runtime approval secret.
- Access tokens are resource-bound to the configured MCP canonical URL and
  validated on every `/mcp` request; inbound ChatGPT tokens are never forwarded
  upstream.
- Unauthenticated `/mcp` requests in OAuth mode return `401` with
  `WWW-Authenticate` `resource_metadata` (RFC 9728).
