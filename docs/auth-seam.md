# Auth design seam (Packet 1)

This module defines the **binding seam** between ChatGPT/Plugin identity and a
single upstream DRLink MCP server. Packet 1 ships a **dev-only mock** binding.

Production identity/account service, multi-tenant brokerage, and real OAuth
token exchange are out of scope.

## Responsibilities

- Map an inbound Plugin bearer token (or anonymous local-dev token) to exactly
  one upstream binding.
- Supply upstream Authorization credentials without exposing DRLink private
  keys or long-lived server secrets to ChatGPT.
- Support disconnect/revoke of the mock binding.

## Non-responsibilities

- DRLink AI Access evaluation (owned by upstream DRLink Server).
- Inventing or filtering tools.
- Caching authorization decisions across tool calls.
