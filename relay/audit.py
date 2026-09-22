"""Structured audit logging with secret redaction."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}

_BEARER_RE = re.compile(r"(?i)(bearer\s+)\S+")
_TOKEN_KV_RE = re.compile(
    r'(?i)("?(?:access_token|refresh_token|id_token|client_secret|api_key|authorization|'
    r'code_verifier|code_challenge|owner_secret|owner_approval_secret|authorization_code)"?'
    r'\s*[:=]\s*)("[^"]*"|\'[^\']*\'|\S+)'
)


def redact_text(value: str) -> str:
    text = _BEARER_RE.sub(r"\1[REDACTED]", value)
    text = _TOKEN_KV_RE.sub(r"\1[REDACTED]", text)
    return text


def sanitize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not headers:
        return out
    for key, value in headers.items():
        if key.lower() in _SENSITIVE_HEADER_NAMES:
            out[key] = "[REDACTED]"
        else:
            out[key] = redact_text(str(value))
    return out


def audit_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    payload: dict[str, Any] = {"event": event}
    for key, value in fields.items():
        if key.endswith("_headers") and isinstance(value, dict):
            payload[key] = sanitize_headers(value)
        elif isinstance(value, str):
            payload[key] = redact_text(value)
        else:
            payload[key] = value
    logger.info("%s", json.dumps(payload, sort_keys=True, default=str))


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("drlink.relay")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger
