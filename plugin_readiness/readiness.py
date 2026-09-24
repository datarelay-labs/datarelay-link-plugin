"""Repository-only OpenAI package and submission-readiness checks.

Owner and platform prerequisites are reported BLOCKED. This module does not
probe DNS, publish legal text, or submit anything to OpenAI.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
AGENT_PLUGIN_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
AGENT_MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"

_SECRET_KEYS = {
    "authorization",
    "proxy-authorization",
    "headers",
    "token",
    "access_token",
    "refresh_token",
    "client_secret",
    "upstream_token",
    "upstream_bearer",
    "api_key",
}

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_METADATA_HOSTS = {"metadata", "metadata.google.internal"}
_POSITIVE_FIELDS = (
    "user_prompt",
    "expected_behavior",
    "expected_result_shape",
    "fixture_data",
)
_NEGATIVE_FIELDS = ("expected_fallback", "why_not_complete")


class PackageError(ValueError):
    """Submission package input is not acceptable."""


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _walk_secret_keys(value: Any, found: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in _SECRET_KEYS:
                found.append(str(key))
            _walk_secret_keys(item, found)
    elif isinstance(value, list):
        for item in value:
            _walk_secret_keys(item, found)


def _is_loopback(hostname: str) -> bool:
    host = hostname.strip("[]").lower()
    if host in _LOOPBACK_HOSTS:
        return True
    return host.startswith("127.")


def _literal_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return None


def _public_literal(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_global
        and not any(
            (
                ip.is_private,
                ip.is_loopback,
                ip.is_link_local,
                ip.is_multicast,
                ip.is_reserved,
                ip.is_unspecified,
            )
        )
    )


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _review_cases_ok(cases: Any) -> bool:
    if not isinstance(cases, dict):
        return False
    positive = cases.get("positive")
    negative = cases.get("negative")
    if not isinstance(positive, list) or len(positive) < 5:
        return False
    if not isinstance(negative, list) or len(negative) < 3:
        return False
    for case in positive:
        if not isinstance(case, dict) or not all(_nonempty(case.get(field)) for field in _POSITIVE_FIELDS):
            return False
    for case in negative:
        if not isinstance(case, dict):
            return False
        if not (_nonempty(case.get("user_prompt")) or _nonempty(case.get("scenario"))):
            return False
        if not all(_nonempty(case.get(field)) for field in _NEGATIVE_FIELDS):
            return False
    return True


def validate_mcp_url(url: str, *, allow_loopback: bool) -> str:
    """Return a submission or local MCP URL, or raise PackageError.

    Hostname reachability is not probed.
    """
    raw = (url or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PackageError("MCP URL must be absolute http(s)")
    if parsed.username or parsed.password:
        raise PackageError("MCP URL must not embed credentials")
    if parsed.query:
        raise PackageError("MCP URL must not include a query or secret")
    if parsed.fragment:
        raise PackageError("MCP URL must not include a fragment")
    host = parsed.hostname.strip("[]").lower()
    loopback = _is_loopback(host)
    literal = _literal_ip(host)
    if not allow_loopback:
        if parsed.scheme != "https":
            raise PackageError("submission MCP URL must use https")
        if parsed.path != "/mcp":
            raise PackageError("submission MCP URL path must be /mcp")
        if loopback or host in _METADATA_HOSTS:
            raise PackageError("submission MCP URL must not be loopback or metadata")
        if literal is not None and not _public_literal(literal):
            raise PackageError(
                "submission MCP URL must not use a private, link-local, metadata, or reserved literal IP"
            )
    elif parsed.scheme == "http" and not loopback:
        raise PackageError("non-loopback MCP URL must use https")
    return raw


def _server_entries(document: dict[str, Any]) -> list[dict[str, Any]]:
    servers = document.get("mcpServers")
    if not isinstance(servers, dict) or not servers:
        raise PackageError("mcpServers must be a non-empty object")
    entries: list[dict[str, Any]] = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            raise PackageError(f"MCP server {name} must be an object")
        if spec.get("type") != "streamable-http":
            raise PackageError(f"MCP server {name} must use type streamable-http")
        if not isinstance(spec.get("url"), str):
            raise PackageError(f"MCP server {name} requires a url")
        entries.append(spec)
    return entries


def render_mcp_document(document: dict[str, Any], mcp_url: str, *, allow_loopback: bool) -> dict[str, Any]:
    """Return a copy of an MCP document with every server URL replaced."""
    url = validate_mcp_url(mcp_url, allow_loopback=allow_loopback)
    secrets: list[str] = []
    _walk_secret_keys(document, secrets)
    if secrets:
        raise PackageError("MCP document contains secret-bearing fields")
    rendered = json.loads(json.dumps(document))
    for spec in rendered["mcpServers"].values():
        spec["url"] = url
        spec.pop("headers", None)
    return rendered


def resolve_canonical_interface(portable: Any, fallback: Any) -> tuple[dict[str, Any] | None, str]:
    """Return the OpenAI interface from root plugin.json, or a failure reason.

    ``.codex-plugin/plugin.json`` is a compatibility fallback. It is not read
    as the source of interface fields. When ``extensions.com.openai`` is
    present, official docs replace the overlay with that object and do not
    merge the two files.
    """
    if not isinstance(portable, dict):
        return None, "root plugin.json is missing or invalid"
    if portable.get("$schema") != AGENT_PLUGIN_SCHEMA:
        return None, "root plugin.json must declare the Agent Plugins schema"
    if portable.get("name") != "datarelay-link":
        return None, "root plugin.json name must be datarelay-link"
    extensions = portable.get("extensions")
    openai = extensions.get("com.openai") if isinstance(extensions, dict) else None
    if not isinstance(openai, dict):
        return None, "OpenAI settings must live under root extensions.com.openai"
    if "apps" in openai or "mcpServers" in openai:
        return None, "portable OpenAI extension must not claim apps or mcpServers"
    interface = openai.get("interface")
    prompts = interface.get("defaultPrompt") if isinstance(interface, dict) else None
    if (
        not isinstance(interface, dict)
        or not isinstance(interface.get("displayName"), str)
        or not isinstance(prompts, list)
        or len(prompts) < 1
    ):
        return None, "extensions.com.openai.interface is missing displayName or starter prompts"
    if not isinstance(fallback, dict):
        return None, "compatibility fallback .codex-plugin/plugin.json is missing"
    if "$schema" in fallback or "extensions" in fallback:
        return None, "compatibility fallback must not imitate the portable manifest"
    if "apps" in fallback or "mcpServers" in fallback:
        return None, "compatibility fallback must not claim apps or mcpServers"
    if fallback.get("interface") != interface:
        return None, "compatibility fallback interface must match the canonical interface"
    return interface, (
        "root plugin.json extensions.com.openai.interface is canonical; "
        ".codex-plugin/plugin.json is a matching compatibility fallback"
    )


def _status(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def _item(item_id: str, status: str, reason: str, scope: str) -> dict[str, str]:
    return {"id": item_id, "status": status, "scope": scope, "reason": reason}


def _blocked(item: str, reason: str) -> dict[str, str]:
    return _item(item, "BLOCKED", reason, "submission")


def _finalize(mode: str, items: list[dict[str, str]], dev_loopback: bool) -> dict[str, Any]:
    """Separate repository checks from submission readiness.

    A BLOCKED prerequisite keeps submission_ready false and overall_status
    BLOCKED. FAIL outranks BLOCKED so an invalid URL is not hidden.
    """
    failed = [item["id"] for item in items if item["status"] == "FAIL"]
    blocked = [item["id"] for item in items if item["status"] == "BLOCKED"]
    repo_items = [item for item in items if item["scope"] == "repository"]
    repository_checks_ok = bool(repo_items) and all(item["status"] == "PASS" for item in repo_items)
    if failed:
        overall_status = "FAIL"
    elif blocked:
        overall_status = "BLOCKED"
    else:
        overall_status = "PASS"
    submission_ready = overall_status == "PASS"
    if blocked and submission_ready:
        raise RuntimeError("BLOCKED report was marked submission ready")
    return {
        "mode": mode,
        "dev_loopback_fixture": dev_loopback,
        "items": items,
        "repository_checks_ok": repository_checks_ok,
        "submission_ready": submission_ready,
        "overall_status": overall_status,
    }


def evaluate(root: Path | None = None, *, mode: str, mcp_url: str | None = None) -> dict[str, Any]:
    """Return a readiness report. mode is ``local`` or ``submission``."""
    if mode not in {"local", "submission"}:
        raise PackageError("mode must be local or submission")
    base = root or ROOT
    items: list[dict[str, str]] = []

    canonical = base / "plugin.json"
    fallback_path = base / ".codex-plugin" / "plugin.json"
    portable_mcp = base / "mcp.json"
    cases_path = base / "docs" / "submission" / "review-cases.json"
    server_py = base / "relay" / "server.py"
    metadata_test = base / "tests" / "test_relay_poc.py"
    prompts: list[Any] | None = None
    dev_loopback = False

    interface_reason = "root plugin.json is missing or invalid"
    interface_ok = False
    try:
        portable_doc = _load_json(canonical)
        fallback_doc = _load_json(fallback_path)
        interface, interface_reason = resolve_canonical_interface(portable_doc, fallback_doc)
        prompts = interface.get("defaultPrompt") if isinstance(interface, dict) else None
        package_text = canonical.read_text(encoding="utf-8") + fallback_path.read_text(encoding="utf-8")
        false_wiring = (base / ".mcp.json").exists() or (base / ".app.json").exists()
        fabricated_id = "plugin_asdk_app" in package_text
        interface_ok = interface is not None and not false_wiring and not fabricated_id
        if false_wiring or fabricated_id:
            interface_reason = (
                "package must not add .mcp.json, .app.json, or a fabricated plugin_asdk_app id"
            )
            interface = None
            prompts = None
    except (OSError, json.JSONDecodeError, AttributeError):
        interface_reason = "canonical plugin manifest is missing or invalid"
        prompts = None
    items.append(
        _item("canonical_interface", _status(interface_ok), interface_reason, "repository")
    )
    layout_reason = interface_reason
    if interface_ok:
        layout_reason = (
            "canonical root plugin.json uses the Agent Plugins schema and "
            "extensions.com.openai; .codex-plugin/plugin.json is fallback only"
        )
    items.append(_item("package_layout", _status(interface_ok), layout_reason, "repository"))

    secret_fail = False
    url_fail_reason = ""
    try:
        document = _load_json(portable_mcp)
        if document.get("$schema") != AGENT_MCP_SCHEMA:
            raise PackageError("root mcp.json must declare the Agent Plugins MCP schema")
        entries = _server_entries(document)
        plugin_schema = _load_json(base / "schemas" / "plugin.schema.json")
        mcp_schema = _load_json(base / "schemas" / "mcp.schema.json")
        Draft202012Validator(plugin_schema).validate(_load_json(canonical))
        Draft202012Validator(mcp_schema).validate(document)
        found: list[str] = []
        _walk_secret_keys(document, found)
        if found:
            secret_fail = True
        for spec in entries:
            url = str(spec["url"])
            validate_mcp_url(url, allow_loopback=True)
            host = urlparse(url).hostname or ""
            dev_loopback = dev_loopback or _is_loopback(host)
    except (OSError, json.JSONDecodeError, PackageError, KeyError) as exc:
        url_fail_reason = str(exc)
        secret_fail = True
    except Exception as exc:
        if exc.__class__.__name__ != "ValidationError":
            raise
        url_fail_reason = str(exc)
        secret_fail = True

    mcp_ok = not secret_fail and not url_fail_reason
    mcp_reason = url_fail_reason or (
        "root mcp.json declares streamable-http under the Agent Plugins MCP schema; "
        "the committed URL is the local PoC"
    )
    items.append(
        _item(
            "portable_mcp_manifest",
            _status(mcp_ok),
            mcp_reason,
            "repository",
        )
    )
    if mcp_ok and interface_ok:
        wiring_reason = mcp_reason
    elif not mcp_ok:
        wiring_reason = url_fail_reason or "root mcp.json is not a portable streamable-http document"
    else:
        wiring_reason = interface_reason
    items.append(
        _item(
            "mcp_package_wiring",
            _status(mcp_ok and interface_ok),
            wiring_reason,
            "repository",
        )
    )
    items.append(
        _item(
            "package_secrets",
            _status(not secret_fail and not url_fail_reason),
            url_fail_reason or "portable MCP manifest has no embedded credentials",
            "repository",
        )
    )

    supplied = (mcp_url or "").strip()
    if not supplied:
        items.append(
            _blocked(
                "production_mcp_url",
                "owner has not supplied a production HTTPS MCP URL",
            )
        )
    else:
        try:
            validate_mcp_url(supplied, allow_loopback=False)
            items.append(
                _item(
                    "production_mcp_url",
                    "PASS",
                    "supplied submission URL is https and non-loopback",
                    "submission",
                )
            )
        except PackageError as exc:
            items.append(_item("production_mcp_url", "FAIL", str(exc), "submission"))
    items.append(
        _blocked(
            "production_mcp_reachability",
            "hostname reachability is live/owner-gated and is not DNS-probed",
        )
    )

    try:
        source = server_py.read_text(encoding="utf-8")
        oauth_ok = (
            "/.well-known/oauth-protected-resource" in source
            and "/.well-known/oauth-authorization-server" in source
        )
    except OSError:
        oauth_ok = False
    items.append(
        _item(
            "oauth_discovery",
            _status(oauth_ok),
            "relay source hosts OAuth protected-resource and authorization-server metadata",
            "repository",
        )
    )

    try:
        source = server_py.read_text(encoding="utf-8")
        challenge_code = "/.well-known/openai-apps-challenge" in source
    except OSError:
        challenge_code = False
    items.append(
        _item(
            "domain_challenge_code",
            _status(challenge_code),
            "runtime challenge route exists; no token is committed",
            "repository",
        )
    )
    items.append(
        _blocked(
            "domain_challenge_live",
            "live portal token and DNS are not activated",
        )
    )

    try:
        test_source = metadata_test.read_text(encoding="utf-8")
        metadata_ok = all(
            token in test_source
            for token in (
                "readOnlyHint",
                "openWorldHint",
                "destructiveHint",
                "securitySchemes",
                "mcp/www_authenticate",
                "outputSchema",
            )
        )
    except OSError:
        metadata_ok = False
    items.append(
        _item(
            "tool_metadata_passthrough",
            _status(metadata_ok),
            "unit coverage preserves upstream tool metadata and annotations",
            "repository",
        )
    )

    try:
        cases_ok = _review_cases_ok(_load_json(cases_path))
    except (OSError, json.JSONDecodeError):
        cases_ok = False
    items.append(
        _item(
            "reviewer_test_cases",
            _status(cases_ok),
            "fixtures include 5 positive and 3 negative cases with the OpenAI review fields",
            "repository",
        )
    )
    items.append(
        _item(
            "starter_prompts",
            _status(bool(prompts)),
            "canonical manifest includes starter prompts",
            "repository",
        )
    )

    items.extend(
        [
            _blocked(
                "website_support_privacy_terms",
                "owner has not approved reachable public website, support, privacy, and terms URLs",
            ),
            _blocked(
                "reviewer_credentials",
                "owner has not provisioned reviewer credentials that work without MFA, SMS, email confirmation, or private-network access",
            ),
            _blocked(
                "apps_management_permission",
                "owner has not confirmed Apps Management write permission for plugin submission",
            ),
            _blocked(
                "listing_logo_assets",
                "owner-approved production listing logo and brand assets are absent",
            ),
            _blocked(
                "openai_project_data_residency",
                "OpenAI project eligibility and data-residency requirements are not owner-confirmed",
            ),
            _blocked(
                "release_notes_attestations",
                "release notes and final policy attestations are not owner-approved",
            ),
            _blocked(
                "publisher_identity",
                "publisher business identity is not verified in the OpenAI Platform organization",
            ),
            _blocked(
                "country_availability",
                "owner has not selected country or region availability",
            ),
            _blocked(
                "openai_submission",
                "OpenAI portal submission and publication are NOT_AUTHORIZED",
            ),
        ]
    )

    return _finalize(mode, items, dev_loopback)
