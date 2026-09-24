"""Phase B OpenAI package, challenge, and submission-readiness regressions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import unittest
from urllib import error, request

from plugin_readiness.readiness import (
    PackageError,
    _review_cases_ok,
    evaluate,
    render_mcp_document,
    resolve_canonical_interface,
    validate_mcp_url,
)
from relay.config import ConfigError, load_config
from relay.server import create_server
from tests.test_relay_poc import ROOT, _free_port

_OWNER = "owner-approval-secret-32chars!!"


def _tool_scan_evidence(url: str) -> dict:
    return {
        "production_mcp_url": url,
        "scan_status": "success",
        "scanned_at": "2026-01-15T00:00:00Z",
        "tools": [
            {
                "name": "read_file",
                "annotations": {
                    "readOnlyHint": True,
                    "openWorldHint": False,
                    "destructiveHint": False,
                },
                "justifications": {
                    "readOnlyHint": "Reads one authorized file and does not change host state.",
                    "openWorldHint": "The tool reaches only the connected DataRelay Link server.",
                    "destructiveHint": "The tool does not delete or overwrite host data.",
                },
            },
            {
                "name": "write_file",
                "annotations": {
                    "readOnlyHint": False,
                    "openWorldHint": False,
                    "destructiveHint": True,
                },
                "justifications": {
                    "readOnlyHint": "Writes host file content when upstream AI Access allows it.",
                    "openWorldHint": "The tool reaches only the connected DataRelay Link server.",
                    "destructiveHint": "A write can overwrite an authorized host file.",
                },
            },
        ],
    }


def _oauth_env(port: int, *, challenge: str | None = None) -> dict[str, str]:
    env = {
        "DRLINK_RELAY_AUTH_MODE": "oauth",
        "DRLINK_RELAY_BIND": "127.0.0.1",
        "DRLINK_RELAY_PORT": str(port),
        "DRLINK_RELAY_PUBLIC_BASE_URL": f"http://127.0.0.1:{port}",
        "DRLINK_RELAY_OWNER_APPROVAL_SECRET": _OWNER,
        "DRLINK_RELAY_OAUTH_ALLOW_EPHEMERAL": "1",
        "DRLINK_RELAY_ALLOW_LOOPBACK_UPSTREAM": "1",
    }
    if challenge is not None:
        env["DRLINK_RELAY_OPENAI_APPS_CHALLENGE"] = challenge
    return env


class PackageContractTests(unittest.TestCase):
    def test_repo_root_does_not_shadow_packaging_version(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = "."
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                "from packaging.version import Version; print(Version('1.2.3'))",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "1.2.3")
        self.assertFalse((ROOT / "packaging").exists())

    def test_canonical_manifest_is_root_plugin_with_openai_extension(self) -> None:
        portable = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
        fallback = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        mcp = json.loads((ROOT / "mcp.json").read_text(encoding="utf-8"))
        interface, reason = resolve_canonical_interface(portable, fallback)
        self.assertIsNotNone(interface, reason)
        assert interface is not None
        self.assertEqual(
            portable["$schema"],
            "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        )
        self.assertEqual(portable["extensions"]["com.openai"]["interface"], interface)
        self.assertEqual(fallback["interface"], interface)
        self.assertNotIn("$schema", fallback)
        self.assertNotIn("extensions", fallback)
        self.assertNotIn("apps", portable["extensions"]["com.openai"])
        self.assertNotIn("mcpServers", portable["extensions"]["com.openai"])
        self.assertNotIn("apps", fallback)
        self.assertNotIn("mcpServers", fallback)
        self.assertNotIn("plugin_asdk_app", json.dumps(portable))
        self.assertNotIn("plugin_asdk_app", json.dumps(fallback))
        self.assertFalse((ROOT / ".app.json").exists())
        self.assertFalse((ROOT / ".mcp.json").exists())
        self.assertEqual(portable["license"], fallback["license"])
        self.assertEqual(mcp["$schema"], "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json")
        self.assertEqual(mcp["mcpServers"]["datarelay-link"]["type"], "streamable-http")
        only_fallback = dict(portable)
        only_fallback.pop("extensions")
        missing, missing_reason = resolve_canonical_interface(only_fallback, fallback)
        self.assertIsNone(missing)
        self.assertIn("extensions.com.openai", missing_reason)
        drifted = json.loads(json.dumps(fallback))
        drifted["interface"] = dict(interface)
        drifted["interface"]["displayName"] = "Other"
        conflict, conflict_reason = resolve_canonical_interface(portable, drifted)
        self.assertIsNone(conflict)
        self.assertIn("must match", conflict_reason)

    def test_portable_mcp_is_documented_streamable_http_without_secrets(self) -> None:
        portable = json.loads((ROOT / "mcp.json").read_text(encoding="utf-8"))
        server = portable["mcpServers"]["datarelay-link"]
        self.assertEqual(server["type"], "streamable-http")
        self.assertEqual(server["url"], "http://127.0.0.1:8741/mcp")
        blob = json.dumps(portable)
        self.assertNotIn("Authorization", blob)
        self.assertNotIn("Bearer", blob)

    def test_submission_url_rejects_http_loopback_and_secrets(self) -> None:
        with self.assertRaises(PackageError):
            validate_mcp_url("http://127.0.0.1:8741/mcp", allow_loopback=False)
        with self.assertRaises(PackageError):
            validate_mcp_url("http://example.com/mcp", allow_loopback=False)
        with self.assertRaises(PackageError):
            validate_mcp_url("https://user:pass@example.com/mcp", allow_loopback=False)
        for rejected in (
            "https://10.0.0.1/mcp",
            "https://169.254.169.254/mcp",
            "https://100.64.0.1/mcp",
            "https://[fc00::1]/mcp",
            "https://metadata.google.internal/mcp",
            "https://mcp.example.com/mcp?token=secret",
            "https://mcp.example.com/mcp#fragment",
            "https://mcp.example.com/other",
        ):
            with self.assertRaises(PackageError, msg=rejected):
                validate_mcp_url(rejected, allow_loopback=False)
        self.assertEqual(
            validate_mcp_url("https://mcp.example.com/mcp", allow_loopback=False),
            "https://mcp.example.com/mcp",
        )
        document = {
            "mcpServers": {
                "datarelay-link": {
                    "type": "streamable-http",
                    "url": "http://127.0.0.1:8741/mcp",
                    "headers": {"Authorization": "Bearer secret"},
                }
            }
        }
        with self.assertRaises(PackageError):
            render_mcp_document(
                document,
                "https://mcp.example.com/mcp",
                allow_loopback=False,
            )
        rendered = render_mcp_document(
            {
                "mcpServers": {
                    "datarelay-link": {
                        "type": "streamable-http",
                        "url": "http://127.0.0.1:8741/mcp",
                    }
                }
            },
            "https://mcp.example.com/mcp",
            allow_loopback=False,
        )
        self.assertEqual(
            rendered["mcpServers"]["datarelay-link"]["url"],
            "https://mcp.example.com/mcp",
        )

    def _assert_not_submission_ready(self, report: dict) -> None:
        blocked = [item for item in report["items"] if item["status"] == "BLOCKED"]
        self.assertNotIn("ok", report)
        self.assertFalse(report["submission_ready"], report)
        self.assertNotEqual(report["overall_status"], "PASS")
        if blocked and report["overall_status"] != "FAIL":
            self.assertEqual(report["overall_status"], "BLOCKED")
        if blocked:
            self.assertFalse(report["submission_ready"])

    def test_local_readiness_passes_repo_checks_and_blocks_owner_gates(self) -> None:
        report = evaluate(mode="local")
        self._assert_not_submission_ready(report)
        self.assertTrue(report["repository_checks_ok"], report)
        self.assertEqual(report["overall_status"], "BLOCKED")
        by_id = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(by_id["canonical_interface"], "PASS")
        self.assertEqual(by_id["portable_mcp_manifest"], "PASS")
        self.assertEqual(by_id["package_layout"], "PASS")
        self.assertEqual(by_id["mcp_package_wiring"], "PASS")
        self.assertEqual(by_id["oauth_discovery"], "PASS")
        self.assertEqual(by_id["domain_challenge_code"], "PASS")
        self.assertEqual(by_id["tool_metadata_passthrough"], "PASS")
        metadata_reason = next(
            item["reason"] for item in report["items"] if item["id"] == "tool_metadata_passthrough"
        )
        self.assertIn("test_tools_metadata_passthrough_is_unmodified", metadata_reason)
        self.assertNotIn("token", metadata_reason.lower())
        self.assertEqual(by_id["reviewer_test_cases"], "PASS")
        self.assertEqual(by_id["starter_prompts"], "PASS")
        for blocked in (
            "production_mcp_url",
            "production_mcp_reachability",
            "domain_challenge_live",
            "website_support_privacy_terms",
            "reviewer_credentials",
            "demo_recording_url",
            "apps_management_permission",
            "listing_logo_assets",
            "openai_project_data_residency",
            "release_notes_attestations",
            "publisher_identity",
            "country_availability",
            "openai_submission",
            "scan_required",
            "annotations_required",
            "justification_required",
        ):
            self.assertEqual(by_id[blocked], "BLOCKED", blocked)
        for gate in ("scan_required", "annotations_required", "justification_required"):
            reason = next(item["reason"] for item in report["items"] if item["id"] == gate)
            self.assertIn("owner", reason)
            self.assertNotIn("test_tools_metadata_passthrough", reason)

    def test_submission_mode_blocks_owner_inputs_and_requires_https(self) -> None:
        missing = evaluate(mode="submission")
        self._assert_not_submission_ready(missing)
        self.assertTrue(missing["repository_checks_ok"], missing)
        self.assertEqual(missing["overall_status"], "BLOCKED")
        by_id = {item["id"]: item["status"] for item in missing["items"]}
        self.assertEqual(by_id["production_mcp_url"], "BLOCKED")
        self.assertEqual(by_id["website_support_privacy_terms"], "BLOCKED")
        self.assertEqual(by_id["openai_submission"], "BLOCKED")
        self.assertEqual(by_id["package_layout"], "PASS")
        self.assertEqual(by_id["mcp_package_wiring"], "PASS")

        insecure = evaluate(mode="submission", mcp_url="http://mcp.example.com/mcp")
        self._assert_not_submission_ready(insecure)
        insecure_ids = {item["id"]: item["status"] for item in insecure["items"]}
        self.assertEqual(insecure_ids["production_mcp_url"], "FAIL")
        self.assertEqual(insecure["overall_status"], "FAIL")
        self.assertFalse(insecure["submission_ready"])

        loopback = evaluate(mode="submission", mcp_url="https://127.0.0.1/mcp")
        loopback_ids = {item["id"]: item["status"] for item in loopback["items"]}
        self.assertEqual(loopback_ids["production_mcp_url"], "FAIL")
        self.assertEqual(loopback["overall_status"], "FAIL")

        supplied = evaluate(mode="submission", mcp_url="https://mcp.example.com/mcp")
        self._assert_not_submission_ready(supplied)
        supplied_ids = {item["id"]: item["status"] for item in supplied["items"]}
        self.assertEqual(supplied_ids["production_mcp_url"], "PASS")
        self.assertEqual(supplied_ids["reviewer_credentials"], "BLOCKED")
        self.assertEqual(supplied_ids["demo_recording_url"], "BLOCKED")
        self.assertEqual(supplied_ids["country_availability"], "BLOCKED")
        self.assertEqual(supplied_ids["publisher_identity"], "BLOCKED")
        self.assertEqual(supplied_ids["mcp_package_wiring"], "PASS")
        self.assertEqual(supplied_ids["package_layout"], "PASS")
        self.assertEqual(supplied_ids["production_mcp_reachability"], "BLOCKED")
        self.assertEqual(supplied_ids["apps_management_permission"], "BLOCKED")
        self.assertEqual(supplied_ids["listing_logo_assets"], "BLOCKED")
        self.assertEqual(supplied_ids["openai_project_data_residency"], "BLOCKED")
        self.assertEqual(supplied_ids["release_notes_attestations"], "BLOCKED")
        self.assertIn("MFA", next(item["reason"] for item in supplied["items"] if item["id"] == "reviewer_credentials"))
        self.assertEqual(supplied["overall_status"], "BLOCKED")
        self.assertFalse(supplied["submission_ready"])
        self.assertEqual(supplied_ids["scan_required"], "BLOCKED")
        self.assertEqual(supplied_ids["annotations_required"], "BLOCKED")
        self.assertEqual(supplied_ids["justification_required"], "BLOCKED")
        self.assertEqual(supplied_ids["tool_metadata_passthrough"], "PASS")

    def test_live_tool_scan_gates_block_submission_until_owner_evidence(self) -> None:
        report = evaluate(mode="submission", mcp_url="https://mcp.example.com/mcp")
        self._assert_not_submission_ready(report)
        self.assertTrue(report["repository_checks_ok"], report)
        by_id = {item["id"]: item for item in report["items"]}
        for gate in ("scan_required", "annotations_required", "justification_required"):
            self.assertEqual(by_id[gate]["status"], "BLOCKED", gate)
            self.assertEqual(by_id[gate]["scope"], "submission")
        self.assertEqual(by_id["tool_metadata_passthrough"]["status"], "PASS")
        self.assertIn(
            "test_tools_metadata_passthrough_is_unmodified",
            by_id["tool_metadata_passthrough"]["reason"],
        )

    def test_owner_tool_scan_evidence_passes_gates_without_submission_ready(self) -> None:
        url = "https://mcp.example.com/mcp"
        evidence = _tool_scan_evidence(url)
        report = evaluate(mode="submission", mcp_url=url, tool_scan_evidence=evidence)
        self._assert_not_submission_ready(report)
        self.assertTrue(report["repository_checks_ok"], report)
        by_id = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(by_id["scan_required"], "PASS")
        self.assertEqual(by_id["annotations_required"], "PASS")
        self.assertEqual(by_id["justification_required"], "PASS")
        self.assertEqual(by_id["reviewer_credentials"], "BLOCKED")
        self.assertEqual(report["overall_status"], "BLOCKED")
        self.assertFalse(report["submission_ready"])

        mismatched = evaluate(
            mode="submission",
            mcp_url=url,
            tool_scan_evidence=_tool_scan_evidence("https://other.example.com/mcp"),
        )
        mismatched_ids = {item["id"]: item["status"] for item in mismatched["items"]}
        self.assertEqual(mismatched_ids["scan_required"], "FAIL")
        self.assertEqual(mismatched_ids["annotations_required"], "FAIL")
        self.assertEqual(mismatched_ids["justification_required"], "FAIL")
        self.assertEqual(mismatched["overall_status"], "FAIL")
        self.assertFalse(mismatched["submission_ready"])

        incomplete = _tool_scan_evidence(url)
        incomplete["tools"][0]["annotations"].pop("openWorldHint")
        incomplete["tools"][1]["justifications"]["destructiveHint"] = " "
        partial = evaluate(mode="submission", mcp_url=url, tool_scan_evidence=incomplete)
        partial_ids = {item["id"]: item["status"] for item in partial["items"]}
        self.assertEqual(partial_ids["scan_required"], "PASS")
        self.assertEqual(partial_ids["annotations_required"], "FAIL")
        self.assertEqual(partial_ids["justification_required"], "FAIL")
        self.assertFalse(partial["submission_ready"])

        stringly = _tool_scan_evidence(url)
        stringly["tools"][0]["annotations"]["readOnlyHint"] = "true"
        stringly_report = evaluate(mode="submission", mcp_url=url, tool_scan_evidence=stringly)
        stringly_ids = {item["id"]: item["status"] for item in stringly_report["items"]}
        self.assertEqual(stringly_ids["annotations_required"], "FAIL")
        self.assertFalse(stringly_report["submission_ready"])

        secretive = _tool_scan_evidence(url)
        secretive["access_token"] = "upstream-secret"
        secret_report = evaluate(mode="submission", mcp_url=url, tool_scan_evidence=secretive)
        secret_ids = {item["id"]: item["status"] for item in secret_report["items"]}
        self.assertEqual(secret_ids["scan_required"], "FAIL")
        self.assertFalse(secret_report["submission_ready"])

        empty = _tool_scan_evidence(url)
        empty["tools"] = []
        empty_report = evaluate(mode="submission", mcp_url=url, tool_scan_evidence=empty)
        empty_ids = {item["id"]: item["status"] for item in empty_report["items"]}
        self.assertEqual(empty_ids["scan_required"], "FAIL")
        self.assertEqual(empty_ids["annotations_required"], "FAIL")
        self.assertEqual(empty_ids["justification_required"], "FAIL")
        self.assertFalse(empty_report["submission_ready"])

    def test_cli_rejects_unreadable_tool_scan_evidence(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "scripts/submission-readiness.py",
                "--mode",
                "local",
                "--tool-scan-evidence",
                str(ROOT / "docs" / "submission" / "missing-tool-scan.json"),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("tool scan evidence", completed.stderr)
        self.assertFalse((ROOT / "docs" / "submission" / "missing-tool-scan.json").exists())

    def test_review_cases_have_five_positive_and_three_negative(self) -> None:
        cases = json.loads(
            (ROOT / "docs" / "submission" / "review-cases.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(cases["positive"]), 5)
        self.assertEqual(len(cases["negative"]), 3)
        self.assertTrue(_review_cases_ok(cases))
        six_positive = json.loads(json.dumps(cases))
        six_positive["positive"].append(dict(cases["positive"][0]))
        self.assertEqual(len(six_positive["positive"]), 6)
        self.assertEqual(len(six_positive["negative"]), 3)
        self.assertFalse(_review_cases_ok(six_positive))
        five_four = json.loads(json.dumps(cases))
        five_four["negative"].append(dict(cases["negative"][0]))
        self.assertEqual(len(five_four["positive"]), 5)
        self.assertEqual(len(five_four["negative"]), 4)
        self.assertFalse(_review_cases_ok(five_four))
        self.assertIn("AI Access", cases["authority"])
        for case in cases["positive"]:
            for field in (
                "user_prompt",
                "expected_behavior",
                "expected_result_shape",
                "fixture_data",
            ):
                self.assertTrue(str(case.get(field, "")).strip(), case["id"] + field)
            self.assertNotIn("password", case["fixture_data"].lower())
        for case in cases["negative"]:
            self.assertTrue(
                str(case.get("user_prompt", "")).strip() or str(case.get("scenario", "")).strip(),
                case["id"],
            )
            self.assertTrue(str(case.get("expected_fallback", "")).strip(), case["id"])
            self.assertTrue(str(case.get("why_not_complete", "")).strip(), case["id"])


class OpenAIChallengeTests(unittest.TestCase):
    def _start(self, challenge: str | None) -> tuple[object, str]:
        port = _free_port()
        config = load_config(_oauth_env(port, challenge=challenge))
        server = create_server(config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, f"http://127.0.0.1:{port}"

    def test_unconfigured_challenge_is_404_without_placeholder(self) -> None:
        server, base = self._start(None)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        with self.assertRaises(error.HTTPError) as ctx:
            request.urlopen(f"{base}/.well-known/openai-apps-challenge", timeout=5)
        self.assertEqual(ctx.exception.code, 404)
        body = ctx.exception.read().decode("utf-8")
        self.assertNotIn("openai-apps-challenge", body.lower())
        self.assertNotIn("token", body.lower())

    def test_configured_challenge_is_exact_plain_token(self) -> None:
        token = "portal-challenge-token"
        server, base = self._start(token)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        with request.urlopen(f"{base}/.well-known/openai-apps-challenge", timeout=5) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
        self.assertEqual(resp.status, 200)
        self.assertEqual(raw.decode("utf-8"), token)
        self.assertNotIn("\n", raw.decode("utf-8"))
        self.assertTrue(ctype.startswith("text/plain"))
        self.assertNotIn("{", raw.decode("utf-8"))
        with request.urlopen(f"{base}/health", timeout=5) as health:
            health_body = health.read().decode("utf-8")
        self.assertNotIn(token, health_body)

    def test_challenge_token_rejects_whitespace(self) -> None:
        port = _free_port()
        with self.assertRaises(ConfigError):
            load_config(_oauth_env(port, challenge="token\nsecond"))
        with self.assertRaises(ConfigError):
            load_config(_oauth_env(port, challenge=""))


if __name__ == "__main__":
    unittest.main()
