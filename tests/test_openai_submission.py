"""Phase B OpenAI package, challenge, and submission-readiness regressions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import unittest
from urllib import error, request

from plugin_readiness.readiness import PackageError, evaluate, render_mcp_document, validate_mcp_url
from relay.config import ConfigError, load_config
from relay.server import create_server
from tests.test_relay_poc import ROOT, _free_port

_OWNER = "owner-approval-secret-32chars!!"


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

    def test_canonical_manifest_is_codex_plugin_without_inline_extension(self) -> None:
        canonical = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        portable = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(canonical["name"], "datarelay-link")
        self.assertIn("displayName", canonical["interface"])
        self.assertGreaterEqual(len(canonical["interface"]["defaultPrompt"]), 1)
        self.assertNotIn("extensions", canonical)
        self.assertNotIn("extensions", portable)
        self.assertNotIn("apps", canonical)
        self.assertNotIn("mcpServers", canonical)
        self.assertNotIn("plugin_asdk_app", json.dumps(canonical))
        self.assertFalse((ROOT / ".app.json").exists())
        self.assertFalse((ROOT / ".mcp.json").exists())
        self.assertEqual(portable["license"], canonical["license"])

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
        self.assertEqual(by_id["package_layout"], "BLOCKED")
        self.assertEqual(by_id["mcp_package_wiring"], "BLOCKED")
        self.assertEqual(by_id["oauth_discovery"], "PASS")
        self.assertEqual(by_id["domain_challenge_code"], "PASS")
        self.assertEqual(by_id["tool_metadata_passthrough"], "PASS")
        self.assertEqual(by_id["reviewer_test_cases"], "PASS")
        self.assertEqual(by_id["starter_prompts"], "PASS")
        for blocked in (
            "production_mcp_url",
            "production_mcp_reachability",
            "domain_challenge_live",
            "website_support_privacy_terms",
            "reviewer_credentials",
            "apps_management_permission",
            "listing_logo_assets",
            "openai_project_data_residency",
            "release_notes_attestations",
            "publisher_identity",
            "country_availability",
            "openai_submission",
        ):
            self.assertEqual(by_id[blocked], "BLOCKED", blocked)

    def test_submission_mode_blocks_owner_inputs_and_requires_https(self) -> None:
        missing = evaluate(mode="submission")
        self._assert_not_submission_ready(missing)
        self.assertTrue(missing["repository_checks_ok"], missing)
        self.assertEqual(missing["overall_status"], "BLOCKED")
        by_id = {item["id"]: item["status"] for item in missing["items"]}
        self.assertEqual(by_id["production_mcp_url"], "BLOCKED")
        self.assertEqual(by_id["website_support_privacy_terms"], "BLOCKED")
        self.assertEqual(by_id["openai_submission"], "BLOCKED")
        self.assertNotEqual(by_id["package_layout"], "PASS")

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
        self.assertEqual(supplied_ids["country_availability"], "BLOCKED")
        self.assertEqual(supplied_ids["publisher_identity"], "BLOCKED")
        self.assertEqual(supplied_ids["mcp_package_wiring"], "BLOCKED")
        self.assertEqual(supplied_ids["production_mcp_reachability"], "BLOCKED")
        self.assertEqual(supplied_ids["apps_management_permission"], "BLOCKED")
        self.assertEqual(supplied_ids["listing_logo_assets"], "BLOCKED")
        self.assertEqual(supplied_ids["openai_project_data_residency"], "BLOCKED")
        self.assertEqual(supplied_ids["release_notes_attestations"], "BLOCKED")
        self.assertIn("MFA", next(item["reason"] for item in supplied["items"] if item["id"] == "reviewer_credentials"))
        self.assertEqual(supplied["overall_status"], "BLOCKED")
        self.assertFalse(supplied["submission_ready"])

    def test_review_cases_have_five_positive_and_three_negative(self) -> None:
        cases = json.loads(
            (ROOT / "docs" / "submission" / "review-cases.json").read_text(encoding="utf-8")
        )
        self.assertGreaterEqual(len(cases["positive"]), 5)
        self.assertGreaterEqual(len(cases["negative"]), 3)
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
