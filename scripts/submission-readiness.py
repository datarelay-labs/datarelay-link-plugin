#!/usr/bin/env python3
"""Print OpenAI submission-readiness without contacting OpenAI or DNS."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from plugin_readiness.readiness import PackageError, evaluate  # noqa: E402


def _load_evidence(path: str) -> object:
    evidence_path = Path(path)
    try:
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackageError(f"tool scan evidence is not readable JSON: {exc}") from exc
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("local", "submission"), required=True)
    parser.add_argument("--mcp-url", default=None)
    parser.add_argument(
        "--tool-scan-evidence",
        default=None,
        help="owner-supplied production MCP tool scan JSON; absent evidence stays BLOCKED",
    )
    args = parser.parse_args(argv)
    try:
        evidence = None if args.tool_scan_evidence is None else _load_evidence(args.tool_scan_evidence)
        report = evaluate(
            mode=args.mode,
            mcp_url=args.mcp_url,
            tool_scan_evidence=evidence,
        )
    except PackageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0 if report["submission_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
