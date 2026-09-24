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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("local", "submission"), required=True)
    parser.add_argument("--mcp-url", default=None)
    args = parser.parse_args(argv)
    try:
        report = evaluate(mode=args.mode, mcp_url=args.mcp_url)
    except PackageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0 if report["submission_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
