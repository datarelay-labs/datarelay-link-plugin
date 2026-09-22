"""CLI entrypoint: python -m relay"""

from __future__ import annotations

import sys

from .config import ConfigError, load_config
from .server import serve_forever


def main(argv: list[str] | None = None) -> int:
    _ = argv  # reserved for future flags
    try:
        config = load_config()
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    serve_forever(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
