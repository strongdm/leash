#!/usr/bin/env python3
"""Return success if Docker config indicates ghcr credentials exist."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def has_ghcr(mapping: dict | None) -> bool:
    if not mapping:
        return False
    for key in mapping:
        if isinstance(key, str) and "ghcr.io" in key:
            return True
    return False


def main() -> int:
    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / ".docker/config.json"
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return 1

    if has_ghcr(data.get("auths")) or has_ghcr(data.get("credHelpers")):
        return 0

    if data.get("credsStore") or data.get("credStore"):
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
