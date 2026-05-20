"""Generate the deterministic OpenAPI snapshot for the user-service public API.

Usage:
    python scripts/generate_openapi_snapshot.py
    make openapi-snapshot

Writes to docs/openapi-snapshot.json. Output is stable across runs (sorted keys,
2-space indent, trailing newline) so the CI drift gate compares cleanly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.app.main import create_app  # noqa: E402

SNAPSHOT_PATH = REPO_ROOT / "docs" / "openapi-snapshot.json"


def generate_snapshot() -> str:
    app = create_app()
    spec = app.openapi()
    return json.dumps(spec, indent=2, sort_keys=True) + "\n"


def main() -> None:
    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_PATH.write_text(generate_snapshot(), encoding="utf-8")


if __name__ == "__main__":
    main()
