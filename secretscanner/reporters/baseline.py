"""Secret-free baseline persistence."""

from __future__ import annotations

import json
from pathlib import Path

from secretscanner.exceptions import ConfigurationError
from secretscanner.models import ScanResult


def load_baseline(path: Path | None) -> set[str]:
    if path is None:
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Could not load baseline {path}: {exc}") from exc
    fingerprints = data.get("fingerprints") if isinstance(data, dict) else None
    if not isinstance(fingerprints, list) or any(
        not isinstance(item, str) for item in fingerprints
    ):
        raise ConfigurationError("Baseline must contain a string fingerprint list.")
    return set(fingerprints)


def write_baseline(result: ScanResult, path: Path) -> None:
    payload = {
        "version": 1,
        "generator": "SecretScanner",
        "fingerprints": sorted({item.fingerprint for item in result.findings}),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
