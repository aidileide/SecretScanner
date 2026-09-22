"""Ignore, allowlist, and context-risk filters."""

from __future__ import annotations

from pathlib import Path

import pathspec

from secretscanner.config import AllowlistConfig
from secretscanner.models import Confidence

DEFAULT_IGNORES = [
    ".git/",
    ".pytest_cache/",
    ".ruff_cache/",
    "node_modules/",
    ".venv/",
    "venv/",
    "dist/",
    "build/",
    "__pycache__/",
    "vendor/",
    "target/",
    "coverage/",
    ".next/",
    ".idea/",
    ".vscode/",
]
LOW_RISK_WORDS = {
    "example",
    "sample",
    "dummy",
    "fake",
    "test",
    "fixture",
    "placeholder",
    "changeme",
    "your_api_key_here",
    "your_token_here",
    "xxxxxx",
    "not real",
    "not_real",
}
HIGH_RISK_WORDS = {"production", "prod", "live", "credential", "private_key", "secret", "token"}


def load_ignore_spec(root: Path, extra: list[str]) -> pathspec.PathSpec:
    patterns = [*DEFAULT_IGNORES, *extra]
    ignore_file = root / ".secretscannerignore"
    if ignore_file.is_file():
        try:
            patterns.extend(ignore_file.read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeError):
            pass
    return pathspec.PathSpec.from_lines("gitwildmatch", patterns)


def confidence_for_context(base: Confidence, context: str) -> Confidence:
    lowered = context.lower()
    if any(word in lowered for word in LOW_RISK_WORDS):
        return Confidence.LOW
    if any(word in lowered for word in HIGH_RISK_WORDS):
        return Confidence.HIGH
    return base


def is_inline_allowed(lines: list[str], line_index: int) -> bool:
    current = lines[line_index].lower()
    if "secretscanner: allow" in current:
        return True
    if line_index > 0 and "secretscanner: allow-next-line" in lines[line_index - 1].lower():
        return True
    return False


def allowlisted(
    allowlist: AllowlistConfig,
    path: str,
    rule_id: str,
    fingerprint: str,
) -> bool:
    if rule_id in allowlist.rules or fingerprint in allowlist.fingerprints:
        return True
    if not allowlist.paths:
        return False
    spec = pathspec.PathSpec.from_lines("gitwildmatch", allowlist.paths)
    return spec.match_file(path.replace("\\", "/"))
