"""Low-cost validators that reduce obvious false positives."""

from __future__ import annotations

import re

PLACEHOLDER_WORDS = {
    "example",
    "sample",
    "dummy",
    "fake",
    "foobar",
    "test",
    "test123",
    "password",
    "changeme",
    "placeholder",
    "your_api_key",
    "your_token_here",
    "not_real",
    "redacted",
}


def is_plausible_secret(value: str, _context: str = "") -> bool:
    cleaned = value.strip().strip("\"'").lower()
    if not cleaned or cleaned in PLACEHOLDER_WORDS:
        return False
    if any(word in cleaned for word in ("your_", "replace_me", "not-real", "not_real")):
        return False
    alphanumeric = re.sub(r"[^a-z0-9]", "", cleaned)
    if len(set(alphanumeric)) <= 3:
        return False
    return True


def has_database_password(value: str, _context: str = "") -> bool:
    return bool(re.match(r"^[a-z][a-z0-9+.-]*://[^:/\s]+:[^@/\s]+@", value, re.IGNORECASE))


def not_uuid_or_hash(value: str, _context: str = "") -> bool:
    cleaned = value.strip()
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        cleaned,
    ):
        return False
    if re.fullmatch(
        r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|"
        r"[0-9a-fA-F]{96}|[0-9a-fA-F]{128}",
        cleaned,
    ):
        return False
    return is_plausible_secret(value)
