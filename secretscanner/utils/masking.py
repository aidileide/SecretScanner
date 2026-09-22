"""Secret-safe display and fingerprint helpers."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")


def mask_secret(value: str) -> str:
    """Mask a possible secret without logging or persisting its full value."""
    cleaned = value.strip().strip("\"'")
    if PRIVATE_KEY_HEADER.search(cleaned):
        return f"{PRIVATE_KEY_HEADER.search(cleaned).group(0)} ... [redacted]"
    if "://" in cleaned:
        masked_url = mask_database_url(cleaned)
        if masked_url != cleaned:
            return masked_url
    if len(cleaned) <= 4:
        return "*" * len(cleaned)
    if len(cleaned) <= 8:
        return f"{cleaned[:2]}{'*' * max(4, len(cleaned) - 4)}{cleaned[-2:]}"
    return f"{cleaned[:4]}{'*' * max(6, len(cleaned) - 8)}{cleaned[-4:]}"


def mask_database_url(value: str) -> str:
    """Mask only a URL password while keeping useful location context."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.scheme or parsed.password is None or parsed.hostname is None:
        return value
    username = parsed.username or ""
    credentials = f"{username}:********@" if username else "********@"
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port_value = parsed.port
    except ValueError:
        return value
    port = f":{port_value}" if port_value else ""
    return urlunsplit(
        (parsed.scheme, f"{credentials}{host}{port}", parsed.path, parsed.query, parsed.fragment)
    )


def finding_fingerprint(rule_id: str, file_path: str, line_number: int, masked: str) -> str:
    """Create a stable identifier without including plaintext secret material."""
    normalized_path = file_path.replace("\\", "/")
    normalized = f"{rule_id}\0{normalized_path}\0{line_number}\0{masked}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
