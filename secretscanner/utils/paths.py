"""Filesystem safety helpers."""

from __future__ import annotations

from pathlib import Path

BINARY_SUFFIXES = {
    ".7z",
    ".aab",
    ".apk",
    ".avi",
    ".bmp",
    ".db",
    ".class",
    ".dex",
    ".dll",
    ".dylib",
    ".exe",
    ".flac",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jar",
    ".jpg",
    ".m4a",
    ".mov",
    ".mp3",
    ".mp4",
    ".o",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".sqlite",
    ".tar",
    ".webp",
    ".woff",
    ".zip",
}


def is_probably_text_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_SUFFIXES:
        return False
    try:
        with path.open("rb") as handle:
            chunk = handle.read(8192)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    if not chunk:
        return True
    control = sum(byte < 9 or 13 < byte < 32 for byte in chunk)
    return control / len(chunk) < 0.05
