"""Conservative Shannon-entropy candidate detection."""

from __future__ import annotations

import math
import re
from collections import Counter

from secretscanner.rules.validators import not_uuid_or_hash

TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{20,}(?![A-Za-z0-9])")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def entropy_candidates(line: str) -> list[tuple[int, str, float]]:
    candidates: list[tuple[int, str, float]] = []
    if "://" in line:
        return candidates
    for match in TOKEN_PATTERN.finditer(line):
        value = match.group(0).rstrip("=")
        if len(value) < 20 or not not_uuid_or_hash(value):
            continue
        character_groups = sum(
            bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]")
        )
        if character_groups < 3:
            continue
        if value.startswith(("http", "https")):
            continue
        threshold = 3.2 if re.fullmatch(r"[0-9a-fA-F]+", value) else 4.2
        score = shannon_entropy(value)
        if score >= threshold:
            candidates.append((match.start(), value, score))
    return candidates
