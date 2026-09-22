"""Masked-by-default JSON reporting."""

from __future__ import annotations

import json

from secretscanner import __version__
from secretscanner.models import ScanResult


def json_report(result: ScanResult, *, show_secrets: bool = False) -> str:
    payload = {
        "version": __version__,
        "summary": result.summary.counts(result.findings),
        "findings": [item.to_dict(show_secrets=show_secrets) for item in result.findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
