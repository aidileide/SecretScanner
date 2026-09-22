"""Minimal SARIF 2.1.0 output for GitHub Code Scanning."""

from __future__ import annotations

import json

from secretscanner import __version__
from secretscanner.models import Finding, ScanResult, Severity


def sarif_report(result: ScanResult, *, show_secrets: bool = False) -> str:
    rule_map = {finding.rule_id: finding for finding in result.findings}
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecretScanner",
                        "version": __version__,
                        "informationUri": "https://github.com/aidileide/SecretScanner",
                        "rules": [_sarif_rule(item) for item in rule_map.values()],
                    }
                },
                "results": [_sarif_result(item, show_secrets) for item in result.findings],
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _sarif_rule(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_name,
        "shortDescription": {"text": finding.message},
        "help": {"text": finding.remediation},
        "properties": {"security-severity": _security_score(finding.severity)},
    }


def _sarif_result(finding: Finding, show_secrets: bool) -> dict[str, object]:
    value = (
        finding.matched_text_revealed
        if show_secrets and finding.matched_text_revealed
        else finding.matched_text_masked
    )
    return {
        "ruleId": finding.rule_id,
        "level": _level(finding.severity),
        "message": {"text": f"{finding.message} Match: {value}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path.replace("\\", "/")},
                    "region": {
                        "startLine": finding.line_number,
                        "startColumn": finding.column,
                    },
                }
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
        "properties": {
            "confidence": finding.confidence.value,
            "sourceType": finding.source_type.value,
            **({"commit": finding.commit_hash} if finding.commit_hash else {}),
        },
    }


def _level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }[severity]


def _security_score(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "2.0",
    }[severity]
