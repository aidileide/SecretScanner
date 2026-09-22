"""Stable data models shared by scanners and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceType(StrEnum):
    FILESYSTEM = "filesystem"
    GIT_WORKTREE = "git_worktree"
    GIT_STAGED = "git_staged"
    GIT_HISTORY = "git_history"


SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    confidence: Confidence
    file_path: str
    line_number: int
    column: int
    matched_text_masked: str
    fingerprint: str
    message: str
    remediation: str
    source_type: SourceType
    commit_hash: str | None = None
    matched_text_revealed: str | None = field(default=None, repr=False)

    def to_dict(self, *, show_secrets: bool = False) -> dict[str, Any]:
        result = asdict(self)
        revealed = result.pop("matched_text_revealed")
        result["matched_text"] = (
            revealed if show_secrets and revealed is not None else self.matched_text_masked
        )
        return result


@dataclass(slots=True)
class ScanSummary:
    scanned_files: int = 0
    skipped_files: int = 0
    elapsed_seconds: float = 0.0

    def counts(self, findings: list[Finding]) -> dict[str, int | float]:
        by_severity = {severity.value: 0 for severity in Severity}
        for finding in findings:
            by_severity[finding.severity.value] += 1
        return {
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            **by_severity,
            "total": len(findings),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding]
    summary: ScanSummary
    root: Path

    def has_at_or_above(self, threshold: Severity) -> bool:
        minimum = SEVERITY_RANK[threshold]
        return any(SEVERITY_RANK[item.severity] >= minimum for item in self.findings)
