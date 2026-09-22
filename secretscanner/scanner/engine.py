"""Rule, context, entropy, allowlist, and baseline orchestration."""

from __future__ import annotations

import time
from pathlib import Path

from secretscanner.config import ScannerConfig
from secretscanner.exceptions import SecretScannerError
from secretscanner.models import Confidence, Finding, ScanResult, ScanSummary, Severity, SourceType
from secretscanner.rules import RuleRegistry
from secretscanner.scanner.entropy import entropy_candidates
from secretscanner.scanner.filesystem import iter_files
from secretscanner.scanner.filters import (
    allowlisted,
    confidence_for_context,
    is_inline_allowed,
    load_ignore_spec,
)
from secretscanner.utils.masking import finding_fingerprint, mask_secret
from secretscanner.utils.paths import is_probably_text_file


class SecretScanner:
    def __init__(
        self,
        config: ScannerConfig,
        registry: RuleRegistry,
        *,
        show_secrets: bool = False,
        baseline_fingerprints: set[str] | None = None,
    ) -> None:
        self.config = config
        self.registry = registry
        self.show_secrets = show_secrets
        self.baseline_fingerprints = baseline_fingerprints or set()

    def scan_path(
        self,
        target: Path,
        *,
        source_type: SourceType = SourceType.FILESYSTEM,
        extra_excludes: list[str] | None = None,
        max_file_size_mb: int | None = None,
        follow_symlinks: bool | None = None,
    ) -> ScanResult:
        started = time.perf_counter()
        target = target.expanduser().resolve()
        if not target.exists():
            raise SecretScannerError(f"Scan target does not exist: {target}")
        root = target if target.is_dir() else target.parent
        summary = ScanSummary()
        findings: list[Finding] = []
        ignores = load_ignore_spec(root, [*self.config.exclude, *(extra_excludes or [])])
        size_limit = (max_file_size_mb or self.config.max_file_size_mb) * 1024 * 1024
        follow = self.config.follow_symlinks if follow_symlinks is None else follow_symlinks
        for path in iter_files(target, ignores, follow_symlinks=follow):
            try:
                if path.stat().st_size > size_limit or not is_probably_text_file(path):
                    summary.skipped_files += 1
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                summary.skipped_files += 1
                continue
            summary.scanned_files += 1
            relative = path.relative_to(root).as_posix()
            findings.extend(self.scan_lines(lines, relative, source_type=source_type))
        summary.elapsed_seconds = time.perf_counter() - started
        return ScanResult(_stable_unique(findings), summary, root)

    def scan_lines(
        self,
        lines: list[str],
        file_path: str,
        *,
        source_type: SourceType,
        line_numbers: list[int] | None = None,
        commit_hash: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        filename = Path(file_path).name
        extension = ".env" if filename.startswith(".env") else Path(file_path).suffix.lower()
        for index, line in enumerate(lines):
            if is_inline_allowed(lines, index):
                continue
            line_number = line_numbers[index] if line_numbers else index + 1
            context = "\n".join(lines[max(0, index - 2) : index + 3])
            occupied: list[tuple[int, int]] = []
            for rule in self.registry.rules():
                if rule.rule_id == "generic-password" and extension == ".env":
                    continue
                if rule.file_extensions and extension not in rule.file_extensions:
                    continue
                for match in rule.compiled.finditer(line):
                    try:
                        value = match.group(rule.match_group)
                        start = match.start(rule.match_group)
                    except IndexError:
                        continue
                    if rule.validator and not rule.validator(value, context):
                        continue
                    if any(pattern.lower() in value.lower() for pattern in rule.exclude_patterns):
                        continue
                    finding = self._finding(
                        rule.rule_id,
                        rule.name,
                        rule.category,
                        rule.severity,
                        confidence_for_context(rule.confidence, context),
                        file_path,
                        line_number,
                        start + 1,
                        value,
                        rule.remediation,
                        source_type,
                        commit_hash,
                    )
                    if finding:
                        findings.append(finding)
                        occupied.append((start, start + len(value)))
            if self.config.entropy:
                for start, value, score in entropy_candidates(line):
                    if any(left <= start < right for left, right in occupied):
                        continue
                    confidence = (
                        Confidence.MEDIUM
                        if any(
                            word in context.lower()
                            for word in ("token", "secret", "password", "key")
                        )
                        else Confidence.LOW
                    )
                    finding = self._finding(
                        "high-entropy",
                        "High Entropy String",
                        "entropy",
                        Severity.MEDIUM,
                        confidence,
                        file_path,
                        line_number,
                        start + 1,
                        value,
                        (
                            f"Review this random-looking value (entropy {score:.2f}) and "
                            "move it to a secret manager if sensitive."
                        ),
                        source_type,
                        commit_hash,
                    )
                    if finding:
                        findings.append(finding)
        return findings

    def _finding(
        self,
        rule_id: str,
        rule_name: str,
        category: str,
        severity: Severity,
        confidence: Confidence,
        file_path: str,
        line_number: int,
        column: int,
        value: str,
        remediation: str,
        source_type: SourceType,
        commit_hash: str | None,
    ) -> Finding | None:
        masked = mask_secret(value)
        fingerprint = finding_fingerprint(rule_id, file_path, line_number, masked)
        if fingerprint in self.baseline_fingerprints:
            return None
        if allowlisted(self.config.allowlist, file_path, rule_id, fingerprint):
            return None
        return Finding(
            rule_id=rule_id,
            rule_name=rule_name,
            category=category,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_number=line_number,
            column=column,
            commit_hash=commit_hash,
            matched_text_masked=masked,
            matched_text_revealed=value if self.show_secrets else None,
            fingerprint=fingerprint,
            message=f"Potential {rule_name} detected.",
            remediation=remediation,
            source_type=source_type,
        )


def _stable_unique(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int, int, str | None]] = set()
    result: list[Finding] = []
    for finding in sorted(
        findings,
        key=lambda item: (item.file_path, item.line_number, item.column, item.rule_id),
    ):
        key = (
            finding.rule_id,
            finding.file_path,
            finding.line_number,
            finding.column,
            finding.commit_hash,
        )
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
