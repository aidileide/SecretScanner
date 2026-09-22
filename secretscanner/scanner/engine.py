"""Rule, context, entropy, allowlist, and baseline orchestration."""

from __future__ import annotations

import re
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from secretscanner.config import ScannerConfig
from secretscanner.exceptions import SecretScannerError
from secretscanner.models import (
    Confidence,
    Finding,
    ScanProgress,
    ScanResult,
    ScanSummary,
    Severity,
    SourceType,
)
from secretscanner.rules import RuleRegistry
from secretscanner.scanner.entropy import entropy_candidates
from secretscanner.scanner.filesystem import iter_files
from secretscanner.scanner.filters import (
    allowlisted,
    confidence_for_context,
    entropy_allowed_for_path,
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
        self._rules = registry.rules()
        self._always_rules = tuple(rule for rule in self._rules if not rule.keywords)
        keywords = sorted(
            {keyword for rule in self._rules for keyword in rule.keywords},
            key=len,
            reverse=True,
        )
        self._keyword_prefilter = (
            re.compile("|".join(re.escape(keyword) for keyword in keywords)) if keywords else None
        )

    def scan_path(
        self,
        target: Path,
        *,
        source_type: SourceType = SourceType.FILESYSTEM,
        extra_excludes: list[str] | None = None,
        max_file_size_mb: int | None = None,
        follow_symlinks: bool | None = None,
        workers: int | None = None,
        max_files: int | None = None,
        timeout_seconds: int | None = None,
        progress: Callable[[ScanProgress], None] | None = None,
    ) -> ScanResult:
        started = time.perf_counter()
        target = target.expanduser().absolute()
        if not target.exists():
            raise SecretScannerError(f"Scan target does not exist: {target}")
        root = target if target.is_dir() else target.parent
        summary = ScanSummary()
        findings: list[Finding] = []
        ignores = load_ignore_spec(root, [*self.config.exclude, *(extra_excludes or [])])
        size_limit = (max_file_size_mb or self.config.max_file_size_mb) * 1024 * 1024
        follow = self.config.follow_symlinks if follow_symlinks is None else follow_symlinks
        paths = list(iter_files(target, ignores, follow_symlinks=follow))
        summary.discovered_files = len(paths)
        file_limit = max_files or self.config.max_files
        if len(paths) > file_limit:
            paths = paths[:file_limit]
            summary.incomplete = True
            summary.incomplete_reason = f"file limit reached ({file_limit})"
        total = len(paths)
        if progress:
            progress(ScanProgress(total, 0, 0, 0))
        worker_count = max(1, workers or self.config.workers)
        time_limit = timeout_seconds or self.config.timeout_seconds
        deadline = started + time_limit if time_limit else None
        pool = ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="secretscanner")
        try:
            futures = {
                pool.submit(self._scan_file, path, root, size_limit, source_type): path
                for path in paths
            }
            for completed, future in enumerate(as_completed(futures), start=1):
                path = futures[future]
                file_findings, scanned = future.result()
                if scanned:
                    summary.scanned_files += 1
                    findings.extend(file_findings)
                else:
                    summary.skipped_files += 1
                if progress:
                    progress(
                        ScanProgress(
                            total,
                            completed,
                            summary.scanned_files,
                            summary.skipped_files,
                            path.relative_to(root).as_posix(),
                        )
                    )
                if deadline is not None and time.perf_counter() >= deadline:
                    summary.incomplete = True
                    summary.incomplete_reason = f"time limit reached ({time_limit}s)"
                    for pending in futures:
                        pending.cancel()
                    break
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        summary.elapsed_seconds = time.perf_counter() - started
        return ScanResult(_stable_unique(findings), summary, root)

    def _scan_file(
        self,
        path: Path,
        root: Path,
        size_limit: int,
        source_type: SourceType,
    ) -> tuple[list[Finding], bool]:
        try:
            if path.stat().st_size > size_limit or not is_probably_text_file(path):
                return [], False
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return [], False
        relative = path.relative_to(root).as_posix()
        return self.scan_lines(lines, relative, source_type=source_type), True

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
        rule_counts: Counter[str] = Counter()
        finding_limit = self.config.max_findings_per_rule_per_file
        filename = Path(file_path).name
        extension = ".env" if filename.startswith(".env") else Path(file_path).suffix.lower()
        for index, line in enumerate(lines):
            if is_inline_allowed(lines, index):
                continue
            line_number = line_numbers[index] if line_numbers else index + 1
            context: str | None = None
            lowered_line = line.lower()
            occupied: list[tuple[int, int]] = []
            candidate_rules = self._rules
            if self._keyword_prefilter and not self._keyword_prefilter.search(lowered_line):
                candidate_rules = self._always_rules
            for rule in candidate_rules:
                if rule_counts[rule.rule_id] >= finding_limit:
                    continue
                if rule.rule_id == "generic-password" and extension == ".env":
                    continue
                if rule.file_extensions and extension not in rule.file_extensions:
                    continue
                if rule.keywords and not any(keyword in lowered_line for keyword in rule.keywords):
                    continue
                for match in rule.compiled.finditer(line):
                    if context is None:
                        context = "\n".join(lines[max(0, index - 2) : index + 3])
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
                        rule_counts[rule.rule_id] += 1
                        occupied.append((start, start + len(value)))
            if (
                self.config.entropy
                and rule_counts["high-entropy"] < finding_limit
                and entropy_allowed_for_path(file_path)
            ):
                for start, value, score in entropy_candidates(line):
                    if rule_counts["high-entropy"] >= finding_limit:
                        break
                    if any(left <= start < right for left, right in occupied):
                        continue
                    if context is None:
                        context = "\n".join(lines[max(0, index - 2) : index + 3])
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
                        rule_counts["high-entropy"] += 1
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
