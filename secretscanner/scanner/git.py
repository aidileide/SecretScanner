"""Git worktree, staged diff, and bounded history scanners."""

from __future__ import annotations

import re
import time
from pathlib import Path

from secretscanner.models import ScanResult, ScanSummary, SourceType
from secretscanner.scanner.engine import SecretScanner
from secretscanner.scanner.filters import load_ignore_spec
from secretscanner.utils.git_utils import repository_root, run_git
from secretscanner.utils.paths import is_probably_text_file

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class GitScanner:
    def __init__(self, scanner: SecretScanner) -> None:
        self.scanner = scanner

    def scan_worktree(self, path: Path, *, include_untracked: bool = False) -> ScanResult:
        started = time.perf_counter()
        root = repository_root(path)
        tracked = _nul_paths(run_git(root, ["ls-files", "-z"]))
        if include_untracked:
            tracked.extend(
                _nul_paths(run_git(root, ["ls-files", "--others", "--exclude-standard", "-z"]))
            )
        ignores = load_ignore_spec(root, self.scanner.config.exclude)
        summary = ScanSummary()
        findings = []
        size_limit = self.scanner.config.max_file_size_mb * 1024 * 1024
        for relative in sorted(set(tracked)):
            if ignores.match_file(relative):
                summary.skipped_files += 1
                continue
            file_path = root / relative
            try:
                if (
                    not file_path.is_file()
                    or file_path.is_symlink()
                    or file_path.stat().st_size > size_limit
                    or not is_probably_text_file(file_path)
                ):
                    summary.skipped_files += 1
                    continue
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                summary.skipped_files += 1
                continue
            summary.scanned_files += 1
            findings.extend(
                self.scanner.scan_lines(lines, relative, source_type=SourceType.GIT_WORKTREE)
            )
        summary.elapsed_seconds = time.perf_counter() - started
        return ScanResult(findings, summary, root)

    def scan_staged(self, path: Path) -> ScanResult:
        started = time.perf_counter()
        root = repository_root(path)
        diff = run_git(
            root,
            ["diff", "--cached", "--no-color", "--unified=0", "--diff-filter=ACMR"],
        )
        findings = []
        parsed = parse_added_lines(diff)
        for file_path, lines, numbers in parsed:
            findings.extend(
                self.scanner.scan_lines(
                    lines,
                    file_path,
                    source_type=SourceType.GIT_STAGED,
                    line_numbers=numbers,
                )
            )
        summary = ScanSummary(
            scanned_files=len(parsed),
            elapsed_seconds=time.perf_counter() - started,
        )
        return ScanResult(findings, summary, root)

    def scan_history(
        self,
        path: Path,
        *,
        max_commits: int = 100,
        since: str | None = None,
    ) -> ScanResult:
        started = time.perf_counter()
        root = repository_root(path)
        log_args = ["log", f"--max-count={max_commits}", "--format=%H"]
        if since:
            log_args.insert(1, f"--since={since}")
        commits = [line for line in run_git(root, log_args).splitlines() if line]
        findings = []
        scanned_sections = 0
        for commit in commits:
            diff = run_git(
                root,
                [
                    "show",
                    "--format=",
                    "--no-color",
                    "--unified=0",
                    "--diff-filter=AM",
                    commit,
                ],
            )
            parsed = parse_added_lines(diff)
            scanned_sections += len(parsed)
            for file_path, lines, numbers in parsed:
                findings.extend(
                    self.scanner.scan_lines(
                        lines,
                        file_path,
                        source_type=SourceType.GIT_HISTORY,
                        line_numbers=numbers,
                        commit_hash=commit,
                    )
                )
        summary = ScanSummary(
            scanned_files=scanned_sections,
            elapsed_seconds=time.perf_counter() - started,
        )
        return ScanResult(findings, summary, root)


def _nul_paths(output: str) -> list[str]:
    return [item for item in output.split("\0") if item]


def parse_added_lines(diff: str) -> list[tuple[str, list[str], list[int]]]:
    """Extract only added diff content and its new-file line numbers."""
    sections: list[tuple[str, list[str], list[int]]] = []
    current_path: str | None = None
    current_lines: list[str] = []
    current_numbers: list[int] = []
    next_line: int | None = None

    def flush() -> None:
        nonlocal current_lines, current_numbers
        if current_path is not None and current_lines:
            sections.append((current_path, current_lines, current_numbers))
        current_lines = []
        current_numbers = []

    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            flush()
            current_path = None
            next_line = None
        elif raw.startswith("+++ b/"):
            current_path = raw[6:]
        elif raw.startswith("+++ /dev/null"):
            current_path = None
        elif match := HUNK.match(raw):
            next_line = int(match.group(1))
        elif next_line is not None and raw.startswith("+") and not raw.startswith("+++"):
            current_lines.append(raw[1:])
            current_numbers.append(next_line)
            next_line += 1
        elif next_line is not None and raw.startswith("-") and not raw.startswith("---"):
            continue
        elif next_line is not None and not raw.startswith("\\"):
            next_line += 1
    flush()
    return sections
