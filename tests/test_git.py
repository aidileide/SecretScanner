from __future__ import annotations

from pathlib import Path

from conftest import git

from secretscanner.models import SourceType
from secretscanner.scanner.engine import SecretScanner
from secretscanner.scanner.git import GitScanner, parse_added_lines


def test_parse_added_lines_tracks_new_line_numbers() -> None:
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -3,0 +4,2 @@
+safe = True
+token = \"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"  # secretscanner: allow
"""
    assert parse_added_lines(diff) == [
        (
            "app.py",
            [
                "safe = True",
                'token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # secretscanner: allow',
            ],
            [4, 5],
        )
    ]


def test_staged_scans_only_added_lines(scanner: SecretScanner, git_repo: Path) -> None:
    file = git_repo / "app.py"
    file.write_text("safe = True\n", encoding="utf-8")
    git(git_repo, "add", "app.py")
    git(git_repo, "commit", "-m", "initial")
    secret = "ghp_" + "C" * 36  # secretscanner: allow
    file.write_text(f"safe = True\ntoken = '{secret}'\n", encoding="utf-8")
    git(git_repo, "add", "app.py")

    result = GitScanner(scanner).scan_staged(git_repo)

    assert len(result.findings) >= 1
    assert all(item.line_number == 2 for item in result.findings)
    assert all(item.source_type is SourceType.GIT_STAGED for item in result.findings)


def test_history_includes_commit_hash(scanner: SecretScanner, git_repo: Path) -> None:
    secret = "glpat-" + "D" * 24  # secretscanner: allow
    (git_repo / "config.txt").write_text(secret, encoding="utf-8")
    git(git_repo, "add", "config.txt")
    git(git_repo, "commit", "-m", "add config")

    result = GitScanner(scanner).scan_history(git_repo, max_commits=1)

    assert result.findings
    assert all(item.commit_hash for item in result.findings)
    assert all(item.source_type is SourceType.GIT_HISTORY for item in result.findings)
