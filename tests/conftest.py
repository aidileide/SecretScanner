from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from secretscanner.config import ScannerConfig
from secretscanner.rules import RuleRegistry, builtin_rules
from secretscanner.scanner.engine import SecretScanner


@pytest.fixture
def scanner() -> SecretScanner:
    return SecretScanner(ScannerConfig(), RuleRegistry(builtin_rules()))


def git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.name", "SecretScanner Tests")
    git(tmp_path, "config", "user.email", "tests@example.invalid")
    return tmp_path
