"""Safe Git subprocess wrappers."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from secretscanner.exceptions import GitError


def run_git(repo: Path, arguments: list[str], *, check: bool = True) -> str:
    """Run Git without a shell and return UTF-8 text with replacement decoding."""
    git_binary = shutil.which("git")
    if git_binary is None:
        raise GitError("Git is not installed or not available on PATH.")
    command = [git_binary, "-c", "core.quotepath=false", *arguments]
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            cwd=repo,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError("Git command could not be executed safely.") from exc
    if check and completed.returncode != 0:
        detail = (
            completed.stderr.strip().splitlines()[-1]
            if completed.stderr.strip()
            else "unknown error"
        )
        raise GitError(f"Git command failed: {detail}")
    return completed.stdout


def repository_root(path: Path) -> Path:
    root = run_git(path.resolve(), ["rev-parse", "--show-toplevel"]).strip()
    return Path(root)
