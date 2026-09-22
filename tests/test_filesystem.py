from __future__ import annotations

from pathlib import Path

import pytest

from secretscanner.exceptions import SecretScannerError
from secretscanner.scanner.engine import SecretScanner


def test_recursive_scan_honors_ignore_and_binary_detection(
    scanner: SecretScanner, tmp_path: Path
) -> None:
    secret = "ghp_" + "a" * 36
    (tmp_path / "visible.py").write_text(secret, encoding="utf-8")
    (tmp_path / "ignored.txt").write_text(secret, encoding="utf-8")
    (tmp_path / "binary.bin").write_bytes(b"\x00" + secret.encode())
    (tmp_path / ".secretscannerignore").write_text("ignored.txt\n", encoding="utf-8")

    result = scanner.scan_path(tmp_path)

    assert {item.file_path for item in result.findings} == {"visible.py"}
    assert result.summary.skipped_files >= 1


def test_size_limit_skips_large_file(scanner: SecretScanner, tmp_path: Path) -> None:
    (tmp_path / "large.txt").write_text("x" * (1024 * 1024 + 1), encoding="utf-8")
    result = scanner.scan_path(tmp_path, max_file_size_mb=1)
    assert result.summary.skipped_files == 1


def test_missing_target_is_controlled_error(scanner: SecretScanner, tmp_path: Path) -> None:
    with pytest.raises(SecretScannerError, match="does not exist"):
        scanner.scan_path(tmp_path / "missing")


def test_symlink_is_not_followed_by_default(scanner: SecretScanner, tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("ghp_" + "E" * 36, encoding="utf-8")  # secretscanner: allow
    link = tmp_path / "linked.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable on this system")
    result = scanner.scan_path(link)
    assert result.findings == []
