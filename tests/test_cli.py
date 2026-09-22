from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from secretscanner.cli import app

runner = CliRunner()


def test_help_and_version() -> None:
    assert runner.invoke(app, ["--help"]).exit_code == 0
    version = runner.invoke(app, ["version"])
    assert version.exit_code == 0
    assert "0.1.1" in version.stdout


def test_exit_codes_and_json_output(tmp_path: Path) -> None:
    clean = tmp_path / "clean.txt"
    clean.write_text("hello\n", encoding="utf-8")
    assert runner.invoke(app, ["scan", str(clean)]).exit_code == 0

    secret_file = tmp_path / "secret.txt"
    secret = "github_pat_" + "aB1_" * 14  # secretscanner: allow
    secret_file.write_text(secret, encoding="utf-8")
    report = tmp_path / "result.json"
    result = runner.invoke(
        app,
        ["scan", str(secret_file), "--format", "json", "--output", str(report)],
    )
    assert result.exit_code == 1
    assert secret not in report.read_text(encoding="utf-8")
    assert json.loads(report.read_text(encoding="utf-8"))["findings"]

    missing = runner.invoke(app, ["scan", str(tmp_path / "missing")])
    assert missing.exit_code == 2


def test_incomplete_scan_returns_error_code(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"file-{index}.txt").write_text("safe\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--max-files", "1"])

    assert result.exit_code == 2
    assert "扫描未完整完成" in result.stdout
