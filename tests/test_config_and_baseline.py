from __future__ import annotations

import json
from pathlib import Path

import pytest

from secretscanner.config import load_config
from secretscanner.exceptions import ConfigurationError
from secretscanner.reporters.baseline import load_baseline, write_baseline
from secretscanner.scanner.engine import SecretScanner


def test_custom_rule_and_rule_override(tmp_path: Path) -> None:
    config = tmp_path / ".secretscanner.yml"
    config.write_text(
        """
rules:
  jwt:
    enabled: false
custom_rules:
  - id: internal-token
    name: Internal token
    regex: 'INT_[A-Z0-9]{12}'
    severity: critical
    confidence: high
""",
        encoding="utf-8",
    )
    _, registry, _ = load_config(tmp_path)
    assert "jwt" not in {rule.rule_id for rule in registry.rules()}
    assert "internal-token" in {rule.rule_id for rule in registry.rules()}


def test_invalid_regex_has_clean_error(tmp_path: Path) -> None:
    (tmp_path / ".secretscanner.yml").write_text(
        "custom_rules:\n  - id: broken-rule\n    name: Broken\n    regex: '[unterminated'\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="Invalid regex"):
        load_config(tmp_path)


def test_invalid_enabled_type_is_rejected(tmp_path: Path) -> None:
    (tmp_path / ".secretscanner.yml").write_text(
        "rules:\n  jwt:\n    enabled: yes-please\n", encoding="utf-8"
    )
    with pytest.raises(ConfigurationError, match="boolean"):
        load_config(tmp_path)


def test_invalid_scan_boolean_is_rejected(tmp_path: Path) -> None:
    (tmp_path / ".secretscanner.yml").write_text("scan:\n  entropy: yes-please\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="scan.entropy must be a boolean"):
        load_config(tmp_path)


def test_baseline_contains_no_secret_and_filters_finding(
    scanner: SecretScanner, tmp_path: Path
) -> None:
    secret = "ghp_" + "B" * 36
    target = tmp_path / "secret.txt"
    target.write_text(secret, encoding="utf-8")
    first = scanner.scan_path(target)
    baseline = tmp_path / "baseline.json"
    write_baseline(first, baseline)
    assert secret not in baseline.read_text(encoding="utf-8")

    filtered = SecretScanner(
        scanner.config,
        scanner.registry,
        baseline_fingerprints=load_baseline(baseline),
    ).scan_path(target)
    assert filtered.findings == []
    assert json.loads(baseline.read_text())["fingerprints"]
