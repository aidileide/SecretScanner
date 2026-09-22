from __future__ import annotations

from pathlib import Path

from secretscanner.config import AllowlistConfig, ScannerConfig
from secretscanner.rules import RuleRegistry, builtin_rules
from secretscanner.scanner.engine import SecretScanner


def make_scanner(allowlist: AllowlistConfig) -> SecretScanner:
    return SecretScanner(ScannerConfig(allowlist=allowlist), RuleRegistry(builtin_rules()))


def test_path_and_rule_allowlists(tmp_path: Path) -> None:
    secret = "ghp_" + "F" * 36  # secretscanner: allow
    allowed = tmp_path / "examples" / "sample.py"
    allowed.parent.mkdir()
    allowed.write_text(secret, encoding="utf-8")

    by_path = make_scanner(AllowlistConfig(paths=["examples/**"])).scan_path(tmp_path)
    by_rule = make_scanner(AllowlistConfig(rules={"github-token"})).scan_path(allowed)

    assert by_path.findings == []
    assert not any(item.rule_id == "github-token" for item in by_rule.findings)


def test_fingerprint_allowlist(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("glpat-" + "G7" * 12, encoding="utf-8")  # secretscanner: allow
    first = make_scanner(AllowlistConfig()).scan_path(target)
    fingerprints = {item.fingerprint for item in first.findings}

    filtered = make_scanner(AllowlistConfig(fingerprints=fingerprints)).scan_path(target)

    assert first.findings
    assert filtered.findings == []
