from secretscanner.config import ScannerConfig
from secretscanner.models import SourceType
from secretscanner.rules import RuleRegistry, builtin_rules
from secretscanner.scanner.engine import SecretScanner


def test_findings_are_capped_per_rule_per_file() -> None:
    scanner = SecretScanner(
        ScannerConfig(max_findings_per_rule_per_file=3),
        RuleRegistry(builtin_rules()),
    )
    lines = ["ghp_" + f"A{i:02d}" * 12 for i in range(10)]

    findings = scanner.scan_lines(lines, "tokens.txt", source_type=SourceType.FILESYSTEM)

    github_findings = [item for item in findings if item.rule_id == "github-token"]
    assert len(github_findings) == 3
