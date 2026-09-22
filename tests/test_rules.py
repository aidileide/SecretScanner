from __future__ import annotations

from secretscanner.models import SourceType
from secretscanner.scanner.engine import SecretScanner


def scan(scanner: SecretScanner, *lines: str):
    return scanner.scan_lines(list(lines), "settings.py", source_type=SourceType.FILESYSTEM)


def test_detects_github_token_and_masks_it(scanner: SecretScanner) -> None:
    secret = "ghp_" + "A1b2" * 9  # secretscanner: allow
    findings = scan(scanner, f'token = "{secret}"')  # secretscanner: allow
    assert {item.rule_id for item in findings} >= {"github-token"}
    assert all(secret not in item.matched_text_masked for item in findings)
    assert all(item.matched_text_revealed is None for item in findings)


def test_detects_private_key_header(scanner: SecretScanner) -> None:
    findings = scan(scanner, "-----BEGIN PRIVATE KEY-----")  # secretscanner: allow
    assert any(item.rule_id == "private-key" for item in findings)


def test_detects_database_url_and_masks_password(scanner: SecretScanner) -> None:
    secret = (  # secretscanner: allow
        "postgresql://admin:CorrectHorseBatteryStaple@db.internal:5432/app"  # secretscanner: allow
    )
    findings = scan(scanner, f'DATABASE_URL = "{secret}"')
    database = next(item for item in findings if item.rule_id == "database-url")
    assert "CorrectHorseBatteryStaple" not in database.matched_text_masked
    assert "db.internal:5432/app" in database.matched_text_masked


def test_detects_generic_password(scanner: SecretScanner) -> None:
    findings = scan(scanner, 'password = "Tr0ub4dor&3"')  # secretscanner: allow
    assert any(item.rule_id == "generic-password" for item in findings)


def test_placeholder_password_is_ignored(scanner: SecretScanner) -> None:
    findings = scan(scanner, 'password = "changeme"  # example')
    assert not any(item.rule_id == "generic-password" for item in findings)


def test_env_rule_only_applies_to_dotenv(scanner: SecretScanner) -> None:
    secret = "A9zX2kLm7Qw4Nv8Bc3Rt"  # secretscanner: allow
    env = scanner.scan_lines([f"API_KEY={secret}"], ".env.local", source_type=SourceType.FILESYSTEM)
    plain = scanner.scan_lines(
        [f"API_KEY={secret}"], "notes.txt", source_type=SourceType.FILESYSTEM
    )
    assert any(item.rule_id == "env-secret" for item in env)
    assert not any(item.rule_id == "env-secret" for item in plain)


def test_inline_suppression(scanner: SecretScanner) -> None:
    secret = "ghp_" + "x" * 36
    findings = scan(
        scanner,
        "# secretscanner: allow-next-line",
        secret,
        f"{secret}  # secretscanner: allow",
    )
    assert findings == []
