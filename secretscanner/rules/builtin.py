"""Built-in credential patterns. No rule performs network validation."""

from __future__ import annotations

from secretscanner.models import Confidence, Severity
from secretscanner.rules.registry import Rule
from secretscanner.rules.validators import has_database_password, is_plausible_secret

ROTATE_TOKEN = (  # noqa: S105 - remediation text, not a credential
    "Revoke or rotate this credential, remove it from source control, "
    "and use a secret manager or environment variable."
)
ROTATE_KEY = (
    "Rotate the key pair, remove the private key from source control, "
    "and store it in a secure secret manager."
)
CHANGE_PASSWORD = (  # noqa: S105 - remediation text, not a credential
    "Change the password if real, remove it from source, "
    "and use an environment variable or secret manager."
)


def builtin_rules() -> list[Rule]:
    return [
        Rule(
            "aws-access-key",
            "AWS Access Key ID",
            "AWS access key identifier",
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
            "cloud",
            Severity.HIGH,
            Confidence.HIGH,
            ROTATE_TOKEN,
            frozenset({"aws", "cloud"}),
        ),
        Rule(
            "aws-secret-key",
            "AWS Secret Access Key",
            "AWS secret key assignment",
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})",
            "cloud",
            Severity.CRITICAL,
            Confidence.HIGH,
            ROTATE_TOKEN,
            match_group=1,
            validator=is_plausible_secret,
        ),
        Rule(
            "github-token",
            "GitHub Token",
            "GitHub classic or OAuth token",
            r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
            "source-control",
            Severity.CRITICAL,
            Confidence.HIGH,
            ROTATE_TOKEN,
        ),
        Rule(
            "github-fine-grained-token",
            "GitHub Fine-grained PAT",
            "GitHub fine-grained token",
            r"\bgithub_pat_[A-Za-z0-9_]{50,255}\b",
            "source-control",
            Severity.CRITICAL,
            Confidence.HIGH,
            ROTATE_TOKEN,
        ),
        Rule(
            "gitlab-token",
            "GitLab Token",
            "GitLab personal/project token",
            r"\bglpat-[A-Za-z0-9_-]{20,}\b",
            "source-control",
            Severity.HIGH,
            Confidence.HIGH,
            ROTATE_TOKEN,
        ),
        Rule(
            "slack-token",
            "Slack Token",
            "Slack access token",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
            "messaging",
            Severity.HIGH,
            Confidence.HIGH,
            ROTATE_TOKEN,
        ),
        Rule(
            "stripe-live-key",
            "Stripe Live Key",
            "Stripe live secret or restricted key",
            r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b",
            "payment",
            Severity.CRITICAL,
            Confidence.HIGH,
            ROTATE_TOKEN,
        ),
        Rule(
            "google-api-key",
            "Google API Key",
            "Google/GCP API key",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            "cloud",
            Severity.HIGH,
            Confidence.HIGH,
            ROTATE_TOKEN,
        ),
        Rule(
            "jwt",
            "JSON Web Token",
            "JWT-like bearer token",
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            "token",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            ROTATE_TOKEN,
        ),
        Rule(
            "private-key",
            "Private Key",
            "Private key PEM header",
            r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----",
            "private-key",
            Severity.CRITICAL,
            Confidence.HIGH,
            ROTATE_KEY,
        ),
        Rule(
            "database-url",
            "Database Connection String",
            "Database URL containing username and password",
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s\"']+",
            "database",
            Severity.CRITICAL,
            Confidence.HIGH,
            CHANGE_PASSWORD,
            validator=has_database_password,
        ),
        Rule(
            "env-secret",
            "Sensitive Environment Variable",
            "Sensitive value in a dotenv file",
            r"(?i)^\s*(?:API_KEY|SECRET|TOKEN|PASSWORD|DATABASE_URL|PRIVATE_KEY)\s*=\s*[\"']?([^\s\"'#]+)",
            "configuration",
            Severity.HIGH,
            Confidence.HIGH,
            CHANGE_PASSWORD,
            file_extensions=frozenset({".env"}),
            match_group=1,
            validator=is_plausible_secret,
        ),
        Rule(
            "generic-password",
            "Hard-coded Credential",
            "Password, secret, token, or API key assignment",
            r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']",
            "generic",
            Severity.HIGH,
            Confidence.MEDIUM,
            CHANGE_PASSWORD,
            match_group=1,
            validator=is_plausible_secret,
        ),
    ]
