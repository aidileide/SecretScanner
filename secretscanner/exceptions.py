"""Expected, user-facing scanner errors."""


class SecretScannerError(Exception):
    """Base class for controlled scanner failures."""


class ConfigurationError(SecretScannerError):
    """Raised for invalid project or rule configuration."""


class GitError(SecretScannerError):
    """Raised when a safe Git subprocess cannot complete."""
