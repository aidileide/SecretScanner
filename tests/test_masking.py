from secretscanner.utils.masking import mask_database_url, mask_secret


def test_short_and_long_values_are_masked() -> None:
    assert mask_secret("abcd") == "****"
    assert mask_secret("abcdefghij") == "abcd******ghij"


def test_private_key_and_database_password_are_masked() -> None:
    header = "-----BEGIN PRIVATE KEY-----"  # secretscanner: allow
    assert mask_secret(header).endswith("... [redacted]")
    url = "postgres://alice:correct-horse@db.example/app"  # secretscanner: allow
    masked = mask_database_url(url)
    assert "correct-horse" not in masked
    assert masked == "postgres://alice:********@db.example/app"  # secretscanner: allow
