from secretscanner.scanner.entropy import entropy_candidates, shannon_entropy


def test_entropy_finds_random_looking_token() -> None:
    value = "p7Kx2Lm9Qw4Nv8Bc3Rt6Yz1Ha5Fd0JsU"  # secretscanner: allow
    assert entropy_candidates(f'key = "{value}"')
    assert shannon_entropy(value) > 4


def test_entropy_ignores_uuid_and_sha256() -> None:
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    sha = "d2a57dc1d883fd21fb9951699df71cc7d1587d58728f6ab36b1bfc78dc9a455f"
    assert entropy_candidates(uuid) == []
    assert entropy_candidates(sha) == []
