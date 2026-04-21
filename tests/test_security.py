from aegis.security import (
    generate_api_key,
    hash_password,
    split_api_key,
    verify_api_secret,
    verify_password,
)


def test_password_round_trip():
    h = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", h)
    assert not verify_password("wrong", h)


def test_api_key_round_trip():
    gen = generate_api_key()
    assert gen.full.startswith("aeg_")
    parts = split_api_key(gen.full)
    assert parts is not None
    prefix, secret = parts
    assert prefix == gen.prefix
    assert verify_api_secret(secret, gen.secret_hash)
    assert not verify_api_secret("nope", gen.secret_hash)


def test_split_handles_malformed_keys():
    assert split_api_key("") is None
    assert split_api_key("Bearer xyz") is None
    assert split_api_key("aeg_live_no_dot") is None
