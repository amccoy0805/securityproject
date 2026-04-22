
import pytest

from aegis.safety.vault import decrypt, encrypt, fingerprint


@pytest.fixture(autouse=True)
def _set_key(monkeypatch):
    monkeypatch.setenv("AEGIS_VAULT_KEY", "test-vault-key-test-vault-key-test")


def test_round_trip():
    ct = encrypt("hello world")
    assert ct.startswith("aegisvault.v1:")
    assert decrypt(ct) == "hello world"


def test_each_encryption_uses_fresh_nonce():
    a = encrypt("same plaintext")
    b = encrypt("same plaintext")
    assert a != b
    assert decrypt(a) == decrypt(b) == "same plaintext"


def test_tamper_detection_flips_byte(monkeypatch):
    ct = encrypt("very secret")
    # Flip the last char of the ciphertext segment.
    parts = ct.rsplit(":", 1)
    tampered = parts[0] + ":" + (parts[1][:-2] + ("AA" if not parts[1].endswith("AA") else "BB"))
    with pytest.raises(ValueError):
        decrypt(tampered)


def test_wrong_key_cannot_decrypt(monkeypatch):
    ct = encrypt("payload")
    monkeypatch.setenv("AEGIS_VAULT_KEY", "different-vault-key-different-key")
    with pytest.raises(ValueError):
        decrypt(ct)


def test_fingerprint_is_stable_and_short():
    fp = fingerprint("payload")
    assert len(fp) == 16
    assert fp == fingerprint("payload")
    assert fp != fingerprint("different")
