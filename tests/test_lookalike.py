from aegis.safety.url_safety import inspect_url, is_lookalike


def test_lookalike_detects_homoglyph_zero_for_o():
    assert is_lookalike("g00gle.com", "google.com")


def test_lookalike_detects_one_for_l():
    assert is_lookalike("goog1e.com", "google.com")


def test_lookalike_detects_cyrillic_a():
    assert is_lookalike("\u0430pple.com", "apple.com")


def test_lookalike_ignores_exact_match():
    assert not is_lookalike("google.com", "google.com")


def test_lookalike_ignores_legit_subdomain():
    assert not is_lookalike("mail.google.com", "google.com")


def test_url_inspect_blocks_lookalike():
    v = inspect_url("https://g00gle.com/login", protected_domains=["google.com"])
    assert not v.allowed
    assert "lookalike" in (v.blocked_reason or "").lower() or "spoof" in (v.blocked_reason or "").lower()


def test_url_inspect_allows_real_brand():
    v = inspect_url("https://accounts.google.com/login", protected_domains=["google.com"])
    assert v.allowed
