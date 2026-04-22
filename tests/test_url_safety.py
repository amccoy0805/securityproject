from aegis.safety.url_safety import extract_urls, inspect_url


def test_blocks_loopback_by_default():
    v = inspect_url("http://127.0.0.1/admin")
    assert not v.allowed and "loopback" in (v.blocked_reason or "").lower()


def test_blocks_metadata_service_even_when_private_allowed():
    # The cloud-metadata IP is link-local; either reason is acceptable as long
    # as the verdict is to refuse the call.
    v = inspect_url("http://169.254.169.254/latest/meta-data/", allow_private=True)
    assert not v.allowed
    reason = (v.blocked_reason or "").lower()
    assert "metadata" in reason or "link-local" in reason


def test_blocks_rfc1918_unless_allowed():
    v = inspect_url("http://10.0.0.5/api")
    assert not v.allowed
    v2 = inspect_url("http://10.0.0.5/api", allow_private=True)
    assert v2.allowed


def test_blocks_disallowed_schemes():
    for url in ("javascript:alert(1)", "data:text/html,evil", "file:///etc/passwd"):
        v = inspect_url(url)
        assert not v.allowed


def test_allowlist_enforces_domain():
    v_ok = inspect_url("https://api.example.com/x", allow_domains=["example.com"])
    v_bad = inspect_url("https://attacker.example.org/x", allow_domains=["example.com"])
    assert v_ok.allowed and not v_bad.allowed


def test_denylist_blocks_subdomain():
    v = inspect_url("https://evil.attacker.example/x", deny_domains=["attacker.example"])
    assert not v.allowed


def test_warns_on_shortener():
    v = inspect_url("https://bit.ly/abc")
    assert v.allowed
    assert any("shortener" in f.reason for f in v.findings)


def test_extract_urls_walks_nested_dicts():
    args = {"to": "x", "body": "see https://a.example and http://b.example"}
    urls = extract_urls(args)
    assert sorted(urls) == ["http://b.example", "https://a.example"]


def test_extract_urls_in_lists_and_strings():
    urls = extract_urls(["plain text", {"u": "https://x.test"}])
    assert urls == ["https://x.test"]
