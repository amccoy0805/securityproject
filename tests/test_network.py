from aegis.safety.network import ip_allowed, same_network


def test_empty_allowlist_permits_everything():
    assert ip_allowed("8.8.8.8", "")


def test_explicit_allowlist_permits_match():
    assert ip_allowed("8.8.8.8", "8.8.8.8")
    assert not ip_allowed("8.8.4.4", "8.8.8.8")


def test_cidr_allowlist():
    assert ip_allowed("10.0.0.5", "10.0.0.0/24")
    assert not ip_allowed("10.0.1.5", "10.0.0.0/24")


def test_multiple_entries():
    allowed = "192.168.1.0/24, 8.8.8.8"
    assert ip_allowed("192.168.1.99", allowed)
    assert ip_allowed("8.8.8.8", allowed)
    assert not ip_allowed("9.9.9.9", allowed)


def test_invalid_presented_ip_is_rejected():
    assert not ip_allowed("not-an-ip", "10.0.0.0/8")


def test_same_network_v4():
    assert same_network("10.0.0.5", "10.0.0.250")
    assert not same_network("10.0.0.5", "10.0.1.5")


def test_same_network_handles_blanks():
    assert not same_network("", "10.0.0.5")
    assert not same_network("10.0.0.5", "")
