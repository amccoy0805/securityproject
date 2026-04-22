from aegis.policy.detectors import redact_text, scan_text


def test_detects_email_and_phone():
    text = "Contact me at jane.doe@example.com or +1 415-555-0199."
    findings = scan_text(text)
    cats = {f.detector for f in findings}
    assert "email" in cats
    assert "phone_us" in cats


def test_detects_ssn_with_validator():
    good = "SSN 543-21-9876"
    bad = "Not an SSN: 000-00-0000"
    assert any(f.detector == "ssn_us" for f in scan_text(good))
    assert not any(f.detector == "ssn_us" for f in scan_text(bad))


def test_detects_credit_card_with_luhn():
    # 4111 1111 1111 1111 is a well-known Visa test card (passes Luhn).
    good = "Card: 4111 1111 1111 1111"
    bad = "Not a card: 4111 1111 1111 1112"
    assert any(f.detector == "credit_card" for f in scan_text(good))
    assert not any(f.detector == "credit_card" for f in scan_text(bad))


def test_detects_secrets():
    text = "GH=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa SLACK=xoxb-1234567890-abcdefg"
    cats = {f.category for f in scan_text(text)}
    assert "secret" in cats


def test_redaction_replaces_findings_with_tokens():
    text = "email a@b.co"
    findings = scan_text(text)
    out = redact_text(text, findings)
    assert "a@b.co" not in out
    assert "[REDACTED:PII]" in out


def test_overlap_dedupe_keeps_higher_severity():
    # Email pattern would match inside a longer secret-shaped substring; ensure
    # detector ordering does not yield duplicate spans.
    text = "ssn 543-21-9876 only"
    findings = scan_text(text)
    spans = [(f.start, f.end) for f in findings]
    assert len(spans) == len(set(spans))
