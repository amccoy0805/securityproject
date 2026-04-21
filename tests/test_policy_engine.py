from aegis.policy import (
    Decision,
    PolicyInput,
    apply_outbound,
    evaluate_inbound,
)
from aegis.policy.engine import effective_spec


def test_baseline_blocks_high_severity():
    spec = effective_spec(["baseline"])
    decision = evaluate_inbound(spec, PolicyInput(text="card 4111 1111 1111 1111"))
    assert decision.decision == Decision.BLOCK
    assert "pci" in decision.matched_categories


def test_baseline_redacts_medium():
    spec = effective_spec(["baseline"])
    decision = evaluate_inbound(spec, PolicyInput(text="IBAN GB29NWBK60161331926819"))
    assert decision.decision == Decision.REDACT
    assert "[REDACTED:FINANCIAL]" in decision.sanitized_text


def test_baseline_allows_clean_text():
    spec = effective_spec(["baseline"])
    decision = evaluate_inbound(spec, PolicyInput(text="Tell me a fun fact about space."))
    assert decision.decision == Decision.ALLOW
    assert decision.findings == []


def test_hipaa_blocks_phi():
    spec = effective_spec(["hipaa"])
    decision = evaluate_inbound(spec, PolicyInput(text="Patient MRN 123456789, DOB: 01/02/1980."))
    assert decision.decision == Decision.BLOCK


def test_model_allow_list_enforced():
    spec = effective_spec(["baseline"], overrides={"model_allow": ["gpt-4o-mini"]})
    bad = evaluate_inbound(spec, PolicyInput(text="hi", model="gpt-4o"))
    assert bad.decision == Decision.BLOCK
    good = evaluate_inbound(spec, PolicyInput(text="hi", model="gpt-4o-mini"))
    assert good.decision == Decision.ALLOW


def test_model_deny_list_enforced():
    spec = effective_spec(["baseline"], overrides={"model_deny": ["gpt-3.5-turbo"]})
    decision = evaluate_inbound(spec, PolicyInput(text="hi", model="gpt-3.5-turbo"))
    assert decision.decision == Decision.BLOCK


def test_outbound_redacts_secrets_in_response():
    spec = effective_spec(["baseline"])
    text = "Sure, your token is ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    sanitized, findings = apply_outbound(spec, text)
    assert findings, "should detect leaked token"
    assert "ghp_" not in sanitized


def test_max_request_chars_enforced():
    spec = effective_spec(["baseline"], overrides={"max_request_chars": 50})
    decision = evaluate_inbound(spec, PolicyInput(text="x" * 100))
    assert decision.decision == Decision.BLOCK
    assert "exceeds" in decision.reason


def test_profile_merge_takes_strictest_action():
    spec = effective_spec(["baseline", "hipaa"])
    assert spec.actions["medium"] == "block"
    assert spec.actions["high"] == "block"
