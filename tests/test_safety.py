from datetime import timedelta

from aegis.pricing import estimate_cost_usd, lookup_price
from aegis.safety.budgets import BudgetEnforcer, BudgetSpec, BudgetWindow
from aegis.safety.loops import LoopDetector


def test_pricing_known_model():
    p = lookup_price("gpt-4o-mini")
    assert p["input"] > 0 and p["output"] > 0


def test_pricing_unknown_model_falls_back():
    p = lookup_price("some-future-model-9000")
    assert p == lookup_price("_default")


def test_pricing_overrides_take_precedence():
    p = lookup_price("acme-llm", overrides={"acme-llm": {"input": 10.0, "output": 30.0}})
    assert p == {"input": 10.0, "output": 30.0}


def test_estimate_cost_scales():
    a = estimate_cost_usd("gpt-4o-mini", 100_000, 50_000)
    b = estimate_cost_usd("gpt-4o-mini", 200_000, 100_000)
    assert b == 2 * a


def test_budget_blocks_when_request_count_exceeded():
    enforcer = BudgetEnforcer()
    spec = BudgetSpec(
        enabled=True,
        require_explicit_override=True,
        per_key_windows=[BudgetWindow(timedelta(minutes=1), max_requests=3, label="key/min")],
        per_tenant_windows=[],
    )
    for _ in range(3):
        check = enforcer.precheck(
            spec, tenant_id="t1", api_key_id="k1", projected_input_chars=10, projected_cost_usd=0.0
        )
        assert check.allowed
        enforcer.commit(tenant_id="t1", api_key_id="k1", input_chars=10, output_chars=10, cost_usd=0.0)

    check = enforcer.precheck(
        spec, tenant_id="t1", api_key_id="k1", projected_input_chars=10, projected_cost_usd=0.0
    )
    assert not check.allowed
    assert "requests" in (check.reason or "")


def test_budget_blocks_when_usd_exceeded():
    enforcer = BudgetEnforcer()
    spec = BudgetSpec(
        enabled=True,
        require_explicit_override=True,
        per_key_windows=[],
        per_tenant_windows=[BudgetWindow(timedelta(minutes=5), max_usd=1.0, label="tenant/5min/$")],
    )
    enforcer.commit(tenant_id="t1", api_key_id="k1", input_chars=0, output_chars=0, cost_usd=0.95)
    check = enforcer.precheck(
        spec, tenant_id="t1", api_key_id="k1", projected_input_chars=0, projected_cost_usd=0.10
    )
    assert not check.allowed
    assert "$" in (check.reason or "")


def test_loop_detector_fires_after_threshold():
    det = LoopDetector(window=timedelta(seconds=60), threshold=3)
    for _ in range(2):
        v = det.observe(tenant_id="t", api_key_id="k", model="m", text="same prompt")
        assert not v.looping
    v = det.observe(tenant_id="t", api_key_id="k", model="m", text="same prompt")
    assert v.looping
    assert v.repeat_count == 3


def test_loop_detector_normalises_whitespace():
    det = LoopDetector(window=timedelta(seconds=60), threshold=2)
    det.observe(tenant_id="t", api_key_id="k", model="m", text="hello   world")
    v = det.observe(tenant_id="t", api_key_id="k", model="m", text="hello\nworld")
    assert v.looping


def test_loop_detector_isolates_keys():
    det = LoopDetector(window=timedelta(seconds=60), threshold=2)
    det.observe(tenant_id="t", api_key_id="kA", model="m", text="x")
    v = det.observe(tenant_id="t", api_key_id="kB", model="m", text="x")
    assert not v.looping
