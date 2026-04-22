from aegis.pricing import (
    cost_from_usage,
    estimate_cost_usd,
    normalise_usage,
)


def test_cost_from_usage_openai_shape():
    usage = {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}
    cost = cost_from_usage("gpt-4o-mini", usage)
    assert cost is not None and cost > 0


def test_cost_from_usage_anthropic_shape():
    usage = {"input_tokens": 1000, "output_tokens": 500}
    cost = cost_from_usage("claude-3-5-sonnet", usage)
    assert cost is not None and cost > 0


def test_cost_from_usage_returns_none_when_absent():
    assert cost_from_usage("gpt-4o-mini", None) is None
    assert cost_from_usage("gpt-4o-mini", {}) is None
    assert cost_from_usage("gpt-4o-mini", {"foo": 1}) is None


def test_normalise_handles_openai():
    n = normalise_usage({"prompt_tokens": 10, "completion_tokens": 20})
    assert n == {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}


def test_normalise_handles_anthropic():
    n = normalise_usage({"input_tokens": 5, "output_tokens": 7})
    assert n == {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}


def test_normalise_returns_none_for_unknown_shape():
    assert normalise_usage({"foo": 1}) is None
    assert normalise_usage(None) is None


def test_estimate_and_reconcile_are_in_the_same_currency_ballpark():
    """Reconciled (token-based) cost for ~1000 tokens should be of the same
    magnitude as estimated cost for the equivalent ~4000 chars — i.e. one
    is not 100× the other due to a unit mistake."""
    rec = cost_from_usage("gpt-4o-mini", {"prompt_tokens": 1000, "completion_tokens": 0})
    est = estimate_cost_usd("gpt-4o-mini", input_chars=4000, output_chars=0)
    assert 0.1 <= (rec / est) <= 10
