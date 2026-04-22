"""Tests for the Redis-backed budget enforcer + loop detector.

The Redis tests are skipped if no reachable Redis is configured via
``AEGIS_REDIS_URL`` (or ``AEGIS_TEST_REDIS_URL`` for opt-in CI). The
in-memory equivalence test always runs.
"""

from __future__ import annotations

import os
from datetime import timedelta

import pytest

from aegis.safety import get_runtime, reset_runtime, select_backends
from aegis.safety.budgets import BudgetEnforcer, BudgetSpec, BudgetWindow
from aegis.safety.loops import LoopDetector


def _redis_url() -> str | None:
    return os.environ.get("AEGIS_TEST_REDIS_URL") or os.environ.get("AEGIS_REDIS_URL") or None


def test_get_runtime_returns_in_memory_when_no_redis(monkeypatch):
    monkeypatch.delenv("AEGIS_REDIS_URL", raising=False)
    from aegis.config import get_settings
    get_settings.cache_clear()  # type: ignore[attr-defined]
    reset_runtime()
    enforcer, detector = get_runtime()
    assert isinstance(enforcer, BudgetEnforcer)
    assert isinstance(detector, LoopDetector)
    reset_runtime()


def test_select_backends_falls_back_when_redis_unreachable(monkeypatch):
    monkeypatch.setenv("AEGIS_REDIS_URL", "redis://127.0.0.1:1/0")  # invalid port + DB
    from aegis.config import get_settings
    get_settings.cache_clear()  # type: ignore[attr-defined]
    enforcer, detector = select_backends()
    assert isinstance(enforcer, BudgetEnforcer)
    assert isinstance(detector, LoopDetector)
    monkeypatch.delenv("AEGIS_REDIS_URL", raising=False)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    reset_runtime()


@pytest.mark.skipif(_redis_url() is None, reason="No reachable Redis configured")
def test_redis_budget_enforcer_blocks_on_request_count():
    from aegis.safety.redis_backend import RedisBudgetEnforcer, is_available

    url = _redis_url()
    assert is_available(url), f"Redis unreachable at {url}"

    enforcer = RedisBudgetEnforcer(url)
    spec = BudgetSpec(
        enabled=True,
        require_explicit_override=True,
        per_key_windows=[BudgetWindow(timedelta(minutes=1), max_requests=2, label="rt-min")],
        per_tenant_windows=[],
    )
    tid, kid = "t-rb", "k-rb"
    # Fresh prefix per run.
    import uuid
    tid = f"t-{uuid.uuid4().hex[:8]}"
    kid = f"k-{uuid.uuid4().hex[:8]}"

    for _ in range(2):
        check = enforcer.precheck(spec, tenant_id=tid, api_key_id=kid,
                                  projected_input_chars=1, projected_cost_usd=0.0)
        assert check.allowed
        enforcer.commit(tenant_id=tid, api_key_id=kid, input_chars=1,
                        output_chars=1, cost_usd=0.0)

    blocked = enforcer.precheck(spec, tenant_id=tid, api_key_id=kid,
                                projected_input_chars=1, projected_cost_usd=0.0)
    assert not blocked.allowed
    assert "requests" in (blocked.reason or "")


@pytest.mark.skipif(_redis_url() is None, reason="No reachable Redis configured")
def test_redis_loop_detector_fires_after_threshold():
    from aegis.safety.redis_backend import RedisLoopDetector, is_available

    url = _redis_url()
    assert is_available(url), f"Redis unreachable at {url}"

    import uuid
    det = RedisLoopDetector(url, window=timedelta(seconds=60), threshold=3)
    tid, kid = f"t-{uuid.uuid4().hex[:8]}", f"k-{uuid.uuid4().hex[:8]}"
    for _ in range(2):
        v = det.observe(tenant_id=tid, api_key_id=kid, model="m", text="same prompt")
        assert not v.looping
    v = det.observe(tenant_id=tid, api_key_id=kid, model="m", text="same prompt")
    assert v.looping and v.repeat_count == 3


def test_in_memory_and_redis_have_compatible_shape():
    """The proxy must be able to swap one for the other without code changes."""
    enforcer = BudgetEnforcer()
    spec = BudgetSpec.default()
    pre = enforcer.precheck(spec, tenant_id="t", api_key_id="k",
                            projected_input_chars=1, projected_cost_usd=0.0)
    assert hasattr(pre, "allowed") and hasattr(pre, "reason")
    enforcer.commit(tenant_id="t", api_key_id="k", input_chars=1, output_chars=1, cost_usd=0.0)
    s = enforcer.stats("t", "k", window_seconds=60)
    assert "tenant" in s and "key" in s
