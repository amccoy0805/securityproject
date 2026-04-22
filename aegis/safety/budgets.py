"""Per-tenant / per-key request, character, and USD budget enforcement.

Goals
-----
- Stop a runaway agent before it costs the customer real money.
- Default-on safety net: even if an admin forgets to configure a budget, the
  *built-in* spec will fire on egregious activity (e.g., 500 calls/min from a
  single key, or $50 spent in 5 minutes).
- Cheap and dependency-free: a sliding-window deque per (tenant, key, window).
  For a multi-replica deployment, swap the storage to Redis using the same
  ``BudgetEnforcer`` interface — nothing else changes.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


@dataclass
class BudgetWindow:
    duration: timedelta
    max_requests: int | None = None
    max_input_chars: int | None = None
    max_output_chars: int | None = None
    max_usd: float | None = None
    label: str = "window"


@dataclass
class BudgetSpec:
    """One tenant's effective budget configuration."""

    enabled: bool = True
    require_explicit_override: bool = True
    per_key_windows: list[BudgetWindow] = field(default_factory=list)
    per_tenant_windows: list[BudgetWindow] = field(default_factory=list)

    @classmethod
    def default(cls) -> BudgetSpec:
        # These are intentionally generous — they exist to catch *runaway*
        # behaviour, not to throttle real usage. Admins should tighten them per
        # tenant via the policy spec.
        return cls(
            enabled=True,
            require_explicit_override=True,
            per_key_windows=[
                BudgetWindow(timedelta(minutes=1), max_requests=120, label="key/minute"),
                BudgetWindow(timedelta(minutes=5), max_usd=25.0, label="key/5min/$"),
                BudgetWindow(timedelta(hours=1), max_requests=2_000, max_usd=100.0, label="key/hour"),
            ],
            per_tenant_windows=[
                BudgetWindow(timedelta(minutes=5), max_usd=100.0, label="tenant/5min/$"),
                BudgetWindow(timedelta(hours=24), max_usd=2_500.0, label="tenant/day/$"),
            ],
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> BudgetSpec:
        if not data:
            return cls.default()
        spec = cls.default()
        if "enabled" in data:
            spec.enabled = bool(data["enabled"])
        if "require_explicit_override" in data:
            spec.require_explicit_override = bool(data["require_explicit_override"])
        for key_attr, key_in in (("per_key_windows", "per_key"), ("per_tenant_windows", "per_tenant")):
            if key_in in data and isinstance(data[key_in], list):
                windows: list[BudgetWindow] = []
                for w in data[key_in]:
                    if not isinstance(w, dict) or "seconds" not in w:
                        continue
                    windows.append(
                        BudgetWindow(
                            duration=timedelta(seconds=int(w["seconds"])),
                            max_requests=w.get("max_requests"),
                            max_input_chars=w.get("max_input_chars"),
                            max_output_chars=w.get("max_output_chars"),
                            max_usd=(float(w["max_usd"]) if w.get("max_usd") is not None else None),
                            label=str(w.get("label", "custom")),
                        )
                    )
                setattr(spec, key_attr, windows)
        return spec


@dataclass
class BudgetCheck:
    allowed: bool
    reason: str | None
    triggered_window: str | None
    snapshot: dict[str, Any]


@dataclass
class _Sample:
    when: datetime
    requests: int
    input_chars: int
    output_chars: int
    cost_usd: float


class _SlidingCounter:
    """Per-bucket sliding window counter."""

    def __init__(self, capacity: int = 10_000):
        self._samples: deque[_Sample] = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def add(self, sample: _Sample) -> None:
        with self._lock:
            self._samples.append(sample)

    def aggregate(self, since: datetime) -> _Sample:
        agg = _Sample(when=since, requests=0, input_chars=0, output_chars=0, cost_usd=0.0)
        with self._lock:
            while self._samples and self._samples[0].when < since:
                self._samples.popleft()
            for s in self._samples:
                agg.requests += s.requests
                agg.input_chars += s.input_chars
                agg.output_chars += s.output_chars
                agg.cost_usd += s.cost_usd
        return agg


class BudgetEnforcer:
    """Tracks usage in-memory across tenants and keys."""

    def __init__(self) -> None:
        self._key_windows: dict[tuple[str, str], _SlidingCounter] = defaultdict(_SlidingCounter)
        self._tenant_windows: dict[str, _SlidingCounter] = defaultdict(_SlidingCounter)

    @staticmethod
    def _violates(window: BudgetWindow, agg: _Sample) -> str | None:
        # Strict-greater so the limit itself is permitted; only over the line is blocked.
        if window.max_requests is not None and agg.requests > window.max_requests:
            return f"{window.label}: {agg.requests}/{window.max_requests} requests"
        if window.max_input_chars is not None and agg.input_chars > window.max_input_chars:
            return f"{window.label}: {agg.input_chars}/{window.max_input_chars} input chars"
        if window.max_output_chars is not None and agg.output_chars > window.max_output_chars:
            return f"{window.label}: {agg.output_chars}/{window.max_output_chars} output chars"
        if window.max_usd is not None and agg.cost_usd > window.max_usd:
            return f"{window.label}: ${agg.cost_usd:.2f}/{window.max_usd:.2f} estimated"
        return None

    def precheck(
        self,
        spec: BudgetSpec,
        *,
        tenant_id: str,
        api_key_id: str,
        projected_input_chars: int,
        projected_cost_usd: float,
    ) -> BudgetCheck:
        """Block *before* the upstream call if the projected request would
        push any window over its cap."""
        if not spec.enabled:
            return BudgetCheck(True, None, None, {})

        now = datetime.utcnow()
        snapshot: dict[str, Any] = {}

        def _check(windows: list[BudgetWindow], counter: _SlidingCounter, scope: str) -> str | None:
            for w in windows:
                agg = counter.aggregate(now - w.duration)
                projected = _Sample(
                    when=now,
                    requests=agg.requests + 1,
                    input_chars=agg.input_chars + projected_input_chars,
                    output_chars=agg.output_chars,
                    cost_usd=agg.cost_usd + projected_cost_usd,
                )
                snapshot[f"{scope}:{w.label}"] = {
                    "requests": projected.requests,
                    "input_chars": projected.input_chars,
                    "cost_usd": round(projected.cost_usd, 6),
                    "limit_requests": w.max_requests,
                    "limit_input_chars": w.max_input_chars,
                    "limit_usd": w.max_usd,
                }
                violation = self._violates(w, projected)
                if violation:
                    return violation
            return None

        violation = _check(
            spec.per_key_windows, self._key_windows[(tenant_id, api_key_id)], "key"
        )
        if violation:
            return BudgetCheck(False, violation, violation.split(":", 1)[0], snapshot)

        violation = _check(spec.per_tenant_windows, self._tenant_windows[tenant_id], "tenant")
        if violation:
            return BudgetCheck(False, violation, violation.split(":", 1)[0], snapshot)

        return BudgetCheck(True, None, None, snapshot)

    def commit(
        self,
        *,
        tenant_id: str,
        api_key_id: str,
        input_chars: int,
        output_chars: int,
        cost_usd: float,
    ) -> None:
        """Record actual usage *after* the upstream call (or attempt)."""
        sample = _Sample(
            when=datetime.utcnow(),
            requests=1,
            input_chars=input_chars,
            output_chars=output_chars,
            cost_usd=cost_usd,
        )
        self._key_windows[(tenant_id, api_key_id)].add(sample)
        self._tenant_windows[tenant_id].add(sample)

    def stats(
        self, tenant_id: str, api_key_id: str | None = None, window_seconds: int = 3600
    ) -> dict[str, Any]:
        since = datetime.utcnow() - timedelta(seconds=window_seconds)
        out: dict[str, Any] = {}
        agg = self._tenant_windows[tenant_id].aggregate(since)
        out["tenant"] = {
            "requests": agg.requests,
            "input_chars": agg.input_chars,
            "output_chars": agg.output_chars,
            "cost_usd": round(agg.cost_usd, 6),
        }
        if api_key_id:
            agg = self._key_windows[(tenant_id, api_key_id)].aggregate(since)
            out["key"] = {
                "requests": agg.requests,
                "input_chars": agg.input_chars,
                "output_chars": agg.output_chars,
                "cost_usd": round(agg.cost_usd, 6),
            }
        return out


enforcer = BudgetEnforcer()
