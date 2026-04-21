"""Audit logging + lightweight anomaly detection.

Anomaly detection here is intentionally simple — it gives operators a useful
signal in the dashboard out of the box, and it's pluggable so you can replace
it with a streaming detector (Kinesis Analytics, Flink, etc.) later.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEvent

log = logging.getLogger("aegis.audit")

EXCERPT_MAX = 4_000


def _excerpt(text: str, allow: bool) -> str | None:
    if not allow or not text:
        return None
    if len(text) <= EXCERPT_MAX:
        return text
    return text[: EXCERPT_MAX] + f"\n…[truncated {len(text) - EXCERPT_MAX} chars]"


async def record_event(
    session: AsyncSession,
    *,
    tenant_id: str,
    request_id: str,
    actor_kind: str,
    actor_id: str | None,
    actor_label: str | None,
    provider: str | None,
    model: str | None,
    route: str,
    decision: str,
    severity: str,
    findings: list[dict[str, Any]],
    input_text: str,
    output_text: str,
    latency_ms: int,
    store_excerpts: bool,
    extra: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        tenant_id=tenant_id,
        request_id=request_id,
        actor_kind=actor_kind,
        actor_id=actor_id,
        actor_label=actor_label,
        provider=provider,
        model=model,
        route=route,
        decision=decision,
        severity=severity,
        findings=findings,
        input_chars=len(input_text or ""),
        output_chars=len(output_text or ""),
        latency_ms=latency_ms,
        request_excerpt=_excerpt(input_text, store_excerpts),
        response_excerpt=_excerpt(output_text, store_excerpts),
        extra=extra or {},
    )
    session.add(event)
    log.info(
        "audit",
        extra={
            "request_id": request_id,
            "tenant_id": tenant_id,
            "policy_decision": decision,
        },
    )
    return event


# --- in-memory anomaly tracker --------------------------------------------------

@dataclass
class _Window:
    events: deque[tuple[datetime, str]]


class AnomalyTracker:
    """Tracks per-tenant block/redact rates over a sliding window."""

    def __init__(self, window: timedelta = timedelta(minutes=10), capacity: int = 5_000):
        self._windows: dict[str, _Window] = {}
        self._window = window
        self._capacity = capacity

    def record(self, tenant_id: str, decision: str) -> None:
        w = self._windows.setdefault(tenant_id, _Window(events=deque(maxlen=self._capacity)))
        w.events.append((datetime.utcnow(), decision))
        self._evict(w)

    def _evict(self, w: _Window) -> None:
        cutoff = datetime.utcnow() - self._window
        while w.events and w.events[0][0] < cutoff:
            w.events.popleft()

    def stats(self, tenant_id: str) -> dict[str, int]:
        w = self._windows.get(tenant_id)
        if not w:
            return {"total": 0, "allow": 0, "redact": 0, "block": 0, "error": 0}
        self._evict(w)
        out = {"total": 0, "allow": 0, "redact": 0, "block": 0, "error": 0}
        for _, d in w.events:
            out["total"] += 1
            out[d] = out.get(d, 0) + 1
        return out

    def is_anomalous(self, tenant_id: str, *, min_total: int = 25, block_ratio: float = 0.4) -> bool:
        s = self.stats(tenant_id)
        if s["total"] < min_total:
            return False
        return (s["block"] / s["total"]) >= block_ratio


tracker = AnomalyTracker()
