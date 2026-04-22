"""Audit logging + lightweight anomaly detection.

Anomaly detection here is intentionally simple — it gives operators a useful
signal in the dashboard out of the box, and it's pluggable so you can replace
it with a streaming detector (Kinesis Analytics, Flink, etc.) later.

The audit log is **hash-chained** for tamper-evidence: each row stores
``prev_hash`` (the previous row's hash for the same tenant) and ``this_hash``
(SHA-256 over a canonical payload). :func:`verify_chain` re-checks the chain
end-to-end. This gives forensic confidence even on a single-table SQLite
deployment; for "real" tamper resistance, replicate the table to a WORM
store (S3 Object Lock / QLDB) on top.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import desc, select
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


def _canonical_payload(event: AuditEvent) -> str:
    payload = {
        "tenant_id": event.tenant_id,
        "request_id": event.request_id,
        "actor_kind": event.actor_kind,
        "actor_id": event.actor_id,
        "actor_label": event.actor_label,
        "provider": event.provider,
        "model": event.model,
        "route": event.route,
        "decision": event.decision,
        "severity": event.severity,
        "findings": event.findings or [],
        "input_chars": event.input_chars,
        "output_chars": event.output_chars,
        "latency_ms": event.latency_ms,
        "extra": event.extra or {},
        "agent_id": event.agent_id,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_event_hash(event: AuditEvent) -> str:
    h = hashlib.sha256()
    h.update((event.prev_hash or "").encode("utf-8"))
    h.update(b"\x00")
    h.update(_canonical_payload(event).encode("utf-8"))
    return h.hexdigest()


async def _last_hash_for(session: AsyncSession, tenant_id: str) -> str | None:
    result = await session.execute(
        select(AuditEvent.this_hash)
        .where(AuditEvent.tenant_id == tenant_id, AuditEvent.this_hash.isnot(None))
        .order_by(desc(AuditEvent.created_at))
        .limit(1)
    )
    return result.scalar_one_or_none()


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
    agent_id: str | None = None,
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
        agent_id=agent_id,
    )
    event.created_at = datetime.utcnow()
    event.prev_hash = await _last_hash_for(session, tenant_id)
    event.this_hash = compute_event_hash(event)
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


async def verify_chain(session: AsyncSession, tenant_id: str) -> dict[str, Any]:
    """Re-walk the audit chain for a tenant; return verification result.

    Output ``{ "ok": bool, "checked": int, "first_break_id": str | None,
                "first_break_reason": str | None }``.
    """
    rows = (
        await session.execute(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        )
    ).scalars().all()
    expected_prev: str | None = None
    for ev in rows:
        if ev.prev_hash != expected_prev:
            return {
                "ok": False,
                "checked": 0,
                "first_break_id": ev.id,
                "first_break_reason": (
                    f"prev_hash mismatch (expected {expected_prev!r}, "
                    f"saw {ev.prev_hash!r})"
                ),
            }
        recomputed = compute_event_hash(ev)
        if recomputed != ev.this_hash:
            return {
                "ok": False,
                "checked": 0,
                "first_break_id": ev.id,
                "first_break_reason": "this_hash mismatch (record was modified after write)",
            }
        expected_prev = ev.this_hash
    return {"ok": True, "checked": len(rows), "first_break_id": None, "first_break_reason": None}


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
