"""Audit hash-chain tamper-evidence tests.

Uses the same shared DB as :mod:`test_proxy`; we only assert on the chain
verifier here.
"""

from __future__ import annotations

# This import drags in the same env-var setup + app + DB as the proxy tests,
# so we share state with them rather than racing on env-var mutation.
import pytest

from aegis.audit import compute_event_hash, verify_chain
from aegis.db import session_scope
from aegis.models import AuditEvent
from tests.test_proxy import client  # noqa: F401  (fixture)


async def _write_three_audit_rows(tenant_id: str):
    from aegis.audit import record_event

    async with session_scope() as session:
        for i in range(3):
            await record_event(
                session,
                tenant_id=tenant_id,
                request_id=f"chain-r-{i}",
                actor_kind="system",
                actor_id=None,
                actor_label="chain-test",
                provider="openai",
                model="gpt-4o-mini",
                route="chat/completions",
                decision="allow",
                severity="info",
                findings=[],
                input_text="hi",
                output_text="hello",
                latency_ms=10,
                store_excerpts=True,
            )


async def _tenant_id():
    from sqlalchemy import select

    from aegis.models import Tenant

    async with session_scope() as session:
        r = await session.execute(select(Tenant))
        return r.scalars().first().id


@pytest.mark.asyncio
async def test_chain_verifies_after_writes(client):  # noqa: ARG001  (fixture order)
    tid = await _tenant_id()
    await _write_three_audit_rows(tid)
    async with session_scope() as session:
        result = await verify_chain(session, tid)
    assert result["ok"], result
    assert result["checked"] >= 3


@pytest.mark.asyncio
async def test_chain_detects_tampering(client):  # noqa: ARG001
    tid = await _tenant_id()
    await _write_three_audit_rows(tid)

    from sqlalchemy import desc, select

    async with session_scope() as session:
        rows = (
            await session.execute(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == tid)
                .order_by(desc(AuditEvent.created_at))
                .limit(1)
            )
        ).scalars().all()
        assert len(rows) >= 1
        target = rows[-1]
        target.decision = "tampered"
        session.add(target)

    async with session_scope() as session:
        result = await verify_chain(session, tid)
    assert not result["ok"]
    assert result["first_break_id"] is not None


@pytest.mark.asyncio
async def test_compute_event_hash_is_deterministic():
    from datetime import datetime

    e = AuditEvent(
        tenant_id="t", request_id="r", actor_kind="api_key",
        actor_id="a", actor_label="x", provider="openai", model="gpt-4o-mini",
        route="chat/completions", decision="allow", severity="info",
        findings=[], input_chars=0, output_chars=0, latency_ms=0,
        extra={}, agent_id=None, prev_hash=None,
    )
    e.created_at = datetime(2026, 1, 1, 0, 0, 0)
    h1 = compute_event_hash(e)
    h2 = compute_event_hash(e)
    assert h1 == h2 and len(h1) == 64
