import pytest

from aegis.safety.agents import (
    AgentObservation,
    compute_risk,
    derive_agent_name,
    fold_observation,
)


class _FakeAgent:
    def __init__(self):
        self.autonomy = "supervised"
        self.risk_factors: dict = {}
        self.risk_score = 0
        self.request_count = 1
        self.block_count = 0


# ---- naming + risk ----

def test_derive_uses_explicit_header_when_present():
    name = derive_agent_name(header_value="my-bot", api_key_name="prod-key", model="gpt-4o-mini")
    assert name == "my-bot"


def test_derive_falls_back_to_key_plus_model():
    name = derive_agent_name(header_value=None, api_key_name="prod-key", model="gpt-4o-mini")
    assert name == "prod-key:gpt-4o-mini"


def test_risk_starts_low_for_supervised_agent():
    a = _FakeAgent()
    score, factors = compute_risk(a)
    assert score < 20
    assert factors["autonomy"] == 5


def test_risk_rises_with_destructive_and_financial_actions():
    a = _FakeAgent()
    a.autonomy = "autonomous"
    fold_observation(a, AgentObservation(
        decision="allow", severity="info", matched_categories=[],
        untrusted_present=True, tool_action_classes=["financial", "destructive"],
    ))
    assert a.risk_score >= 30 + 15 + 15 + 5  # autonomy + financial + destructive + external


def test_risk_caps_at_100():
    a = _FakeAgent()
    a.autonomy = "autonomous"
    a.block_count = 100
    a.request_count = 100
    fold_observation(a, AgentObservation(
        decision="block", severity="high",
        matched_categories=["injection", "secret"],
        untrusted_present=True,
        tool_action_classes=["financial", "destructive", "memory_write", "network"],
    ))
    assert a.risk_score == 100


# ---- approvals ----

# The two integration tests below share the same DB / app as test_proxy.py
# (importing the ``client`` fixture forces the proxy module's env-var setup
# to run *first*, so we don't race on AEGIS_DATABASE_URL).
from tests.test_proxy import client  # noqa: E402, F401  (fixture)


@pytest.mark.asyncio
async def test_create_consume_decide_lifecycle(client):  # noqa: ARG001
    """End-to-end: create ticket, decide approve, consume once, can't reuse."""
    from sqlalchemy import select

    from aegis.db import session_scope
    from aegis.models import Tenant
    from aegis.safety.approvals import (
        ApprovalRequest,
        consume_ticket,
        create_ticket,
        decide,
    )

    async with session_scope() as session:
        tenant = (await session.execute(select(Tenant))).scalars().first()
        tid = tenant.id

    async with session_scope() as session:
        ticket = await create_ticket(
            session,
            ApprovalRequest(
                request_id="r1",
                tenant_id=tid,
                api_key_id=None,
                actor_label="alice",
                agent_id=None,
                tool_name="charge_card",
                action_class="financial",
                summary="Charge $50",
                arguments_excerpt='{"amount":50}',
                risk_factors={},
            ),
        )
        ticket_id = ticket.id

    async with session_scope() as session:
        ok, reason = await consume_ticket(session, tenant_id=tid, ticket_id=ticket_id, expected_tool=None)
    assert not ok and "approved" in reason

    async with session_scope() as session:
        await decide(session, tenant_id=tid, ticket_id=ticket_id, decision="approved", decided_by="bob")

    async with session_scope() as session:
        ok, _ = await consume_ticket(session, tenant_id=tid, ticket_id=ticket_id, expected_tool=None)
    assert ok

    async with session_scope() as session:
        ok2, reason2 = await consume_ticket(session, tenant_id=tid, ticket_id=ticket_id, expected_tool=None)
    assert not ok2 and "consumed" in reason2

    async with session_scope() as session:
        t2 = await create_ticket(
            session,
            ApprovalRequest(
                request_id="r2", tenant_id=tid, api_key_id=None, actor_label="alice",
                agent_id=None, tool_name="delete_user",
                action_class="destructive", summary="Delete", arguments_excerpt=None,
                risk_factors={},
            ),
        )
        await decide(session, tenant_id=tid, ticket_id=t2.id, decision="approved", decided_by="bob")
    async with session_scope() as session:
        ok3, reason3 = await consume_ticket(
            session, tenant_id=tid, ticket_id=t2.id, expected_tool="charge_card"
        )
    assert not ok3 and "issued for tool" in reason3


@pytest.mark.asyncio
async def test_expired_ticket_rejected(client):  # noqa: ARG001
    from datetime import timedelta

    from sqlalchemy import select

    from aegis.db import session_scope
    from aegis.models import Tenant
    from aegis.safety.approvals import (
        ApprovalRequest,
        consume_ticket,
        create_ticket,
        decide,
    )

    async with session_scope() as session:
        tenant = (await session.execute(select(Tenant))).scalars().first()
        tid = tenant.id

    async with session_scope() as session:
        ticket = await create_ticket(
            session,
            ApprovalRequest(
                request_id="r-exp", tenant_id=tid, api_key_id=None, actor_label="alice",
                agent_id=None, tool_name=None, action_class="write",
                summary="x", arguments_excerpt=None, risk_factors={},
            ),
            ttl=timedelta(seconds=-1),
        )
        await decide(session, tenant_id=tid, ticket_id=ticket.id, decision="approved", decided_by="bob")

    async with session_scope() as session:
        ok, reason = await consume_ticket(session, tenant_id=tid, ticket_id=ticket.id, expected_tool=None)
    assert not ok and "expired" in reason
