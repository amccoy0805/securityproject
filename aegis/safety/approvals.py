"""Async human-in-the-loop approval workflow.

When the model emits a sensitive tool call without a synchronous approval
header, the proxy creates a ``PendingApproval`` row and returns the ticket
id to the caller. A human visits the admin queue and approves/denies. The
caller (or a cron in the orchestrator) re-submits the original request with
``X-Aegis-Approval-Ticket: <id>`` and the gateway lets the call through.

Tickets expire (default 30 minutes) so a stale "yes" can't be replayed
days later for a new request.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import PendingApproval

DEFAULT_TTL = timedelta(minutes=30)


@dataclass
class ApprovalRequest:
    request_id: str
    tenant_id: str
    api_key_id: str | None
    actor_label: str | None
    agent_id: str | None
    tool_name: str | None
    action_class: str
    summary: str
    arguments_excerpt: str | None
    risk_factors: dict[str, Any]


async def create_ticket(session: AsyncSession, req: ApprovalRequest, *, ttl: timedelta = DEFAULT_TTL) -> PendingApproval:
    ticket = PendingApproval(
        tenant_id=req.tenant_id,
        agent_id=req.agent_id,
        api_key_id=req.api_key_id,
        actor_label=req.actor_label,
        request_id=req.request_id,
        action_class=req.action_class,
        tool_name=req.tool_name,
        summary=req.summary,
        arguments_excerpt=req.arguments_excerpt,
        risk_factors=req.risk_factors,
        status="pending",
        expires_at=datetime.utcnow() + ttl,
    )
    session.add(ticket)
    await session.flush()
    return ticket


async def consume_ticket(
    session: AsyncSession,
    *,
    tenant_id: str,
    ticket_id: str,
    expected_tool: str | None,
) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` and consume the ticket.

    A consumed ticket is moved to ``approved-used`` so it can't be replayed
    for a different request.
    """
    ticket = await session.get(PendingApproval, ticket_id)
    if not ticket or ticket.tenant_id != tenant_id:
        return False, "approval ticket not found for this tenant"
    if ticket.status == "approved-used":
        return False, "approval ticket has already been consumed"
    if ticket.status != "approved":
        return False, f"approval ticket status is '{ticket.status}', not 'approved'"
    if ticket.expires_at and ticket.expires_at < datetime.utcnow():
        ticket.status = "expired"
        session.add(ticket)
        return False, "approval ticket has expired"
    if expected_tool and ticket.tool_name and ticket.tool_name != expected_tool:
        return False, (
            f"approval ticket was issued for tool '{ticket.tool_name}', "
            f"not '{expected_tool}'"
        )
    ticket.status = "approved-used"
    session.add(ticket)
    return True, "approved"


async def list_pending(session: AsyncSession, tenant_id: str, limit: int = 100) -> list[PendingApproval]:
    result = await session.execute(
        select(PendingApproval)
        .where(PendingApproval.tenant_id == tenant_id, PendingApproval.status == "pending")
        .order_by(PendingApproval.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars())


async def decide(
    session: AsyncSession,
    *,
    tenant_id: str,
    ticket_id: str,
    decision: str,
    decided_by: str,
) -> PendingApproval | None:
    if decision not in {"approved", "denied"}:
        raise ValueError("decision must be 'approved' or 'denied'")
    ticket = await session.get(PendingApproval, ticket_id)
    if not ticket or ticket.tenant_id != tenant_id:
        return None
    if ticket.status not in {"pending"}:
        return ticket
    ticket.status = decision
    ticket.decided_by = decided_by
    ticket.decided_at = datetime.utcnow()
    session.add(ticket)
    return ticket
