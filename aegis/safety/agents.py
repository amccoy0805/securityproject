"""Agent inventory & risk scoring.

Auto-discovers agents from gateway traffic, computes a transparent risk score,
and exposes helpers the proxy uses on every request.

Discovery rules (cheapest first):
1. Caller passes ``X-Aegis-Agent: <name>`` header → that's the agent.
2. Otherwise we synthesise the name as ``<api_key.name>:<model or unknown>``.
3. The first time we see a (tenant, name) combo we insert an ``Agent`` row
   marked ``discovered_from = "auto"``. Admins can rename and reclassify
   without losing the activity history.

Risk score is a deterministic 0–100 number with named factors so admins
understand the rating. We do NOT pretend it's predictive ML — it's a
conservative checklist that maps to the spec's risk dimensions:

- ``autonomy``       : how much human approval is in the loop
- ``data``           : recent block-rate on data-leak detectors
- ``injection``      : recent injection findings
- ``tool_breadth``   : count of action classes seen recently
- ``financial``      : has the agent attempted financial actions?
- ``destructive``    : has the agent attempted destructive actions?
- ``external_input`` : seen ``<aegis:untrusted>`` traffic?
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Agent

AUTONOMY_LEVELS = ("supervised", "semi", "autonomous")
_AUTONOMY_RISK = {"supervised": 5, "semi": 15, "autonomous": 30}


@dataclass
class AgentObservation:
    """One request's worth of signal feeding the agent's running state."""

    decision: str
    severity: str
    matched_categories: list[str]
    untrusted_present: bool
    tool_action_classes: list[str]


def derive_agent_name(*, header_value: str | None, api_key_name: str | None, model: str | None) -> str:
    if header_value and header_value.strip():
        return header_value.strip()[:200]
    return f"{(api_key_name or 'unknown-app')}:{(model or 'unknown')}"[:200]


def compute_risk(agent: Agent) -> tuple[int, dict[str, int]]:
    factors: dict[str, int] = {}
    factors["autonomy"] = _AUTONOMY_RISK.get(agent.autonomy, 5)

    rec = agent.risk_factors or {}

    block_rate_pct = int(rec.get("recent_block_rate_pct", 0))
    factors["data"] = min(25, block_rate_pct // 4)

    injection_hits = int(rec.get("recent_injection_hits", 0))
    factors["injection"] = min(15, injection_hits * 3)

    breadth = int(rec.get("tool_action_classes_seen", 0))
    factors["tool_breadth"] = min(10, breadth * 2)

    factors["financial"] = 15 if rec.get("seen_financial") else 0
    factors["destructive"] = 15 if rec.get("seen_destructive") else 0
    factors["external_input"] = 5 if rec.get("seen_untrusted") else 0

    score = sum(factors.values())
    return min(100, score), factors


async def upsert_agent(
    session: AsyncSession,
    *,
    tenant_id: str,
    name: str,
    api_key_id: str | None,
    api_key_name: str | None,
    model: str | None,
    src_ip: str | None,
) -> Agent:
    """Find or create the agent row; update last-seen telemetry."""
    result = await session.execute(
        select(Agent).where(Agent.tenant_id == tenant_id, Agent.name == name)
    )
    agent = result.scalar_one_or_none()
    if agent is None:
        agent = Agent(
            tenant_id=tenant_id,
            name=name,
            kind="assistant",
            autonomy="supervised",
            discovered_from="auto",
            discovered_via_key_id=api_key_id,
            metadata_json={"first_seen_via_key_name": api_key_name},
        )
        session.add(agent)
        await session.flush()

    agent.last_seen_at = datetime.utcnow()
    if model:
        agent.last_model = model
    if src_ip:
        agent.last_seen_ip = src_ip
    agent.request_count = (agent.request_count or 0) + 1
    return agent


def fold_observation(agent: Agent, obs: AgentObservation) -> None:
    """Update the rolling risk signal for this agent in-place."""
    if obs.decision == "block":
        agent.block_count = (agent.block_count or 0) + 1

    rec: dict[str, Any] = dict(agent.risk_factors or {})
    total = max(1, agent.request_count)
    rec["recent_block_rate_pct"] = int((agent.block_count / total) * 100)
    if "injection" in (obs.matched_categories or []):
        rec["recent_injection_hits"] = int(rec.get("recent_injection_hits", 0)) + 1
    if obs.untrusted_present:
        rec["seen_untrusted"] = True
    seen_classes = set(rec.get("tool_action_classes_seen_set") or [])
    for cls in obs.tool_action_classes:
        seen_classes.add(cls)
        if cls == "financial":
            rec["seen_financial"] = True
        if cls == "destructive":
            rec["seen_destructive"] = True
    rec["tool_action_classes_seen_set"] = sorted(seen_classes)
    rec["tool_action_classes_seen"] = len(seen_classes)
    agent.risk_factors = rec

    score, factors = compute_risk(agent)
    rec["score_factors"] = factors
    agent.risk_factors = rec
    agent.risk_score = score
