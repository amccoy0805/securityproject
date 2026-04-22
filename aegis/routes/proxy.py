"""The AI proxy.

Every AI call from a customer's app or endpoint agent enters here. The flow:

1. Authenticate via API key (``aeg_...``) → resolve tenant.
2. Resolve effective policy spec (compliance profiles + tenant policies).
3. Adapter extracts plain text + model from the request body.
4. Policy engine evaluates → ALLOW / REDACT / BLOCK.
5. If allowed, body (potentially redacted) is forwarded to the upstream.
6. Adapter extracts assistant text from the response.
7. Outbound redaction is applied if enabled.
8. Audit event is recorded.

The route is OpenAI-compatible at ``/v1/chat/completions`` and Anthropic-compatible
at ``/v1/messages`` so existing customer code can be pointed at the gateway by
changing only the base URL and API key.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..audit import record_event, tracker
from ..auth import AuthContext, require_api_key
from ..db import session_scope
from ..models import Agent, Policy, ProtectedDomain, ProviderCredential, RegisteredTool
from ..policy import (
    Decision,
    PolicyDecision,
    PolicyInput,
    PolicySpec,
    apply_outbound,
    evaluate_inbound,
)
from ..policy.engine import effective_spec
from ..policy.rules import (
    CONSUMER_DEFAULT_RULES,
    RuleContext,
    RuleVerdict,
    evaluate_all,
    fold,
    parse_rules,
)
from ..pricing import estimate_cost_usd
from ..providers import ProviderError, get_provider
from ..safety.agents import (
    AgentObservation,
    derive_agent_name,
    fold_observation,
    upsert_agent,
)
from ..safety.approvals import (
    ApprovalRequest,
    consume_ticket,
    create_ticket,
)
from ..safety.budgets import BudgetSpec
from ..safety.budgets import enforcer as budget_enforcer
from ..safety.loops import detector as loop_detector
from ..safety.network import client_ip
from ..safety.tools import (
    ToolPolicy,
    inspect_request_tools,
    inspect_response_calls,
)

router = APIRouter(tags=["proxy"])


async def _resolve_spec(ctx: AuthContext) -> PolicySpec:
    profile_names = [
        p.strip() for p in ctx.tenant.compliance_profiles.split(",") if p.strip()
    ] or ["baseline"]
    overrides: dict[str, Any] = {}
    async with session_scope() as session:
        rows = await session.execute(
            select(Policy)
            .where(Policy.tenant_id == ctx.tenant.id, Policy.enabled.is_(True))
            .order_by(Policy.priority.asc())
        )
        for policy in rows.scalars():
            if isinstance(policy.spec, dict):
                overrides.update(policy.spec)
    if not ctx.tenant.block_on_high_severity:
        overrides.setdefault("actions", {})
        actions = dict(overrides["actions"]) if overrides.get("actions") else {}
        actions.setdefault("high", "redact")
        overrides["actions"] = actions
    # If the tenant uses the 'consumer' profile and hasn't set custom rules,
    # ship the consumer default rule pack.
    if "consumer" in profile_names and not overrides.get("rules"):
        overrides["rules"] = CONSUMER_DEFAULT_RULES
    return effective_spec(profile_names, overrides)


async def _resolve_credential(tenant_id: str, provider: str) -> ProviderCredential | None:
    async with session_scope() as session:
        result = await session.execute(
            select(ProviderCredential).where(
                ProviderCredential.tenant_id == tenant_id,
                ProviderCredential.provider == provider,
            )
        )
        return result.scalar_one_or_none()


async def _resolve_registered_tools(tenant_id: str) -> dict[str, RegisteredTool]:
    async with session_scope() as session:
        rows = await session.execute(
            select(RegisteredTool).where(RegisteredTool.tenant_id == tenant_id)
        )
        return {t.name: t for t in rows.scalars()}


async def _resolve_protected_domains(tenant_id: str) -> list[str]:
    async with session_scope() as session:
        rows = await session.execute(
            select(ProtectedDomain).where(ProtectedDomain.tenant_id == tenant_id)
        )
        return [d.domain.lower() for d in rows.scalars()]


def _block_response(request_id: str, decision: PolicyDecision) -> JSONResponse:
    payload = {
        "error": {
            "type": "policy_blocked",
            "message": decision.reason,
            "request_id": request_id,
            "policy": decision.to_dict(),
        }
    }
    return JSONResponse(status_code=451, content=payload)


def _safety_block_response(
    request_id: str, *, kind: str, message: str, override_header: str, snapshot: dict[str, Any]
) -> JSONResponse:
    """Friendly 429 with explicit override instructions."""
    payload = {
        "error": {
            "type": kind,
            "message": message,
            "request_id": request_id,
            "override": (
                f"To proceed anyway, retry with header `{override_header}: 1`. The override "
                f"is recorded in the audit log alongside the original block."
            ),
            "snapshot": snapshot,
        }
    }
    return JSONResponse(status_code=429, content=payload)


def _consumer_verdict(decision: str, severity: str, findings: list[Any]) -> dict[str, Any]:
    """Plain-English explanation for B2C clients (browser ext / consumer app)."""
    icons = {"allow": "ok", "redact": "warning", "block": "blocked", "error": "error"}
    if decision == "block":
        msg = "We blocked this because it looked unsafe."
    elif decision == "redact":
        msg = "We removed sensitive details before sending this to the AI."
    elif decision == "error":
        msg = "Something went wrong reaching the AI provider."
    else:
        msg = "Looks safe to proceed."
    detector_names = sorted({f.get("detector") for f in findings if isinstance(f, dict) and f.get("detector")})
    return {
        "level": icons.get(decision, "info"),
        "headline": msg,
        "severity": severity,
        "details": detector_names[:8],
    }


def _untrusted_from_request(request: Request) -> bool:
    raw = request.headers.get("x-aegis-untrusted", "").strip().lower()
    return raw in {"1", "true", "yes", "y", "on"}


def _override_from_request(request: Request, name: str) -> bool:
    raw = request.headers.get(name, "").strip().lower()
    return raw in {"1", "true", "yes", "y", "on"}


async def _proxy(
    *,
    provider_name: str,
    upstream_path: str,
    request: Request,
    ctx: AuthContext,
) -> JSONResponse:
    request_id = str(uuid.uuid4())
    started = time.perf_counter()

    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("Request body must be a JSON object.")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {exc!s}") from exc

    cred = await _resolve_credential(ctx.tenant.id, provider_name)
    adapter = get_provider(
        provider_name,
        api_key=cred.api_key if cred else None,
        base_url=cred.base_url if cred and cred.base_url else None,
    )

    spec = await _resolve_spec(ctx)
    plain = adapter.extract_text(body)
    model = adapter.extract_model(body)
    untrusted = _untrusted_from_request(request)
    override_budget = _override_from_request(request, "x-aegis-override-budget")
    override_loop = _override_from_request(request, "x-aegis-override-loop")
    approve_action = _override_from_request(request, "x-aegis-approve-action")
    approval_ticket_id = (request.headers.get("x-aegis-approval-ticket") or "").strip()
    api_key_id = ctx.api_key.id if ctx.api_key else "no-key"
    src_ip = client_ip(request)

    # ---- Agent discovery + risk score (auto-inventory) ----
    agent_name = derive_agent_name(
        header_value=request.headers.get("x-aegis-agent"),
        api_key_name=ctx.api_key.name if ctx.api_key else None,
        model=model,
    )
    agent_id: str | None = None
    async with session_scope() as session:
        agent = await upsert_agent(
            session,
            tenant_id=ctx.tenant.id,
            name=agent_name,
            api_key_id=api_key_id if api_key_id != "no-key" else None,
            api_key_name=ctx.api_key.name if ctx.api_key else None,
            model=model,
            src_ip=src_ip,
        )
        agent_id = agent.id
        agent_kind = agent.kind
        agent_autonomy = agent.autonomy

    # ---- Loop / runaway detection (before policy + before upstream) ----
    loop = loop_detector.observe(
        tenant_id=ctx.tenant.id, api_key_id=api_key_id, model=model, text=plain
    )
    if loop.looping and not override_loop:
        async with session_scope() as session:
            await record_event(
                session,
                tenant_id=ctx.tenant.id,
                request_id=request_id,
                actor_kind=ctx.actor_kind,
                actor_id=ctx.actor_id,
                actor_label=ctx.actor_label,
                provider=provider_name,
                model=model,
                route=upstream_path,
                decision="block",
                severity="medium",
                findings=[],
                input_text=plain,
                output_text="",
                latency_ms=int((time.perf_counter() - started) * 1000),
                store_excerpts=spec.store_request_excerpts,
                extra={
                    "safety": "loop_detected",
                    "loop_digest": loop.digest,
                    "repeat_count": loop.repeat_count,
                    "reason": loop.reason,
                },
                agent_id=agent_id,
            )
        tracker.record(ctx.tenant.id, "block")
        return _safety_block_response(
            request_id,
            kind="runaway_loop_blocked",
            message=loop.reason or "Repeated identical request blocked.",
            override_header="X-Aegis-Override-Loop",
            snapshot={"repeat_count": loop.repeat_count, "digest": loop.digest},
        )

    # ---- Budget enforcement (pre-flight estimate) ----
    budget_spec = BudgetSpec.from_dict(spec.budgets)
    projected_input_chars = len(plain or "")
    projected_output_chars = max(2_000, projected_input_chars // 2)
    projected_cost = estimate_cost_usd(
        model, projected_input_chars, projected_output_chars, overrides=spec.model_prices
    )
    pre = budget_enforcer.precheck(
        budget_spec,
        tenant_id=ctx.tenant.id,
        api_key_id=api_key_id,
        projected_input_chars=projected_input_chars,
        projected_cost_usd=projected_cost,
    )
    if not pre.allowed and budget_spec.require_explicit_override and not override_budget:
        async with session_scope() as session:
            await record_event(
                session,
                tenant_id=ctx.tenant.id,
                request_id=request_id,
                actor_kind=ctx.actor_kind,
                actor_id=ctx.actor_id,
                actor_label=ctx.actor_label,
                provider=provider_name,
                model=model,
                route=upstream_path,
                decision="block",
                severity="medium",
                findings=[],
                input_text=plain,
                output_text="",
                latency_ms=int((time.perf_counter() - started) * 1000),
                store_excerpts=spec.store_request_excerpts,
                extra={
                    "safety": "budget_exceeded",
                    "reason": pre.reason,
                    "triggered_window": pre.triggered_window,
                    "snapshot": pre.snapshot,
                },
                agent_id=agent_id,
            )
        tracker.record(ctx.tenant.id, "block")
        return _safety_block_response(
            request_id,
            kind="budget_exceeded",
            message=f"Budget exceeded: {pre.reason}",
            override_header="X-Aegis-Override-Budget",
            snapshot=pre.snapshot,
        )

    decision = evaluate_inbound(
        spec,
        PolicyInput(
            text=plain,
            model=model,
            provider=provider_name,
            user_label=ctx.actor_label,
            untrusted=untrusted,
        ),
    )

    # ---- Human-readable rules engine ----
    rules = parse_rules(spec.rules)
    rule_ctx = RuleContext(
        text=plain,
        model=model,
        action_classes=[],  # tool calls not yet known on the inbound side
        detected_categories=decision.matched_categories,
        untrusted_present=decision.untrusted_present,
    )
    rule_results = evaluate_all(rules, rule_ctx)
    folded_rule = fold(rule_results)
    if folded_rule and folded_rule.verdict == RuleVerdict.BLOCK:
        async with session_scope() as session:
            await record_event(
                session,
                tenant_id=ctx.tenant.id,
                request_id=request_id,
                actor_kind=ctx.actor_kind,
                actor_id=ctx.actor_id,
                actor_label=ctx.actor_label,
                provider=provider_name,
                model=model,
                route=upstream_path,
                decision="block",
                severity="high",
                findings=[r.to_dict() for r in rule_results],
                input_text=plain,
                output_text="",
                latency_ms=int((time.perf_counter() - started) * 1000),
                store_excerpts=spec.store_request_excerpts,
                extra={"safety": "rule_block", "rules": [r.to_dict() for r in rule_results]},
                agent_id=agent_id,
            )
        tracker.record(ctx.tenant.id, "block")
        return JSONResponse(
            status_code=451,
            content={
                "error": {
                    "type": "rule_block",
                    "message": folded_rule.reason,
                    "request_id": request_id,
                    "rules": [r.to_dict() for r in rule_results],
                }
            },
        )

    if decision.decision == Decision.BLOCK:
        async with session_scope() as session:
            await record_event(
                session,
                tenant_id=ctx.tenant.id,
                request_id=request_id,
                actor_kind=ctx.actor_kind,
                actor_id=ctx.actor_id,
                actor_label=ctx.actor_label,
                provider=provider_name,
                model=model,
                route=upstream_path,
                decision="block",
                severity=(decision.severity.value if decision.severity else "info"),
                findings=[f.to_dict() for f in decision.findings],
                input_text=plain,
                output_text="",
                latency_ms=int((time.perf_counter() - started) * 1000),
                store_excerpts=spec.store_request_excerpts,
                extra={"reason": decision.reason, "matched_categories": decision.matched_categories},
            )
        tracker.record(ctx.tenant.id, "block")
        return _block_response(request_id, decision)

    forwarded_body = body
    # Always rewrite when sanitizer changed text (e.g. invisible-char strip,
    # untrusted-tag removal) even on ALLOW so we don't relay smuggled bytes.
    if decision.decision == Decision.REDACT or decision.sanitized_text != plain:
        forwarded_body = adapter.rewrite_text(body, decision.sanitized_text)

    # ---- Tool governance: validate the *advertised* tools list (inbound) ----
    tool_policy = ToolPolicy.from_dict(spec.tool_governance)
    protected_domains = await _resolve_protected_domains(ctx.tenant.id)
    if protected_domains:
        tool_policy.protected_domains = sorted(set(tool_policy.protected_domains) | set(protected_domains))
    registered = await _resolve_registered_tools(ctx.tenant.id)
    inbound_tool_report = inspect_request_tools(
        request_tools=forwarded_body.get("tools") if isinstance(forwarded_body, dict) else None,
        registered=registered,
        policy=tool_policy,
    )
    if inbound_tool_report.blocked:
        async with session_scope() as session:
            await record_event(
                session,
                tenant_id=ctx.tenant.id,
                request_id=request_id,
                actor_kind=ctx.actor_kind,
                actor_id=ctx.actor_id,
                actor_label=ctx.actor_label,
                provider=provider_name,
                model=model,
                route=upstream_path,
                decision="block",
                severity="high",
                findings=[t.to_dict() for t in inbound_tool_report.findings],
                input_text=plain,
                output_text="",
                latency_ms=int((time.perf_counter() - started) * 1000),
                store_excerpts=spec.store_request_excerpts,
                extra={
                    "safety": "tool_registry_block",
                    "reason": inbound_tool_report.reason,
                },
                agent_id=agent_id,
            )
        tracker.record(ctx.tenant.id, "block")
        return JSONResponse(
            status_code=451,
            content={
                "error": {
                    "type": "tool_registry_block",
                    "message": inbound_tool_report.reason,
                    "request_id": request_id,
                    "findings": [t.to_dict() for t in inbound_tool_report.findings],
                }
            },
        )
    # If some tools were stripped but at least one survived, send the sanitized list.
    if isinstance(forwarded_body, dict) and inbound_tool_report.sanitized_tools and \
            len(inbound_tool_report.sanitized_tools) != len(forwarded_body.get("tools") or []):
        forwarded_body = dict(forwarded_body)
        forwarded_body["tools"] = inbound_tool_report.sanitized_tools

    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() in {"openai-organization", "openai-project", "anthropic-version", "anthropic-beta"}
    }

    try:
        upstream = await adapter.forward(upstream_path, forwarded_body, forward_headers)
    except ProviderError as exc:
        async with session_scope() as session:
            await record_event(
                session,
                tenant_id=ctx.tenant.id,
                request_id=request_id,
                actor_kind=ctx.actor_kind,
                actor_id=ctx.actor_id,
                actor_label=ctx.actor_label,
                provider=provider_name,
                model=model,
                route=upstream_path,
                decision="error",
                severity="medium",
                findings=[f.to_dict() for f in decision.findings],
                input_text=plain,
                output_text="",
                latency_ms=int((time.perf_counter() - started) * 1000),
                store_excerpts=spec.store_request_excerpts,
                extra={"upstream_error": str(exc)},
                agent_id=agent_id,
            )
        tracker.record(ctx.tenant.id, "error")
        return JSONResponse(status_code=exc.status_code, content=exc.payload)

    output_text = adapter.extract_output_text(upstream.body)
    response_body = upstream.body

    # ---- Tool governance: inspect model-emitted tool calls (outbound) ----
    outbound_tool_report = None
    issued_tickets: list[dict[str, Any]] = []
    consumed_ticket_ok: bool | None = None
    consumed_ticket_reason: str | None = None

    # If the caller supplied an approval ticket, look it up and treat as approval.
    effective_approval = approve_action
    if approval_ticket_id and not effective_approval:
        async with session_scope() as session:
            ok, reason = await consume_ticket(
                session,
                tenant_id=ctx.tenant.id,
                ticket_id=approval_ticket_id,
                expected_tool=None,
            )
        consumed_ticket_ok = ok
        consumed_ticket_reason = reason
        effective_approval = ok

    if upstream.status_code < 400 and isinstance(response_body, dict):
        response_body, outbound_tool_report = inspect_response_calls(
            response_body,
            registered=registered,
            policy=tool_policy,
            approved=effective_approval,
        )

        # For each call we just blocked because of "needs approval" / threshold,
        # issue an async ticket so a human can approve out-of-band.
        if outbound_tool_report and outbound_tool_report.blocked_calls and not effective_approval:
            async with session_scope() as session:
                for finding in outbound_tool_report.blocked_calls:
                    if "approval" not in (finding.reason or "").lower() and "threshold" not in (finding.reason or "").lower():
                        continue
                    ticket = await create_ticket(
                        session,
                        ApprovalRequest(
                            request_id=request_id,
                            tenant_id=ctx.tenant.id,
                            api_key_id=api_key_id if api_key_id != "no-key" else None,
                            actor_label=ctx.actor_label,
                            agent_id=agent_id,
                            tool_name=finding.name,
                            action_class=finding.action_class or "unknown",
                            summary=finding.reason or "sensitive tool call",
                            arguments_excerpt=finding.arguments_excerpt,
                            risk_factors={"agent_kind": agent_kind, "agent_autonomy": agent_autonomy},
                        ),
                    )
                    issued_tickets.append({
                        "ticket_id": ticket.id,
                        "tool": finding.name,
                        "action_class": finding.action_class,
                        "expires_at": ticket.expires_at.isoformat(),
                    })

    outbound_findings: list = []
    if upstream.status_code < 400 and output_text:
        sanitized_out, outbound_findings = apply_outbound(spec, output_text)
        if outbound_findings:
            response_body = adapter.rewrite_output_text(response_body, sanitized_out)

    final_decision = decision.decision.value
    if outbound_findings and final_decision == "allow":
        final_decision = "redact"

    response_body.setdefault("aegis", {})
    actual_input_chars = len(plain or "")
    actual_output_chars = len(output_text or "")
    actual_cost = estimate_cost_usd(
        model, actual_input_chars, actual_output_chars, overrides=spec.model_prices
    )
    response_body["aegis"] = {
        "request_id": request_id,
        "decision": final_decision,
        "inbound_findings": [f.to_dict() for f in decision.findings],
        "outbound_findings": [f.to_dict() for f in outbound_findings],
        "untrusted_present": decision.untrusted_present,
        "policy_profiles": spec.profiles,
        "rules": [r.to_dict() for r in rule_results],
        "usage": {
            "input_chars": actual_input_chars,
            "output_chars": actual_output_chars,
            "estimated_cost_usd": round(actual_cost, 6),
        },
        "overrides": {
            "budget": override_budget,
            "loop": override_loop,
            "action": effective_approval,
            "ip": _override_from_request(request, "x-aegis-override-ip"),
            "approval_ticket": (
                {"id": approval_ticket_id, "ok": consumed_ticket_ok, "reason": consumed_ticket_reason}
                if approval_ticket_id
                else None
            ),
        },
        "tool_governance": {
            "inbound": [t.to_dict() for t in inbound_tool_report.findings],
            "outbound": [t.to_dict() for t in (outbound_tool_report.findings if outbound_tool_report else [])],
            "blocked_calls": [t.to_dict() for t in (outbound_tool_report.blocked_calls if outbound_tool_report else [])],
            "sanitized": bool(outbound_tool_report and outbound_tool_report.sanitized),
            "issued_tickets": issued_tickets,
        },
        "agent": {
            "id": agent_id,
            "name": agent_name,
            "kind": agent_kind,
            "autonomy": agent_autonomy,
        },
        "client_ip": src_ip,
        "verdict": _consumer_verdict(
            final_decision,
            (decision.severity.value if decision.severity else "info"),
            [f.to_dict() for f in decision.findings] + [f.to_dict() for f in outbound_findings],
        ),
    }

    async with session_scope() as session:
        await record_event(
            session,
            tenant_id=ctx.tenant.id,
            request_id=request_id,
            actor_kind=ctx.actor_kind,
            actor_id=ctx.actor_id,
            actor_label=ctx.actor_label,
            provider=provider_name,
            model=model,
            route=upstream_path,
            decision=final_decision,
            severity=(decision.severity.value if decision.severity else "info"),
            findings=[f.to_dict() for f in decision.findings]
            + [f.to_dict() for f in outbound_findings]
            + [t.to_dict() for t in inbound_tool_report.findings]
            + [t.to_dict() for t in (outbound_tool_report.findings if outbound_tool_report else [])],
            input_text=plain,
            output_text=output_text,
            latency_ms=int((time.perf_counter() - started) * 1000),
            store_excerpts=spec.store_request_excerpts,
            extra={
                "upstream_status": upstream.status_code,
                "matched_categories": decision.matched_categories,
                "untrusted_present": decision.untrusted_present,
                "estimated_cost_usd": round(actual_cost, 6),
                "rules": [r.to_dict() for r in rule_results],
                "issued_tickets": issued_tickets,
                "overrides": {
                    "budget": override_budget,
                    "loop": override_loop,
                    "action": effective_approval,
                    "approval_ticket": approval_ticket_id or None,
                },
                "tool_governance": {
                    "blocked_calls": [t.to_dict() for t in (outbound_tool_report.blocked_calls if outbound_tool_report else [])],
                    "sanitized": bool(outbound_tool_report and outbound_tool_report.sanitized),
                },
                "client_ip": src_ip,
            },
            agent_id=agent_id,
        )

        # Fold this observation into the agent's running risk score.
        ag = await session.get(Agent, agent_id) if agent_id else None
        if ag is not None:
            fold_observation(
                ag,
                AgentObservation(
                    decision=final_decision,
                    severity=(decision.severity.value if decision.severity else "info"),
                    matched_categories=decision.matched_categories,
                    untrusted_present=decision.untrusted_present,
                    tool_action_classes=[
                        t.action_class for t in (outbound_tool_report.findings if outbound_tool_report else [])
                        if t.action_class
                    ],
                ),
            )
            session.add(ag)
    tracker.record(ctx.tenant.id, final_decision)
    budget_enforcer.commit(
        tenant_id=ctx.tenant.id,
        api_key_id=api_key_id,
        input_chars=actual_input_chars,
        output_chars=actual_output_chars,
        cost_usd=actual_cost,
    )

    return JSONResponse(status_code=upstream.status_code, content=response_body)


# ---- OpenAI-compatible -------------------------------------------------------

@router.post("/v1/chat/completions")
async def openai_chat(request: Request, ctx: AuthContext = Depends(require_api_key)) -> JSONResponse:
    return await _proxy(
        provider_name="openai",
        upstream_path="chat/completions",
        request=request,
        ctx=ctx,
    )


@router.post("/v1/embeddings")
async def openai_embeddings(request: Request, ctx: AuthContext = Depends(require_api_key)) -> JSONResponse:
    return await _proxy(
        provider_name="openai",
        upstream_path="embeddings",
        request=request,
        ctx=ctx,
    )


@router.post("/v1/responses")
async def openai_responses(request: Request, ctx: AuthContext = Depends(require_api_key)) -> JSONResponse:
    return await _proxy(
        provider_name="openai",
        upstream_path="responses",
        request=request,
        ctx=ctx,
    )


# ---- Anthropic-compatible ----------------------------------------------------

@router.post("/v1/messages")
async def anthropic_messages(request: Request, ctx: AuthContext = Depends(require_api_key)) -> JSONResponse:
    return await _proxy(
        provider_name="anthropic",
        upstream_path="v1/messages",
        request=request,
        ctx=ctx,
    )


# ---- Generic introspection ---------------------------------------------------

@router.get("/v1/policy/me")
async def my_policy(ctx: AuthContext = Depends(require_api_key)) -> dict[str, Any]:
    spec = await _resolve_spec(ctx)
    api_key_id = ctx.api_key.id if ctx.api_key else None
    return {
        "tenant": ctx.tenant.name,
        "actor": ctx.actor_label,
        "policy": spec.to_dict(),
        "anomaly_window": tracker.stats(ctx.tenant.id),
        "usage_last_hour": budget_enforcer.stats(ctx.tenant.id, api_key_id, window_seconds=3600),
        "usage_last_day": budget_enforcer.stats(ctx.tenant.id, api_key_id, window_seconds=86_400),
    }


@router.post("/v1/policy/check")
async def check(
    payload: dict[str, Any],
    request: Request,
    ctx: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Dry-run a piece of text against the tenant's policy. No upstream call."""
    text = str(payload.get("text") or "")
    model = payload.get("model")
    untrusted = bool(payload.get("untrusted")) or _untrusted_from_request(request)
    spec = await _resolve_spec(ctx)
    decision = evaluate_inbound(
        spec,
        PolicyInput(
            text=text,
            model=str(model) if model else None,
            user_label=ctx.actor_label,
            untrusted=untrusted,
        ),
    )
    sanitized_out, outbound = apply_outbound(spec, text) if payload.get("scan_response") else (text, [])
    return {
        "request_id": str(uuid.uuid4()),
        "policy": spec.to_dict(),
        "inbound": decision.to_dict(),
        "sanitized_text": decision.sanitized_text,
        "outbound": [f.to_dict() for f in outbound],
        "sanitized_response": sanitized_out,
    }
