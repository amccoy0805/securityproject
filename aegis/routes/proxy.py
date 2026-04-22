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
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select

from ..audit import record_event, tracker
from ..auth import AuthContext, require_api_key
from ..config import get_settings
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
from ..policy.llm_judge import (
    JudgeConfig,
    LLMJudge,
    OpenAIJudge,
    verdict_to_finding,
)
from ..policy.rules import (
    CONSUMER_DEFAULT_RULES,
    RuleContext,
    RuleVerdict,
    evaluate_all,
    fold,
    parse_rules,
)
from ..policy.streaming import (
    SSE_DONE,
    StreamingRedactor,
    extract_delta_text,
    parse_openai_sse_chunk,
    rewrite_delta_text,
    serialise_sse_event,
)
from ..pricing import cost_from_usage, estimate_cost_usd, normalise_usage
from ..providers import ProviderError, get_provider
from ..safety import get_runtime
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


_JUDGE_FACTORY: list[Any] = [None]  # process-global hook used by tests


def set_judge_factory(factory):
    """Register a custom ``(spec) -> LLMJudge`` factory (used by tests + customers)."""
    _JUDGE_FACTORY[0] = factory


def _build_judge(spec: PolicySpec) -> tuple[LLMJudge, JudgeConfig] | None:
    cfg = JudgeConfig.from_dict(spec.llm_judge)
    if not cfg.enabled:
        return None
    factory = _JUDGE_FACTORY[0]
    if factory is not None:
        judge = factory(spec)
        return (judge, cfg) if judge is not None else None
    settings = get_settings()
    return OpenAIJudge(api_key=settings.openai_api_key, base_url=settings.openai_base_url), cfg


async def _stream_response(
    *,
    request_id: str,
    started: float,
    adapter,
    upstream_path: str,
    forwarded_body: dict[str, Any],
    forward_headers: dict[str, str],
    ctx: AuthContext,
    spec: PolicySpec,
    decision: PolicyDecision,
    inbound_tool_report,
    agent_id: str | None,
    agent_name: str,
    agent_kind: str,
    agent_autonomy: str,
    api_key_id: str,
    provider_name: str,
    model: str | None,
    plain: str,
    actual_input_chars: int,
    override_budget: bool,
    override_loop: bool,
    effective_approval: bool,
    approval_ticket_id: str,
    consumed_ticket_ok: bool | None,
    consumed_ticket_reason: str | None,
    judge_verdict_dict: dict[str, Any] | None,
    rule_results,
    src_ip: str | None,
) -> StreamingResponse:
    """SSE forwarder with incremental output redaction.

    Each upstream chunk is split into one or more events, the assistant text
    deltas are fed into a ``StreamingRedactor`` that maintains a small
    sliding buffer (so secrets straddling chunk boundaries are still
    caught), and the rewritten events are emitted to the client in the same
    SSE shape. Tool-call deltas are passed through unchanged in this MVP;
    the registered-tool gate already ran on the request side.

    On stream end (or upstream error) we:
    - record the audit event with reconciled cost when usage was emitted,
    - commit the actual usage to the budget enforcer,
    - update the agent's risk observation (now also reflects redactions
      done during the stream).
    """
    redactor = StreamingRedactor(
        enabled=spec.redact_response,
        enabled_categories=spec.categories or None,
    )
    output_text_collected: list[str] = []
    upstream_usage: dict[str, Any] | None = None
    upstream_status_holder = {"status": 200}

    async def gen():
        nonlocal upstream_usage
        try:
            async for chunk in adapter.forward_stream(upstream_path, forwarded_body, forward_headers):
                events = parse_openai_sse_chunk(chunk)
                if not events:
                    # Pass through anything we couldn't parse (comments,
                    # heartbeats) untouched.
                    yield chunk
                    continue
                for ev in events:
                    if isinstance(ev, dict) and "usage" in ev and isinstance(ev["usage"], dict):
                        upstream_usage = ev["usage"]
                    delta = extract_delta_text(ev) if isinstance(ev, dict) else ""
                    if not delta:
                        # No text delta to scan; forward the event as-is.
                        yield serialise_sse_event(ev)
                        continue
                    safe_text, _findings = redactor.feed(delta)
                    if safe_text:
                        output_text_collected.append(safe_text)
                        yield serialise_sse_event(rewrite_delta_text(ev, safe_text))
                    # If the safe-tail kept everything in the buffer this
                    # round, we don't emit anything for this chunk; that's
                    # fine — we'll catch up on subsequent chunks or in
                    # flush().
            # Drain any tail still in the buffer.
            tail, _ = redactor.flush()
            if tail:
                output_text_collected.append(tail)
                yield serialise_sse_event(
                    {"choices": [{"index": 0, "delta": {"content": tail}, "finish_reason": None}]}
                )
            yield SSE_DONE
        except ProviderError as exc:
            upstream_status_holder["status"] = exc.status_code
            import json as _json
            yield (
                "event: error\ndata: "
                + _json.dumps(
                    {
                        "error": {
                            "type": "upstream_error",
                            "message": str(exc),
                            "request_id": request_id,
                        }
                    }
                )
                + "\n\n"
            ).encode("utf-8")
            yield SSE_DONE
        finally:
            await _finalise_stream(
                request_id=request_id,
                started=started,
                ctx=ctx,
                spec=spec,
                decision=decision,
                inbound_tool_report=inbound_tool_report,
                agent_id=agent_id,
                agent_name=agent_name,
                agent_kind=agent_kind,
                agent_autonomy=agent_autonomy,
                api_key_id=api_key_id,
                provider_name=provider_name,
                upstream_path=upstream_path,
                model=model,
                plain=plain,
                actual_input_chars=actual_input_chars,
                output_text="".join(output_text_collected),
                outbound_findings=redactor.all_findings,
                upstream_usage=upstream_usage,
                upstream_status=upstream_status_holder["status"],
                override_budget=override_budget,
                override_loop=override_loop,
                effective_approval=effective_approval,
                approval_ticket_id=approval_ticket_id,
                consumed_ticket_ok=consumed_ticket_ok,
                consumed_ticket_reason=consumed_ticket_reason,
                judge_verdict_dict=judge_verdict_dict,
                rule_results=rule_results,
                src_ip=src_ip,
            )

    headers = {
        "X-Aegis-Request-Id": request_id,
        "X-Aegis-Streaming": "true",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)


async def _finalise_stream(
    *,
    request_id: str,
    started: float,
    ctx: AuthContext,
    spec: PolicySpec,
    decision: PolicyDecision,
    inbound_tool_report,
    agent_id: str | None,
    agent_name: str,
    agent_kind: str,
    agent_autonomy: str,
    api_key_id: str,
    provider_name: str,
    upstream_path: str,
    model: str | None,
    plain: str,
    actual_input_chars: int,
    output_text: str,
    outbound_findings,
    upstream_usage: dict[str, Any] | None,
    upstream_status: int,
    override_budget: bool,
    override_loop: bool,
    effective_approval: bool,
    approval_ticket_id: str,
    consumed_ticket_ok: bool | None,
    consumed_ticket_reason: str | None,
    judge_verdict_dict: dict[str, Any] | None,
    rule_results,
    src_ip: str | None,
) -> None:
    """Audit + budget bookkeeping after a streaming response finishes."""
    actual_output_chars = len(output_text)
    reconciled = cost_from_usage(model, upstream_usage, overrides=spec.model_prices)
    estimated = estimate_cost_usd(model, actual_input_chars, actual_output_chars,
                                  overrides=spec.model_prices)
    actual_cost = reconciled if reconciled is not None else estimated
    cost_source = "reconciled" if reconciled is not None else "estimated"

    final_decision = decision.decision.value if upstream_status < 400 else "error"
    if outbound_findings and final_decision == "allow":
        final_decision = "redact"

    enforcer, _ = get_runtime()

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
            + [t.to_dict() for t in inbound_tool_report.findings],
            input_text=plain,
            output_text=output_text,
            latency_ms=int((time.perf_counter() - started) * 1000),
            store_excerpts=spec.store_request_excerpts,
            extra={
                "upstream_status": upstream_status,
                "matched_categories": decision.matched_categories,
                "untrusted_present": decision.untrusted_present,
                "estimated_cost_usd": round(actual_cost, 6),
                "cost_source": cost_source,
                "tokens": normalise_usage(upstream_usage),
                "rules": [r.to_dict() for r in rule_results],
                "issued_tickets": [],
                "overrides": {
                    "budget": override_budget,
                    "loop": override_loop,
                    "action": effective_approval,
                    "approval_ticket": approval_ticket_id or None,
                },
                "tool_governance": {
                    "blocked_calls": [],
                    "sanitized": False,
                },
                "client_ip": src_ip,
                "streaming": True,
                "judge": judge_verdict_dict,
            },
            agent_id=agent_id,
        )
        ag = await session.get(Agent, agent_id) if agent_id else None
        if ag is not None:
            fold_observation(
                ag,
                AgentObservation(
                    decision=final_decision,
                    severity=(decision.severity.value if decision.severity else "info"),
                    matched_categories=decision.matched_categories,
                    untrusted_present=decision.untrusted_present,
                    tool_action_classes=[],
                ),
            )
            session.add(ag)
    tracker.record(ctx.tenant.id, final_decision)
    enforcer.commit(
        tenant_id=ctx.tenant.id,
        api_key_id=api_key_id,
        input_chars=actual_input_chars,
        output_chars=actual_output_chars,
        cost_usd=actual_cost,
    )


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
    approval_ticket_id = (
        request.headers.get("x-aegis-approval-ticket")
        or request.headers.get("X-Aegis-Approval-Ticket")
        or ""
    ).strip()
    api_key_id = ctx.api_key.id if ctx.api_key else "no-key"
    src_ip = client_ip(request)
    # Resolve any approval ticket up front so both streaming and non-streaming
    # paths see the same `effective_approval` flag.
    effective_approval = approve_action
    consumed_ticket_ok: bool | None = None
    consumed_ticket_reason: str | None = None
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
    budget_enforcer, loop_detector = get_runtime()
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

    # ---- Optional LLM judge (off by default) ----
    judge_verdict_dict: dict[str, Any] | None = None
    judge_pair = _build_judge(spec)
    if judge_pair is not None:
        judge, jcfg = judge_pair
        should_run = (not jcfg.only_when_untrusted) or decision.untrusted_present or untrusted
        if should_run and plain:
            try:
                jv = await judge.judge(plain, cfg=jcfg)
            except Exception as exc:  # defensive: judge bugs must not block the request
                jv = None
                judge_verdict_dict = {"error": f"{exc}", "skipped": True}
            if jv is not None:
                judge_verdict_dict = jv.to_dict()
                f = verdict_to_finding(jv, cfg=jcfg, span_end=len(plain))
                if f is not None:
                    # Inject as an injection finding; promote decision to BLOCK because
                    # the judge already weighs severity against threshold.
                    decision.findings.append(f)
                    if "injection" not in decision.matched_categories:
                        decision.matched_categories = sorted(set(decision.matched_categories) | {"injection"})
                    decision.severity = decision.findings and max(
                        (ff.severity for ff in decision.findings), key=lambda s: s.rank
                    )
                    decision.decision = Decision.BLOCK
                    decision.reason = f"LLM judge flagged injection (score {jv.score:.2f}): {jv.reason}"

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

    # ---- Streaming branch (SSE) ----
    wants_stream = bool(forwarded_body.get("stream")) if isinstance(forwarded_body, dict) else False
    if wants_stream and getattr(adapter, "supports_streaming", False):
        return await _stream_response(
            request_id=request_id,
            started=started,
            adapter=adapter,
            upstream_path=upstream_path,
            forwarded_body=forwarded_body,
            forward_headers=forward_headers,
            ctx=ctx,
            spec=spec,
            decision=decision,
            inbound_tool_report=inbound_tool_report,
            agent_id=agent_id,
            agent_name=agent_name,
            agent_kind=agent_kind,
            agent_autonomy=agent_autonomy,
            api_key_id=api_key_id,
            provider_name=provider_name,
            model=model,
            plain=plain,
            actual_input_chars=len(plain or ""),
            override_budget=override_budget,
            override_loop=override_loop,
            effective_approval=effective_approval,
            approval_ticket_id=approval_ticket_id,
            consumed_ticket_ok=consumed_ticket_ok,
            consumed_ticket_reason=consumed_ticket_reason,
            judge_verdict_dict=judge_verdict_dict,
            rule_results=rule_results,
            src_ip=src_ip,
        )

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
    upstream_usage = response_body.get("usage") if isinstance(response_body, dict) else None
    reconciled_cost = cost_from_usage(model, upstream_usage, overrides=spec.model_prices)
    estimated_cost = estimate_cost_usd(
        model, actual_input_chars, actual_output_chars, overrides=spec.model_prices
    )
    actual_cost = reconciled_cost if reconciled_cost is not None else estimated_cost
    cost_source = "reconciled" if reconciled_cost is not None else "estimated"
    response_body["aegis"] = {
        "request_id": request_id,
        "decision": final_decision,
        "inbound_findings": [f.to_dict() for f in decision.findings],
        "outbound_findings": [f.to_dict() for f in outbound_findings],
        "untrusted_present": decision.untrusted_present,
        "policy_profiles": spec.profiles,
        "rules": [r.to_dict() for r in rule_results],
        "llm_judge": judge_verdict_dict,
        "usage": {
            "input_chars": actual_input_chars,
            "output_chars": actual_output_chars,
            "estimated_cost_usd": round(estimated_cost, 6),
            "reconciled_cost_usd": (round(reconciled_cost, 6) if reconciled_cost is not None else None),
            "cost_source": cost_source,
            "tokens": normalise_usage(upstream_usage),
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
                "cost_source": cost_source,
                "tokens": normalise_usage(upstream_usage),
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
    enforcer, _ = get_runtime()
    return {
        "tenant": ctx.tenant.name,
        "actor": ctx.actor_label,
        "policy": spec.to_dict(),
        "anomaly_window": tracker.stats(ctx.tenant.id),
        "usage_last_hour": enforcer.stats(ctx.tenant.id, api_key_id, window_seconds=3600),
        "usage_last_day": enforcer.stats(ctx.tenant.id, api_key_id, window_seconds=86_400),
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
