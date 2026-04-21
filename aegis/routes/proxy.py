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
from ..models import Policy, ProviderCredential
from ..policy import (
    Decision,
    PolicyDecision,
    PolicyInput,
    PolicySpec,
    apply_outbound,
    evaluate_inbound,
)
from ..policy.engine import effective_spec
from ..providers import ProviderError, get_provider

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

    decision = evaluate_inbound(
        spec,
        PolicyInput(text=plain, model=model, provider=provider_name, user_label=ctx.actor_label),
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
    if decision.decision == Decision.REDACT:
        forwarded_body = adapter.rewrite_text(body, decision.sanitized_text)

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
            )
        tracker.record(ctx.tenant.id, "error")
        return JSONResponse(status_code=exc.status_code, content=exc.payload)

    output_text = adapter.extract_output_text(upstream.body)
    response_body = upstream.body
    outbound_findings: list = []
    if upstream.status_code < 400 and output_text:
        sanitized_out, outbound_findings = apply_outbound(spec, output_text)
        if outbound_findings:
            response_body = adapter.rewrite_output_text(upstream.body, sanitized_out)

    final_decision = decision.decision.value
    if outbound_findings and final_decision == "allow":
        final_decision = "redact"

    response_body.setdefault("aegis", {})
    response_body["aegis"] = {
        "request_id": request_id,
        "decision": final_decision,
        "inbound_findings": [f.to_dict() for f in decision.findings],
        "outbound_findings": [f.to_dict() for f in outbound_findings],
        "policy_profiles": spec.profiles,
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
            + [f.to_dict() for f in outbound_findings],
            input_text=plain,
            output_text=output_text,
            latency_ms=int((time.perf_counter() - started) * 1000),
            store_excerpts=spec.store_request_excerpts,
            extra={
                "upstream_status": upstream.status_code,
                "matched_categories": decision.matched_categories,
            },
        )
    tracker.record(ctx.tenant.id, final_decision)

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
    return {
        "tenant": ctx.tenant.name,
        "actor": ctx.actor_label,
        "policy": spec.to_dict(),
        "anomaly_window": tracker.stats(ctx.tenant.id),
    }


@router.post("/v1/policy/check")
async def check(payload: dict[str, Any], ctx: AuthContext = Depends(require_api_key)) -> dict[str, Any]:
    """Dry-run a piece of text against the tenant's policy. No upstream call."""
    text = str(payload.get("text") or "")
    model = payload.get("model")
    spec = await _resolve_spec(ctx)
    decision = evaluate_inbound(
        spec, PolicyInput(text=text, model=str(model) if model else None, user_label=ctx.actor_label)
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
