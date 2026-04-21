"""Admin REST API: tenants, users, API keys, policies, provider credentials, audit."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import desc, func, select

from ..auth import AuthContext, require_admin_user
from ..db import session_scope
from ..models import ApiKey, AuditEvent, Policy, ProviderCredential, Tenant, User
from ..policy.profiles import COMPLIANCE_PROFILES
from ..security import generate_api_key, hash_password

router = APIRouter(prefix="/admin/api", tags=["admin"])


# ----- pydantic schemas -----

class TenantOut(BaseModel):
    id: str
    name: str
    plan: str
    compliance_profiles: list[str]
    block_on_high_severity: bool


class TenantPatch(BaseModel):
    plan: str | None = None
    compliance_profiles: list[str] | None = None
    block_on_high_severity: bool | None = None


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    user_label: str | None = None
    scopes: list[str] = Field(default_factory=lambda: ["proxy"])


class ApiKeyOut(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: list[str]
    user_label: str | None
    revoked: bool
    last_used_at: datetime | None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    plaintext: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=10)
    role: str = Field(default="member")


class UserOut(BaseModel):
    id: str
    email: EmailStr
    role: str
    is_active: bool


class PolicyIn(BaseModel):
    name: str
    enabled: bool = True
    priority: int = 100
    spec: dict[str, Any] = Field(default_factory=dict)


class PolicyOut(PolicyIn):
    id: str


class CredentialIn(BaseModel):
    provider: str
    api_key: str
    base_url: str | None = None


class CredentialOut(BaseModel):
    id: str
    provider: str
    base_url: str | None
    masked_api_key: str


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


# ----- tenant -----

@router.get("/tenant", response_model=TenantOut)
async def get_tenant(ctx: AuthContext = Depends(require_admin_user)) -> TenantOut:
    return TenantOut(
        id=ctx.tenant.id,
        name=ctx.tenant.name,
        plan=ctx.tenant.plan,
        compliance_profiles=[p for p in ctx.tenant.compliance_profiles.split(",") if p],
        block_on_high_severity=ctx.tenant.block_on_high_severity,
    )


@router.patch("/tenant", response_model=TenantOut)
async def patch_tenant(
    body: TenantPatch, ctx: AuthContext = Depends(require_admin_user)
) -> TenantOut:
    async with session_scope() as session:
        tenant = await session.get(Tenant, ctx.tenant.id)
        if not tenant:
            raise HTTPException(404, "Tenant not found.")
        if body.plan is not None:
            tenant.plan = body.plan
        if body.compliance_profiles is not None:
            unknown = [p for p in body.compliance_profiles if p not in COMPLIANCE_PROFILES]
            if unknown:
                raise HTTPException(400, f"Unknown profile(s): {unknown}")
            tenant.compliance_profiles = ",".join(body.compliance_profiles) or "baseline"
        if body.block_on_high_severity is not None:
            tenant.block_on_high_severity = body.block_on_high_severity
        session.add(tenant)
        return TenantOut(
            id=tenant.id,
            name=tenant.name,
            plan=tenant.plan,
            compliance_profiles=[p for p in tenant.compliance_profiles.split(",") if p],
            block_on_high_severity=tenant.block_on_high_severity,
        )


@router.get("/profiles")
async def list_profiles(_: AuthContext = Depends(require_admin_user)) -> dict[str, Any]:
    return {name: {"description": p["description"]} for name, p in COMPLIANCE_PROFILES.items()}


# ----- API keys -----

@router.get("/keys", response_model=list[ApiKeyOut])
async def list_keys(ctx: AuthContext = Depends(require_admin_user)) -> list[ApiKeyOut]:
    async with session_scope() as session:
        rows = await session.execute(
            select(ApiKey).where(ApiKey.tenant_id == ctx.tenant.id).order_by(desc(ApiKey.created_at))
        )
        return [
            ApiKeyOut(
                id=k.id,
                name=k.name,
                prefix=k.prefix,
                scopes=[s for s in k.scopes.split(",") if s],
                user_label=k.user_label,
                revoked=k.revoked,
                last_used_at=k.last_used_at,
                created_at=k.created_at,
            )
            for k in rows.scalars()
        ]


@router.post("/keys", response_model=ApiKeyCreated, status_code=201)
async def create_key(
    body: ApiKeyCreate, ctx: AuthContext = Depends(require_admin_user)
) -> ApiKeyCreated:
    generated = generate_api_key()
    async with session_scope() as session:
        key = ApiKey(
            tenant_id=ctx.tenant.id,
            name=body.name,
            prefix=generated.prefix,
            secret_hash=generated.secret_hash,
            scopes=",".join(body.scopes) or "proxy",
            user_label=body.user_label,
        )
        session.add(key)
        await session.flush()
        return ApiKeyCreated(
            id=key.id,
            name=key.name,
            prefix=key.prefix,
            scopes=body.scopes,
            user_label=key.user_label,
            revoked=False,
            last_used_at=None,
            created_at=key.created_at,
            plaintext=generated.full,
        )


@router.delete("/keys/{key_id}")
async def revoke_key(key_id: str, ctx: AuthContext = Depends(require_admin_user)) -> dict[str, str]:
    async with session_scope() as session:
        key = await session.get(ApiKey, key_id)
        if not key or key.tenant_id != ctx.tenant.id:
            raise HTTPException(404, "Key not found.")
        key.revoked = True
        session.add(key)
        return {"status": "revoked", "id": key_id}


# ----- users -----

@router.get("/users", response_model=list[UserOut])
async def list_users(ctx: AuthContext = Depends(require_admin_user)) -> list[UserOut]:
    async with session_scope() as session:
        rows = await session.execute(
            select(User).where(User.tenant_id == ctx.tenant.id).order_by(User.email)
        )
        return [
            UserOut(id=u.id, email=u.email, role=u.role, is_active=u.is_active) for u in rows.scalars()
        ]


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(body: UserCreate, ctx: AuthContext = Depends(require_admin_user)) -> UserOut:
    if body.role not in {"admin", "security", "member"}:
        raise HTTPException(400, "Role must be admin|security|member.")
    async with session_scope() as session:
        existing = await session.execute(
            select(User).where(User.tenant_id == ctx.tenant.id, User.email == body.email)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(409, "User with that email already exists.")
        u = User(
            tenant_id=ctx.tenant.id,
            email=body.email,
            password_hash=hash_password(body.password),
            role=body.role,
        )
        session.add(u)
        await session.flush()
        return UserOut(id=u.id, email=u.email, role=u.role, is_active=u.is_active)


# ----- policies -----

@router.get("/policies", response_model=list[PolicyOut])
async def list_policies(ctx: AuthContext = Depends(require_admin_user)) -> list[PolicyOut]:
    async with session_scope() as session:
        rows = await session.execute(
            select(Policy).where(Policy.tenant_id == ctx.tenant.id).order_by(Policy.priority)
        )
        return [
            PolicyOut(id=p.id, name=p.name, enabled=p.enabled, priority=p.priority, spec=dict(p.spec or {}))
            for p in rows.scalars()
        ]


@router.post("/policies", response_model=PolicyOut, status_code=201)
async def create_policy(body: PolicyIn, ctx: AuthContext = Depends(require_admin_user)) -> PolicyOut:
    async with session_scope() as session:
        p = Policy(
            tenant_id=ctx.tenant.id,
            name=body.name,
            enabled=body.enabled,
            priority=body.priority,
            spec=body.spec,
        )
        session.add(p)
        await session.flush()
        return PolicyOut(id=p.id, name=p.name, enabled=p.enabled, priority=p.priority, spec=dict(p.spec or {}))


@router.put("/policies/{policy_id}", response_model=PolicyOut)
async def update_policy(
    policy_id: str, body: PolicyIn, ctx: AuthContext = Depends(require_admin_user)
) -> PolicyOut:
    async with session_scope() as session:
        p = await session.get(Policy, policy_id)
        if not p or p.tenant_id != ctx.tenant.id:
            raise HTTPException(404, "Policy not found.")
        p.name = body.name
        p.enabled = body.enabled
        p.priority = body.priority
        p.spec = body.spec
        session.add(p)
        return PolicyOut(id=p.id, name=p.name, enabled=p.enabled, priority=p.priority, spec=dict(p.spec or {}))


@router.delete("/policies/{policy_id}")
async def delete_policy(policy_id: str, ctx: AuthContext = Depends(require_admin_user)) -> dict[str, str]:
    async with session_scope() as session:
        p = await session.get(Policy, policy_id)
        if not p or p.tenant_id != ctx.tenant.id:
            raise HTTPException(404, "Policy not found.")
        await session.delete(p)
        return {"status": "deleted", "id": policy_id}


# ----- provider credentials -----

@router.get("/credentials", response_model=list[CredentialOut])
async def list_credentials(ctx: AuthContext = Depends(require_admin_user)) -> list[CredentialOut]:
    async with session_scope() as session:
        rows = await session.execute(
            select(ProviderCredential).where(ProviderCredential.tenant_id == ctx.tenant.id)
        )
        return [
            CredentialOut(
                id=c.id, provider=c.provider, base_url=c.base_url, masked_api_key=_mask(c.api_key)
            )
            for c in rows.scalars()
        ]


@router.post("/credentials", response_model=CredentialOut, status_code=201)
async def upsert_credential(
    body: CredentialIn, ctx: AuthContext = Depends(require_admin_user)
) -> CredentialOut:
    if body.provider not in {"openai", "anthropic"}:
        raise HTTPException(400, "Provider must be openai|anthropic.")
    async with session_scope() as session:
        existing = await session.execute(
            select(ProviderCredential).where(
                ProviderCredential.tenant_id == ctx.tenant.id,
                ProviderCredential.provider == body.provider,
            )
        )
        cred = existing.scalar_one_or_none()
        if cred:
            cred.api_key = body.api_key
            cred.base_url = body.base_url
        else:
            cred = ProviderCredential(
                tenant_id=ctx.tenant.id,
                provider=body.provider,
                api_key=body.api_key,
                base_url=body.base_url,
            )
        session.add(cred)
        await session.flush()
        return CredentialOut(
            id=cred.id, provider=cred.provider, base_url=cred.base_url, masked_api_key=_mask(cred.api_key)
        )


@router.delete("/credentials/{cred_id}")
async def delete_credential(cred_id: str, ctx: AuthContext = Depends(require_admin_user)) -> dict[str, str]:
    async with session_scope() as session:
        cred = await session.get(ProviderCredential, cred_id)
        if not cred or cred.tenant_id != ctx.tenant.id:
            raise HTTPException(404, "Credential not found.")
        await session.delete(cred)
        return {"status": "deleted", "id": cred_id}


# ----- audit -----

@router.get("/audit")
async def list_audit(
    ctx: AuthContext = Depends(require_admin_user),
    limit: int = 100,
    offset: int = 0,
    decision: str | None = None,
) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    async with session_scope() as session:
        stmt = select(AuditEvent).where(AuditEvent.tenant_id == ctx.tenant.id)
        if decision:
            stmt = stmt.where(AuditEvent.decision == decision)
        stmt = stmt.order_by(desc(AuditEvent.created_at)).offset(offset).limit(limit)
        rows = (await session.execute(stmt)).scalars().all()
        items = [
            {
                "id": e.id,
                "request_id": e.request_id,
                "actor_kind": e.actor_kind,
                "actor_label": e.actor_label,
                "provider": e.provider,
                "model": e.model,
                "route": e.route,
                "decision": e.decision,
                "severity": e.severity,
                "findings": e.findings,
                "input_chars": e.input_chars,
                "output_chars": e.output_chars,
                "latency_ms": e.latency_ms,
                "created_at": e.created_at.isoformat(),
            }
            for e in rows
        ]
        return {"items": items, "limit": limit, "offset": offset}


@router.get("/dashboard/summary")
async def dashboard_summary(ctx: AuthContext = Depends(require_admin_user)) -> dict[str, Any]:
    since = datetime.utcnow() - timedelta(hours=24)
    async with session_scope() as session:
        total_q = await session.execute(
            select(func.count(AuditEvent.id))
            .where(AuditEvent.tenant_id == ctx.tenant.id, AuditEvent.created_at >= since)
        )
        decisions = await session.execute(
            select(AuditEvent.decision, func.count(AuditEvent.id))
            .where(AuditEvent.tenant_id == ctx.tenant.id, AuditEvent.created_at >= since)
            .group_by(AuditEvent.decision)
        )
        providers = await session.execute(
            select(AuditEvent.provider, func.count(AuditEvent.id))
            .where(AuditEvent.tenant_id == ctx.tenant.id, AuditEvent.created_at >= since)
            .group_by(AuditEvent.provider)
        )
        return {
            "window_hours": 24,
            "total": total_q.scalar_one(),
            "by_decision": {d or "unknown": c for d, c in decisions.all()},
            "by_provider": {p or "unknown": c for p, c in providers.all()},
        }
