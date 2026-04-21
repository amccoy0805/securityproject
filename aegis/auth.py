"""Authentication dependencies for the API and admin UI.

- ``require_api_key`` authenticates programmatic clients via the
  ``Authorization: Bearer aeg_...`` header. It returns an ``AuthContext``
  identifying the tenant and the API key row used.
- ``require_admin_user`` validates a session cookie set by the admin UI login.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

import jwt
from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .db import session_scope
from .models import ApiKey, Tenant, User
from .security import split_api_key, verify_api_secret

SESSION_COOKIE = "aegis_session"
SESSION_ALG = "HS256"
SESSION_TTL_SECONDS = 60 * 60 * 12  # 12h


@dataclass
class AuthContext:
    tenant: Tenant
    api_key: ApiKey | None = None
    user: User | None = None
    actor_kind: str = "api_key"
    actor_label: str | None = None

    @property
    def actor_id(self) -> str | None:
        if self.api_key:
            return self.api_key.id
        if self.user:
            return self.user.id
        return None


async def _load_api_key(session: AsyncSession, prefix: str) -> ApiKey | None:
    result = await session.execute(
        select(ApiKey).where(ApiKey.prefix == prefix, ApiKey.revoked.is_(False))
    )
    return result.scalar_one_or_none()


async def require_api_key(authorization: str | None = Header(default=None)) -> AuthContext:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    presented = authorization.split(" ", 1)[1].strip()
    parts = split_api_key(presented)
    if not parts:
        raise HTTPException(status_code=401, detail="Invalid API key format.")
    prefix, secret = parts
    async with session_scope() as session:
        key = await _load_api_key(session, prefix)
        if not key or not verify_api_secret(secret, key.secret_hash):
            raise HTTPException(status_code=401, detail="Invalid API key.")
        tenant = await session.get(Tenant, key.tenant_id)
        if not tenant:
            raise HTTPException(status_code=401, detail="Tenant for API key no longer exists.")
        key.last_used_at = datetime.utcnow()
        session.add(key)
        return AuthContext(
            tenant=tenant,
            api_key=key,
            actor_kind="api_key",
            actor_label=key.user_label or key.name,
        )


def issue_session_token(user_id: str, tenant_id: str) -> str:
    payload: dict[str, Any] = {
        "sub": user_id,
        "tid": tenant_id,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int(datetime.utcnow().timestamp()) + SESSION_TTL_SECONDS,
    }
    return jwt.encode(payload, get_settings().secret_key, algorithm=SESSION_ALG)


def decode_session_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, get_settings().secret_key, algorithms=[SESSION_ALG])
    except jwt.PyJWTError:
        return None


async def optional_admin_user(
    session_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> AuthContext | None:
    if not session_cookie:
        return None
    payload = decode_session_token(session_cookie)
    if not payload:
        return None
    async with session_scope() as session:
        user = await session.get(User, payload.get("sub"))
        if not user or not user.is_active:
            return None
        tenant = await session.get(Tenant, user.tenant_id)
        if not tenant:
            return None
        return AuthContext(
            tenant=tenant,
            user=user,
            actor_kind="user",
            actor_label=user.email,
        )


async def require_admin_user(
    ctx: AuthContext | None = Depends(optional_admin_user),
) -> AuthContext:
    if ctx is None or ctx.user is None:
        raise HTTPException(status_code=401, detail="Sign in required.")
    if ctx.user.role not in {"admin", "security"}:
        raise HTTPException(status_code=403, detail="Admin or security role required.")
    return ctx
