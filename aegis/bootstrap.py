"""First-run bootstrap: create default tenant + admin user if DB is empty."""

from __future__ import annotations

import logging

from sqlalchemy import select

from .config import get_settings
from .db import session_scope
from .models import Tenant, User
from .security import hash_password

log = logging.getLogger("aegis.bootstrap")


async def ensure_initial_tenant() -> None:
    settings = get_settings()
    async with session_scope() as session:
        existing_users = (await session.execute(select(User))).scalars().first()
        if existing_users:
            return
        tenant = (
            await session.execute(select(Tenant).where(Tenant.name == settings.bootstrap_tenant_name))
        ).scalar_one_or_none()
        if not tenant:
            tenant = Tenant(
                name=settings.bootstrap_tenant_name,
                plan="trial",
                compliance_profiles=settings.default_compliance_profiles,
                block_on_high_severity=settings.default_block_on_high_severity,
            )
            session.add(tenant)
            await session.flush()
        admin = User(
            tenant_id=tenant.id,
            email=settings.bootstrap_admin_email,
            password_hash=hash_password(settings.bootstrap_admin_password),
            role="admin",
        )
        session.add(admin)
        log.warning(
            "bootstrap: created default tenant '%s' with admin '%s' — change the password immediately.",
            tenant.name,
            admin.email,
        )
