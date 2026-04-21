"""ORM models for Aegis multi-tenant control plane.

Design notes:
- Strict tenant isolation: every business object carries ``tenant_id``.
- API keys are stored hashed (never plaintext); the prefix is kept so users can
  identify which key is which in the UI without revealing the secret.
- AuditEvent rows are append-only by application convention; for stronger
  guarantees, run them in a write-once table (e.g. Postgres logical replication
  to an immutable store, or AWS QLDB).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.utcnow()


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    plan: Mapped[str] = mapped_column(String(50), default="trial")
    compliance_profiles: Mapped[str] = mapped_column(String(200), default="baseline")
    block_on_high_severity: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    users: Mapped[list[User]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    api_keys: Mapped[list[ApiKey]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    policies: Mapped[list[Policy]] = relationship(back_populates="tenant", cascade="all, delete-orphan")
    provider_creds: Mapped[list[ProviderCredential]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_user_tenant_email"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    email: Mapped[str] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="member")  # admin | security | member
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="users")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    secret_hash: Mapped[str] = mapped_column(String(255))
    scopes: Mapped[str] = mapped_column(String(500), default="proxy")  # csv: proxy,admin
    user_label: Mapped[str | None] = mapped_column(String(200), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="api_keys")


class ProviderCredential(Base):
    """Upstream AI provider credentials per tenant.

    Stored encrypted-at-rest in production via DB-level encryption (e.g. KMS).
    The application treats these as sensitive and never exposes raw values
    via API responses.
    """

    __tablename__ = "provider_credentials"
    __table_args__ = (UniqueConstraint("tenant_id", "provider", name="uq_provider_per_tenant"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(50))  # openai | anthropic
    api_key: Mapped[str] = mapped_column(String(500))
    base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="provider_creds")


class Policy(Base):
    """A tenant policy: model allowlist + detector rules + redaction config."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    spec: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="policies")


class AuditEvent(Base):
    """Append-only audit trail for every AI interaction and admin action."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True)
    request_id: Mapped[str] = mapped_column(String(36), index=True)
    actor_kind: Mapped[str] = mapped_column(String(20))  # api_key | user | system
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_label: Mapped[str | None] = mapped_column(String(200), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    route: Mapped[str] = mapped_column(String(120))
    decision: Mapped[str] = mapped_column(String(20))  # allow | redact | block | error
    severity: Mapped[str] = mapped_column(String(20), default="info")  # info | low | medium | high
    findings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    input_chars: Mapped[int] = mapped_column(Integer, default=0)
    output_chars: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    request_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
