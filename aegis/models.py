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
    tools: Mapped[list[RegisteredTool]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    agents: Mapped[list[Agent]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    protected_domains: Mapped[list[ProtectedDomain]] = relationship(
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
    last_used_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # CIDR allow-list: comma-separated, empty = no IP restriction.
    allowed_ips: Mapped[str] = mapped_column(String(500), default="")
    # If true, the very first request locks first_seen_ip and any future
    # request from a different IP is blocked unless explicitly overridden.
    pin_first_seen_ip: Mapped[bool] = mapped_column(Boolean, default=False)
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


class RegisteredTool(Base):
    """A tool / function the tenant has explicitly registered.

    The proxy refuses to advertise an unregistered tool to the model and
    refuses to relay a model-emitted ``tool_call`` whose name isn't in this
    table. ``schema_hash`` lets us detect a supply-chain mutation: if the
    tool's argument schema changes upstream, the hash mismatch triggers a
    block (or a "needs re-approval" warning, depending on policy).
    """

    __tablename__ = "registered_tools"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_tool_per_tenant"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # read | write | destructive | financial | network
    action_class: Mapped[str] = mapped_column(String(40), default="read")
    schema_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    # JSON: domain allow/deny lists, monetary cap, custom guardrails
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="tools")


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
    # Tamper-evident audit chain: each row records the previous row's hash and
    # its own hash over the canonical payload. ``audit_hash`` in :mod:`aegis.audit`
    # verifies the chain on demand.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    this_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)


class Agent(Base):
    """A logical agent — a deployed bot, integration, or workflow.

    Agents are auto-discovered the first time the proxy sees a new
    ``X-Aegis-Agent`` header or new (api_key, model) combination, so
    customers get an inventory immediately without manual setup. Admins can
    rename them, set allowed model lists, declare autonomy level, and tighten
    risk-relevant settings.
    """

    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_agent_per_tenant"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(50), default="assistant")  # assistant|workflow|browser|background
    autonomy: Mapped[str] = mapped_column(String(20), default="supervised")  # supervised|semi|autonomous
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    discovered_from: Mapped[str | None] = mapped_column(String(80), nullable=True)
    discovered_via_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    block_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_factors: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="agents")


class PendingApproval(Base):
    """Async human-in-the-loop ticket for a sensitive action.

    Created when a model emits a sensitive ``tool_call`` (or a custom rule
    requires approval) without ``X-Aegis-Approve-Action: 1``. The agent
    receives a ticket id; a human approves/denies it from the admin queue;
    the agent then re-submits the original request with
    ``X-Aegis-Approval-Ticket: <id>`` and the gateway lets the call through.
    """

    __tablename__ = "pending_approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    api_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_label: Mapped[str | None] = mapped_column(String(200), nullable=True)
    request_id: Mapped[str] = mapped_column(String(36), index=True)
    action_class: Mapped[str] = mapped_column(String(40))  # destructive|financial|...
    tool_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    arguments_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_factors: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|approved|denied|expired
    decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)


class ToolCredential(Base):
    """Vaulted credential that a registered tool needs (OAuth token, API key, etc.).

    The encrypted blob is stored in ``secret_ciphertext`` — at rest you should
    wrap this with KMS envelope encryption (``AEGIS_VAULT_KEY``); the model in
    code is intentionally agnostic to the cipher. ``scopes`` is a CSV of
    minimum-privilege scopes the tool actually needs; ``expires_at`` drives
    rotation reminders / soft revoke.
    """

    __tablename__ = "tool_credentials"
    __table_args__ = (
        UniqueConstraint("tenant_id", "tool_name", "label", name="uq_toolcred_per_tenant_tool"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    tool_name: Mapped[str] = mapped_column(String(120))
    label: Mapped[str] = mapped_column(String(120), default="default")
    kind: Mapped[str] = mapped_column(String(40), default="api_key")  # api_key|oauth|basic|custom
    secret_ciphertext: Mapped[str] = mapped_column(Text)
    scopes: Mapped[str] = mapped_column(String(500), default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rotation_period_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)


class ProtectedDomain(Base):
    """Tenant-controlled list of brand domains to detect lookalikes for.

    Used by URL safety to flag punycode/typo lookalikes (``g00gle.com``,
    ``goog1e.com``, ``аpple.com``) — common in scams and spoofed agents.
    """

    __tablename__ = "protected_domains"
    __table_args__ = (UniqueConstraint("tenant_id", "domain", name="uq_protected_domain_per_tenant"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    domain: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    tenant: Mapped[Tenant] = relationship(back_populates="protected_domains")
