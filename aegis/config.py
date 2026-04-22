"""Runtime configuration for Aegis AI Gateway.

All settings can be overridden via environment variables prefixed with ``AEGIS_``
(see ``.env.example``). Provider credentials use their conventional names
(``OPENAI_API_KEY``, ``ANTHROPIC_API_KEY``, ...) so existing infra works unchanged.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    env: Literal["dev", "staging", "prod"] = Field(default="dev", alias="AEGIS_ENV")
    host: str = Field(default="0.0.0.0", alias="AEGIS_HOST")
    port: int = Field(default=8080, alias="AEGIS_PORT")
    log_level: str = Field(default="INFO", alias="AEGIS_LOG_LEVEL")

    secret_key: str = Field(
        default="dev-only-insecure-change-me", alias="AEGIS_SECRET_KEY"
    )
    session_cookie_secure: bool = Field(default=False, alias="AEGIS_SESSION_COOKIE_SECURE")
    allowed_hosts: str = Field(default="*", alias="AEGIS_ALLOWED_HOSTS")

    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/aegis.db", alias="AEGIS_DATABASE_URL"
    )

    bootstrap_admin_email: str = Field(
        default="admin@example.com", alias="AEGIS_BOOTSTRAP_ADMIN_EMAIL"
    )
    bootstrap_admin_password: str = Field(
        default="changeme-strong-password", alias="AEGIS_BOOTSTRAP_ADMIN_PASSWORD"
    )
    bootstrap_tenant_name: str = Field(
        default="Default Tenant", alias="AEGIS_BOOTSTRAP_TENANT_NAME"
    )

    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    openai_base_url: str = Field(default="https://api.openai.com/v1", alias="OPENAI_BASE_URL")
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_base_url: str = Field(default="https://api.anthropic.com", alias="ANTHROPIC_BASE_URL")

    default_compliance_profiles: str = Field(
        default="baseline", alias="AEGIS_DEFAULT_COMPLIANCE_PROFILES"
    )
    default_block_on_high_severity: bool = Field(
        default=True, alias="AEGIS_DEFAULT_BLOCK_ON_HIGH_SEVERITY"
    )

    redis_url: str | None = Field(default=None, alias="AEGIS_REDIS_URL")

    @property
    def allowed_hosts_list(self) -> list[str]:
        return [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]

    @property
    def default_compliance_profile_list(self) -> list[str]:
        return [p.strip() for p in self.default_compliance_profiles.split(",") if p.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
