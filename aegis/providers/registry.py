"""Provider registry — central place to instantiate adapters.

Per-tenant credentials override env defaults. Credentials live in DB and are
resolved by ``aegis.proxy`` before this registry is asked to build an adapter.
"""

from __future__ import annotations

from ..config import get_settings
from .anthropic import AnthropicAdapter
from .base import ProviderAdapter
from .openai import OpenAIAdapter

_BUILDERS: dict[str, type[ProviderAdapter]] = {
    "openai": OpenAIAdapter,
    "anthropic": AnthropicAdapter,
}


def list_providers() -> list[str]:
    return sorted(_BUILDERS.keys())


def get_provider(
    name: str,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
) -> ProviderAdapter:
    if name not in _BUILDERS:
        raise ValueError(f"Unknown provider '{name}'. Known: {sorted(_BUILDERS)}")
    settings = get_settings()
    if name == "openai":
        return _BUILDERS[name](
            api_key=api_key or settings.openai_api_key,
            base_url=base_url or settings.openai_base_url,
        )
    if name == "anthropic":
        return _BUILDERS[name](
            api_key=api_key or settings.anthropic_api_key,
            base_url=base_url or settings.anthropic_base_url,
        )
    raise ValueError(f"No factory wired for provider '{name}'")
