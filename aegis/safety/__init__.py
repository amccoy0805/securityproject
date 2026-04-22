"""Runtime safety controls: budgets, loops, action gating, tool governance, URL safety."""

import logging

from ..config import get_settings
from .actions import ActionClass, ActionVerdict, classify_tool
from .budgets import BudgetCheck, BudgetEnforcer, BudgetSpec
from .budgets import enforcer as in_memory_budget_enforcer
from .loops import LoopDetector, LoopVerdict
from .loops import detector as in_memory_loop_detector
from .tools import (
    InboundToolReport,
    OutboundToolReport,
    ToolFinding,
    ToolPolicy,
    inspect_request_tools,
    inspect_response_calls,
    schema_hash,
)
from .url_safety import UrlFinding, UrlVerdict, extract_urls, inspect_url

log = logging.getLogger("aegis.safety")


def select_backends() -> tuple[object, object]:
    """Return ``(budget_enforcer, loop_detector)`` for the current process.

    Uses Redis when ``AEGIS_REDIS_URL`` is set and reachable, otherwise
    falls back to the always-available in-memory implementations. The
    selection is performed at startup; the proxy uses ``get_runtime()`` to
    resolve them on every request.
    """
    settings = get_settings()
    url = settings.redis_url
    if url:
        from .redis_backend import (
            RedisBudgetEnforcer,
            RedisLoopDetector,
            is_available,
        )
        if is_available(url):
            log.info("aegis: using Redis backend at %s for budgets + loops", url)
            return RedisBudgetEnforcer(url), RedisLoopDetector(url)
        log.warning("aegis: AEGIS_REDIS_URL set but Redis unreachable; falling back to in-memory")
    return in_memory_budget_enforcer, in_memory_loop_detector


_runtime: tuple[object, object] | None = None


def get_runtime() -> tuple[object, object]:
    """Lazy singleton — first caller resolves the backend, others reuse it.

    Tests can call ``reset_runtime()`` to re-resolve (e.g. after toggling env
    vars).
    """
    global _runtime
    if _runtime is None:
        _runtime = select_backends()
    return _runtime


def reset_runtime() -> None:
    global _runtime
    _runtime = None


__all__ = [
    "ActionClass",
    "ActionVerdict",
    "BudgetCheck",
    "BudgetEnforcer",
    "BudgetSpec",
    "InboundToolReport",
    "LoopDetector",
    "LoopVerdict",
    "OutboundToolReport",
    "ToolFinding",
    "ToolPolicy",
    "UrlFinding",
    "UrlVerdict",
    "classify_tool",
    "extract_urls",
    "get_runtime",
    "inspect_request_tools",
    "inspect_response_calls",
    "inspect_url",
    "reset_runtime",
    "schema_hash",
    "select_backends",
]
