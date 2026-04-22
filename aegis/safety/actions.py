"""Action classification for agent tool calls.

When a model emits a tool/function call, the *name* and *arguments* of that
call carry intent ("delete this file", "send this email", "purchase this
SKU"). Aegis classifies every tool into one of these action classes:

- ``read``         — query/look-up only; no side-effects.
- ``write``        — mutates data the user owns (e.g. create_calendar_event).
- ``destructive``  — irrecoverable mutations (delete, drop, wipe, revoke).
- ``financial``    — moves money or commits to a purchase (charge, refund, buy, transfer).
- ``network``      — fetches arbitrary URLs (browse, http_request) — also subject
  to URL safety checks.

Classification is deterministic and explainable:

1. If a ``RegisteredTool.action_class`` is set, that wins.
2. Otherwise we fall back to a built-in keyword heuristic.

The proxy uses the class to decide whether to block, allow, or require an
explicit ``X-Aegis-Approve-Action`` header.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

DESTRUCTIVE_KEYWORDS = (
    "delete", "destroy", "drop", "wipe", "purge", "remove", "rm_",
    "uninstall", "format", "shred", "erase", "revoke", "cancel_account",
    "close_account", "deactivate",
)
FINANCIAL_KEYWORDS = (
    "pay", "purchase", "buy", "checkout", "charge", "refund", "transfer",
    "withdraw", "wire", "ach", "invoice", "subscribe", "renew", "order",
    "place_order", "stripe", "paypal",
)
MEMORY_KEYWORDS = (
    "memory_write", "remember", "store_memory", "save_memory", "memorize",
    "note_to_self", "set_memory", "persist_memory", "memory_set",
)
WRITE_KEYWORDS = (
    "create", "send", "post", "publish", "schedule", "update", "patch",
    "put", "edit", "modify", "set_", "write_", "append", "rename", "move",
    "save", "upsert", "insert", "share",
)
NETWORK_KEYWORDS = (
    "browse", "http_request", "http_fetch", "fetch_url", "open_url",
    "scrape", "crawl", "navigate",
)
READ_KEYWORDS = (
    "get_", "read_", "list_", "search", "query", "lookup", "find_",
    "fetch_", "retrieve", "describe", "view_",
)


class ActionClass(str, Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    FINANCIAL = "financial"
    NETWORK = "network"
    MEMORY_WRITE = "memory_write"

    @property
    def is_sensitive(self) -> bool:
        return self in {
            ActionClass.DESTRUCTIVE,
            ActionClass.FINANCIAL,
            ActionClass.WRITE,
            ActionClass.MEMORY_WRITE,
        }


@dataclass
class ActionVerdict:
    cls: ActionClass
    reason: str


_NAME_NORMALISER = re.compile(r"[^a-z0-9]+")


def _normalised_name(name: str) -> str:
    return _NAME_NORMALISER.sub("_", name.lower()).strip("_")


def classify_tool(name: str, *, declared: str | None = None) -> ActionVerdict:
    if declared:
        try:
            return ActionVerdict(ActionClass(declared.lower()), reason=f"explicitly declared as {declared}")
        except ValueError:
            pass  # unknown class declared — fall through to heuristic

    n = _normalised_name(name)
    for kw in DESTRUCTIVE_KEYWORDS:
        if kw in n:
            return ActionVerdict(ActionClass.DESTRUCTIVE, reason=f"name contains '{kw}'")
    for kw in FINANCIAL_KEYWORDS:
        if kw in n:
            return ActionVerdict(ActionClass.FINANCIAL, reason=f"name contains '{kw}'")
    for kw in MEMORY_KEYWORDS:
        if kw in n:
            return ActionVerdict(ActionClass.MEMORY_WRITE, reason=f"name contains '{kw}'")
    for kw in NETWORK_KEYWORDS:
        if kw in n:
            return ActionVerdict(ActionClass.NETWORK, reason=f"name contains '{kw}'")
    for kw in WRITE_KEYWORDS:
        if kw in n:
            return ActionVerdict(ActionClass.WRITE, reason=f"name contains '{kw}'")
    for kw in READ_KEYWORDS:
        if kw in n:
            return ActionVerdict(ActionClass.READ, reason=f"name contains '{kw}'")
    return ActionVerdict(ActionClass.READ, reason="default (no keyword match)")
