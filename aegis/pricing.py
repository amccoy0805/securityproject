"""Token / cost estimation for upstream models.

Two pricing layers, in this order:

1. **Reconciled** (preferred) — when the upstream returns a ``usage`` block
   with ``prompt_tokens`` / ``completion_tokens`` (OpenAI) or
   ``input_tokens`` / ``output_tokens`` (Anthropic), Aegis uses those
   billing-grade actuals to commit cost to the budget enforcer.
2. **Estimated** — used pre-flight (before the upstream call) to predict
   whether a request would push a budget over the line. Today this is a
   chars/token approximation; for OpenAI-compatible models we also expose a
   ``tiktoken`` path when the optional dep is installed.

Both paths share the same per-model price table so the numbers stay
comparable; ``cost_from_usage`` and ``estimate_cost_usd`` both return USD.

Admins can override prices per tenant via the ``model_prices`` policy
spec key.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("aegis.pricing")

try:
    import tiktoken  # type: ignore[import-not-found]
    _TIKTOKEN_OK = True
except Exception:  # pragma: no cover
    _TIKTOKEN_OK = False
    tiktoken = None

# USD per 1M characters (we estimate ~4 chars/token, conservatively rounded).
# Defaults are intentionally a bit pessimistic so budgets bite earlier rather
# than later. Override per tenant in policy spec.
_DEFAULT_PRICE_USD_PER_M_CHARS: dict[str, dict[str, float]] = {
    # OpenAI
    "gpt-4o":            {"input": 1.25, "output": 5.0},
    "gpt-4o-mini":       {"input": 0.04, "output": 0.16},
    "gpt-4-turbo":       {"input": 2.50, "output": 7.5},
    "gpt-4":             {"input": 7.50, "output": 15.0},
    "gpt-3.5-turbo":     {"input": 0.13, "output": 0.38},
    # Anthropic
    "claude-3-opus":     {"input": 3.75, "output": 18.75},
    "claude-3-sonnet":   {"input": 0.75, "output": 3.75},
    "claude-3-haiku":    {"input": 0.06, "output": 0.31},
    "claude-3-5-sonnet": {"input": 0.75, "output": 3.75},
    # Catch-all default
    "_default":          {"input": 1.0,  "output": 3.0},
}


def lookup_price(model: str | None, overrides: dict[str, Any] | None = None) -> dict[str, float]:
    table: dict[str, dict[str, float]] = dict(_DEFAULT_PRICE_USD_PER_M_CHARS)
    if overrides:
        for k, v in overrides.items():
            if isinstance(v, dict) and "input" in v and "output" in v:
                table[k] = {"input": float(v["input"]), "output": float(v["output"])}
    if not model:
        return table["_default"]
    if model in table:
        return table[model]
    for prefix, p in table.items():
        if prefix != "_default" and model.startswith(prefix):
            return p
    return table["_default"]


def estimate_cost_usd(
    model: str | None,
    input_chars: int,
    output_chars: int,
    *,
    overrides: dict[str, Any] | None = None,
) -> float:
    """Pre-flight estimate based on character counts."""
    p = lookup_price(model, overrides)
    return (input_chars / 1_000_000.0) * p["input"] + (output_chars / 1_000_000.0) * p["output"]


# A chars-per-token ratio chosen to *match* the per-character price table
# above (those numbers were calibrated against ~4 chars/token). When we have
# real token counts from the upstream, we convert tokens → equivalent
# characters and reuse the same table so reconciled and estimated values are
# directly comparable.
_CHARS_PER_TOKEN = 4


def cost_from_usage(
    model: str | None,
    usage: dict[str, Any] | None,
    *,
    overrides: dict[str, Any] | None = None,
) -> float | None:
    """Reconciled cost from an upstream ``usage`` block; ``None`` if absent."""
    if not isinstance(usage, dict):
        return None
    in_tok = usage.get("prompt_tokens") or usage.get("input_tokens")
    out_tok = usage.get("completion_tokens") or usage.get("output_tokens")
    if in_tok is None and out_tok is None:
        return None
    in_chars = int(in_tok or 0) * _CHARS_PER_TOKEN
    out_chars = int(out_tok or 0) * _CHARS_PER_TOKEN
    return estimate_cost_usd(model, in_chars, out_chars, overrides=overrides)


def normalise_usage(usage: dict[str, Any] | None) -> dict[str, int] | None:
    """Return ``{prompt_tokens, completion_tokens, total_tokens}`` from any
    OpenAI- or Anthropic-shaped ``usage`` dict; ``None`` if the dict has no
    recognisable token fields."""
    if not isinstance(usage, dict):
        return None
    pt = usage.get("prompt_tokens", usage.get("input_tokens"))
    ct = usage.get("completion_tokens", usage.get("output_tokens"))
    if pt is None and ct is None:
        return None
    pt = int(pt or 0)
    ct = int(ct or 0)
    return {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct}


def count_tokens(text: str, *, model: str | None = None) -> int | None:
    """Best-effort token count using tiktoken when available; ``None`` otherwise."""
    if not text or not _TIKTOKEN_OK:
        return None
    try:
        if model:
            try:
                enc = tiktoken.encoding_for_model(model)
            except KeyError:
                enc = tiktoken.get_encoding("cl100k_base")
        else:
            enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:  # pragma: no cover  (tiktoken corner cases)
        return None
