"""Token / cost estimation for upstream models.

This is a *defensive* estimator: it is not a substitute for the upstream
provider's billing. It exists to drive in-flight budget enforcement and
admin dashboards. Numbers are USD per 1M tokens, prompt+completion blended
where the upstream charges asymmetrically — admins can override per tenant
via policy spec key ``model_prices``.

You can update this table without touching anything else; the budget
enforcer reads it through ``estimate_request_cost``.
"""

from __future__ import annotations

from typing import Any

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
    p = lookup_price(model, overrides)
    return (input_chars / 1_000_000.0) * p["input"] + (output_chars / 1_000_000.0) * p["output"]
