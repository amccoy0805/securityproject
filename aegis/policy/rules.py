"""Human-readable policy rules.

These are the consumer-friendly knobs the spec asks for: "never send
money", "never share SSNs", "require approval for email sends",
"block actions on weekends", etc.

Each rule is a small dataclass with a deterministic ``evaluate`` that
returns one of ``allow / require_approval / block`` and a reason string.
The rules engine evaluates every rule on every request *before* the
data-detector engine runs, and the union of decisions is folded into the
final outcome (strictest wins).

This is intentionally not a Turing-complete DSL — easy to audit, easy to
explain in the admin UI, and impossible to use to write malware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class RuleVerdict(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


@dataclass
class RuleResult:
    verdict: RuleVerdict
    reason: str
    rule_name: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule_name, "verdict": self.verdict.value, "reason": self.reason}


@dataclass
class RuleContext:
    """Snapshot of everything a rule can look at."""

    text: str
    model: str | None
    action_classes: list[str] = field(default_factory=list)
    detected_categories: list[str] = field(default_factory=list)
    untrusted_present: bool = False
    now: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Rule:
    name: str
    kind: str  # built-in identifier
    config: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def evaluate(self, ctx: RuleContext) -> RuleResult | None:
        if not self.enabled:
            return None
        return _DISPATCH[self.kind](self, ctx)


# ---- built-in rule kinds -------------------------------------------------------

def _r_never_send_money(rule: Rule, ctx: RuleContext) -> RuleResult | None:
    if "financial" in ctx.action_classes:
        return RuleResult(
            verdict=RuleVerdict.BLOCK,
            reason="Rule 'never send money' blocked a financial tool call.",
            rule_name=rule.name,
        )
    return None


def _r_require_approval_for(rule: Rule, ctx: RuleContext) -> RuleResult | None:
    target_classes = {c.lower() for c in rule.config.get("classes", [])}
    target_tools = {t.lower() for t in rule.config.get("tools", [])}
    seen = set(c.lower() for c in ctx.action_classes)
    if (target_classes & seen) or any(
        t in (ctx.text or "").lower() for t in target_tools
    ):
        return RuleResult(
            verdict=RuleVerdict.REQUIRE_APPROVAL,
            reason=(
                f"Rule '{rule.name}' requires human approval before "
                f"running {sorted(target_classes | target_tools)}."
            ),
            rule_name=rule.name,
        )
    return None


def _r_never_share_categories(rule: Rule, ctx: RuleContext) -> RuleResult | None:
    targets = {c.lower() for c in rule.config.get("categories", [])}
    if not targets:
        return None
    seen = set(c.lower() for c in ctx.detected_categories)
    matched = sorted(seen & targets)
    if matched:
        return RuleResult(
            verdict=RuleVerdict.BLOCK,
            reason=f"Rule '{rule.name}' refuses to share categories {matched}.",
            rule_name=rule.name,
        )
    return None


def _r_block_weekends(rule: Rule, ctx: RuleContext) -> RuleResult | None:
    # Mon=0 ... Sun=6; weekends = Sat (5), Sun (6).
    if ctx.now.weekday() < 5:
        return None
    if rule.config.get("only_for_classes"):
        target = {c.lower() for c in rule.config["only_for_classes"]}
        if not (target & set(c.lower() for c in ctx.action_classes)):
            return None
    return RuleResult(
        verdict=RuleVerdict.BLOCK,
        reason=f"Rule '{rule.name}' blocks actions on weekends.",
        rule_name=rule.name,
    )


def _r_business_hours_only(rule: Rule, ctx: RuleContext) -> RuleResult | None:
    start = int(rule.config.get("start_hour", 9))
    end = int(rule.config.get("end_hour", 17))
    if start <= ctx.now.hour < end and ctx.now.weekday() < 5:
        return None
    if rule.config.get("only_for_classes"):
        target = {c.lower() for c in rule.config["only_for_classes"]}
        if not (target & set(c.lower() for c in ctx.action_classes)):
            return None
    return RuleResult(
        verdict=RuleVerdict.BLOCK,
        reason=f"Rule '{rule.name}' allows activity only during business hours ({start}:00–{end}:00).",
        rule_name=rule.name,
    )


def _r_no_external_input_for_destructive(rule: Rule, ctx: RuleContext) -> RuleResult | None:
    """Spec item: "an injected webpage shouldn't be able to delete your files"."""
    if ctx.untrusted_present and (
        "destructive" in ctx.action_classes or "financial" in ctx.action_classes
    ):
        return RuleResult(
            verdict=RuleVerdict.BLOCK,
            reason=(
                f"Rule '{rule.name}' refuses destructive/financial actions when "
                "the request includes untrusted (e.g. scraped) content."
            ),
            rule_name=rule.name,
        )
    return None


_DISPATCH = {
    "never_send_money": _r_never_send_money,
    "require_approval_for": _r_require_approval_for,
    "never_share": _r_never_share_categories,
    "block_weekends": _r_block_weekends,
    "business_hours_only": _r_business_hours_only,
    "no_external_input_for_destructive": _r_no_external_input_for_destructive,
}


def parse_rules(spec: list[dict[str, Any]] | None) -> list[Rule]:
    if not spec:
        return []
    out: list[Rule] = []
    for entry in spec:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind", "")).strip()
        if kind not in _DISPATCH:
            continue
        out.append(
            Rule(
                name=str(entry.get("name", kind))[:120],
                kind=kind,
                config=dict(entry.get("config", {})),
                enabled=bool(entry.get("enabled", True)),
            )
        )
    return out


def evaluate_all(rules: list[Rule], ctx: RuleContext) -> list[RuleResult]:
    out: list[RuleResult] = []
    for r in rules:
        verdict = r.evaluate(ctx)
        if verdict is not None:
            out.append(verdict)
    return out


def fold(results: list[RuleResult]) -> RuleResult | None:
    """Fold many rule results into one, strictest-wins."""
    if not results:
        return None
    rank = {RuleVerdict.ALLOW: 0, RuleVerdict.REQUIRE_APPROVAL: 1, RuleVerdict.BLOCK: 2}
    return max(results, key=lambda r: rank[r.verdict])


CONSUMER_DEFAULT_RULES: list[dict[str, Any]] = [
    {"kind": "never_send_money", "name": "Never send money", "enabled": True},
    {
        "kind": "require_approval_for",
        "name": "Require approval for email sends",
        "config": {"classes": ["write"], "tools": ["send_email", "send_message", "send_sms"]},
    },
    {
        "kind": "no_external_input_for_destructive",
        "name": "No destructive actions from scraped content",
        "enabled": True,
    },
    {
        "kind": "never_share",
        "name": "Never share secrets / PCI / PHI",
        "config": {"categories": ["secret", "pci", "phi"]},
    },
]
