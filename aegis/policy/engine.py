"""Policy decisioning.

The engine takes the *effective* policy spec for a tenant + request, scans the
input for findings, and decides whether to **allow**, **redact**, or **block**.
On the response side it can re-scan and redact before returning to the client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .detectors import Finding, Severity, redact_text, scan_text
from .injection import scan_injection
from .profiles import build_default_spec


class Decision(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


@dataclass
class PolicySpec:
    profiles: list[str] = field(default_factory=lambda: ["baseline"])
    categories: list[str] = field(default_factory=list)
    actions: dict[str, str] = field(
        default_factory=lambda: {"low": "allow", "medium": "redact", "high": "block"}
    )
    model_allow: list[str] = field(default_factory=list)
    model_deny: list[str] = field(default_factory=list)
    store_request_excerpts: bool = True
    max_request_chars: int = 200_000
    redact_response: bool = True
    scan_injection: bool = True
    budgets: dict[str, Any] | None = None
    loop_threshold: int = 8
    loop_window_seconds: int = 120
    model_prices: dict[str, dict[str, float]] = field(default_factory=dict)
    tool_governance: dict[str, Any] | None = None
    rules: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicySpec:
        if not data:
            return cls()
        return cls(
            profiles=list(data.get("profiles", ["baseline"])),
            categories=list(data.get("categories", [])),
            actions={**cls().actions, **data.get("actions", {})},
            model_allow=list(data.get("model_allow", [])),
            model_deny=list(data.get("model_deny", [])),
            store_request_excerpts=bool(data.get("store_request_excerpts", True)),
            max_request_chars=int(data.get("max_request_chars", 200_000)),
            redact_response=bool(data.get("redact_response", True)),
            scan_injection=bool(data.get("scan_injection", True)),
            budgets=data.get("budgets"),
            loop_threshold=int(data.get("loop_threshold", 8)),
            loop_window_seconds=int(data.get("loop_window_seconds", 120)),
            model_prices=dict(data.get("model_prices", {})),
            tool_governance=data.get("tool_governance"),
            rules=list(data.get("rules", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profiles": list(self.profiles),
            "categories": list(self.categories),
            "actions": dict(self.actions),
            "model_allow": list(self.model_allow),
            "model_deny": list(self.model_deny),
            "store_request_excerpts": self.store_request_excerpts,
            "max_request_chars": self.max_request_chars,
            "redact_response": self.redact_response,
            "scan_injection": self.scan_injection,
            "budgets": self.budgets,
            "loop_threshold": self.loop_threshold,
            "loop_window_seconds": self.loop_window_seconds,
            "model_prices": dict(self.model_prices),
            "tool_governance": self.tool_governance,
            "rules": list(self.rules),
        }


def spec_from_dict(data: dict[str, Any]) -> PolicySpec:
    return PolicySpec.from_dict(data)


@dataclass
class PolicyInput:
    text: str
    model: str | None = None
    provider: str | None = None
    user_label: str | None = None
    untrusted: bool = False  # whole-request marker (e.g. X-Aegis-Untrusted)


@dataclass
class PolicyDecision:
    decision: Decision
    severity: Severity | None
    findings: list[Finding]
    sanitized_text: str
    reason: str
    matched_categories: list[str]
    untrusted_present: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "severity": self.severity.value if self.severity else "info",
            "findings": [f.to_dict() for f in self.findings],
            "matched_categories": list(self.matched_categories),
            "reason": self.reason,
            "untrusted_present": self.untrusted_present,
        }


def evaluate_inbound(spec: PolicySpec, request: PolicyInput) -> PolicyDecision:
    """Evaluate a request *before* it goes to the AI provider."""
    if request.model:
        if spec.model_deny and request.model in spec.model_deny:
            return PolicyDecision(
                decision=Decision.BLOCK,
                severity=Severity.HIGH,
                findings=[],
                sanitized_text=request.text,
                reason=f"Model '{request.model}' is denied by policy.",
                matched_categories=[],
            )
        if spec.model_allow and request.model not in spec.model_allow:
            return PolicyDecision(
                decision=Decision.BLOCK,
                severity=Severity.HIGH,
                findings=[],
                sanitized_text=request.text,
                reason=f"Model '{request.model}' is not in the allow-list.",
                matched_categories=[],
            )

    if len(request.text) > spec.max_request_chars:
        return PolicyDecision(
            decision=Decision.BLOCK,
            severity=Severity.MEDIUM,
            findings=[],
            sanitized_text=request.text,
            reason=(
                f"Request length {len(request.text)} exceeds policy maximum "
                f"of {spec.max_request_chars} characters."
            ),
            matched_categories=[],
            untrusted_present=request.untrusted,
        )

    inj = scan_injection(
        request.text, untrusted_request=request.untrusted, enabled=spec.scan_injection
    )
    working_text = inj.sanitized_text  # invisibles removed, untrusted tags stripped
    data_findings = scan_text(working_text, enabled_categories=spec.categories or None)
    findings: list[Finding] = list(data_findings) + list(inj.findings)
    untrusted_present = inj.untrusted_present

    if not findings:
        return PolicyDecision(
            decision=Decision.ALLOW,
            severity=None,
            findings=[],
            sanitized_text=working_text,
            reason="No sensitive content or injection signals detected.",
            matched_categories=[],
            untrusted_present=untrusted_present,
        )

    top_severity = max((f.severity for f in findings), key=lambda s: s.rank)
    matched_categories = sorted({f.category for f in findings})
    action = spec.actions.get(top_severity.value, "allow")

    if action == "block":
        return PolicyDecision(
            decision=Decision.BLOCK,
            severity=top_severity,
            findings=findings,
            sanitized_text=working_text,
            reason=(
                f"Blocked: {len(findings)} finding(s) including {top_severity.value} "
                f"severity ({', '.join(matched_categories)})."
            ),
            matched_categories=matched_categories,
            untrusted_present=untrusted_present,
        )
    if action == "redact":
        return PolicyDecision(
            decision=Decision.REDACT,
            severity=top_severity,
            findings=findings,
            sanitized_text=redact_text(working_text, findings),
            reason=(
                f"Redacted {len(findings)} finding(s) "
                f"({', '.join(matched_categories)}) before forwarding."
            ),
            matched_categories=matched_categories,
            untrusted_present=untrusted_present,
        )
    return PolicyDecision(
        decision=Decision.ALLOW,
        severity=top_severity,
        findings=findings,
        sanitized_text=working_text,
        reason="Findings present but policy permits at this severity.",
        matched_categories=matched_categories,
        untrusted_present=untrusted_present,
    )


def apply_outbound(spec: PolicySpec, text: str) -> tuple[str, list[Finding]]:
    """Re-scan model output and redact before returning to the client.

    On the response side we also run the injection scan: model output that
    contains a markdown-image data-exfil link, hidden Unicode tags, or a forged
    system block is *itself* an attack surface (renderers will execute it).
    """
    if not spec.redact_response or not text:
        return text, []
    inj = scan_injection(text, untrusted_request=False, enabled=spec.scan_injection)
    working = inj.sanitized_text
    data_findings = scan_text(working, enabled_categories=spec.categories or None)
    findings = list(data_findings) + list(inj.findings)
    if not findings:
        return working, []
    return redact_text(working, findings), findings


def effective_spec(profile_names: list[str], overrides: dict[str, Any] | None = None) -> PolicySpec:
    base = build_default_spec(profile_names)
    if overrides:
        for k, v in overrides.items():
            base[k] = v
    return PolicySpec.from_dict(base)
