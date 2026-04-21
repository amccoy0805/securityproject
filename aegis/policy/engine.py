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
        }


def spec_from_dict(data: dict[str, Any]) -> PolicySpec:
    return PolicySpec.from_dict(data)


@dataclass
class PolicyInput:
    text: str
    model: str | None = None
    provider: str | None = None
    user_label: str | None = None


@dataclass
class PolicyDecision:
    decision: Decision
    severity: Severity | None
    findings: list[Finding]
    sanitized_text: str
    reason: str
    matched_categories: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "severity": self.severity.value if self.severity else "info",
            "findings": [f.to_dict() for f in self.findings],
            "matched_categories": list(self.matched_categories),
            "reason": self.reason,
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
        )

    findings = scan_text(request.text, enabled_categories=spec.categories or None)
    if not findings:
        return PolicyDecision(
            decision=Decision.ALLOW,
            severity=None,
            findings=[],
            sanitized_text=request.text,
            reason="No sensitive content detected.",
            matched_categories=[],
        )

    top_severity = max((f.severity for f in findings), key=lambda s: s.rank)
    matched_categories = sorted({f.category for f in findings})
    action = spec.actions.get(top_severity.value, "allow")

    if action == "block":
        return PolicyDecision(
            decision=Decision.BLOCK,
            severity=top_severity,
            findings=findings,
            sanitized_text=request.text,
            reason=(
                f"Blocked: {len(findings)} finding(s) including {top_severity.value} "
                f"severity ({', '.join(matched_categories)})."
            ),
            matched_categories=matched_categories,
        )
    if action == "redact":
        return PolicyDecision(
            decision=Decision.REDACT,
            severity=top_severity,
            findings=findings,
            sanitized_text=redact_text(request.text, findings),
            reason=(
                f"Redacted {len(findings)} finding(s) "
                f"({', '.join(matched_categories)}) before forwarding."
            ),
            matched_categories=matched_categories,
        )
    return PolicyDecision(
        decision=Decision.ALLOW,
        severity=top_severity,
        findings=findings,
        sanitized_text=request.text,
        reason="Sensitive content detected but policy permits at this severity.",
        matched_categories=matched_categories,
    )


def apply_outbound(spec: PolicySpec, text: str) -> tuple[str, list[Finding]]:
    """Re-scan model output and redact before returning to the client."""
    if not spec.redact_response or not text:
        return text, []
    findings = scan_text(text, enabled_categories=spec.categories or None)
    if not findings:
        return text, []
    return redact_text(text, findings), findings


def effective_spec(profile_names: list[str], overrides: dict[str, Any] | None = None) -> PolicySpec:
    base = build_default_spec(profile_names)
    if overrides:
        for k, v in overrides.items():
            base[k] = v
    return PolicySpec.from_dict(base)
