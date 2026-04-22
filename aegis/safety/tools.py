"""Tool / function-call governance.

Inspects two surfaces:

1. **Inbound** — the ``tools`` array a customer sends in the request. We
   refuse to advertise an unregistered tool to the model. This stops a
   compromised app or a supply-chain plugin from silently teaching the model
   a new "delete_files" tool.

2. **Outbound** — the model's *response* may include ``tool_calls``
   (OpenAI) or content blocks of type ``tool_use`` (Anthropic). For each:
   - classify the action (read/write/destructive/financial/network),
   - run URL safety on the arguments,
   - check tenant action policy: anything sensitive needs an explicit
     ``X-Aegis-Approve-Action`` header (or a per-tool ``requires_approval``
     opt-out),
   - apply a monetary threshold guard for financial calls.

When something is blocked, we *strip* the call from the response so the
client agent never receives an executable handle to it. The audit log
records what was stripped and why.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..models import RegisteredTool
from .actions import classify_tool
from .schema_validate import validate_arguments
from .url_safety import UrlFinding, extract_urls, inspect_url


@dataclass
class ToolPolicy:
    enforce_registry: bool = True
    require_approval_for: list[str] = field(
        default_factory=lambda: ["destructive", "financial", "memory_write"]
    )
    monetary_threshold_usd: float = 100.0
    deny_domains: list[str] = field(default_factory=list)
    schema_mismatch_blocks: bool = True
    sandbox_required_for: list[str] = field(default_factory=list)
    require_sandbox_class: list[str] = field(default_factory=list)
    protected_domains: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ToolPolicy:
        if not data:
            return cls()
        spec = cls()
        if "enforce_registry" in data:
            spec.enforce_registry = bool(data["enforce_registry"])
        if "require_approval_for" in data and isinstance(data["require_approval_for"], list):
            spec.require_approval_for = [str(x).lower() for x in data["require_approval_for"]]
        if "monetary_threshold_usd" in data:
            spec.monetary_threshold_usd = float(data["monetary_threshold_usd"])
        if "deny_domains" in data and isinstance(data["deny_domains"], list):
            spec.deny_domains = [str(x).lower() for x in data["deny_domains"]]
        if "schema_mismatch_blocks" in data:
            spec.schema_mismatch_blocks = bool(data["schema_mismatch_blocks"])
        if "sandbox_required_for" in data and isinstance(data["sandbox_required_for"], list):
            spec.sandbox_required_for = [str(x) for x in data["sandbox_required_for"]]
        if "require_sandbox_class" in data and isinstance(data["require_sandbox_class"], list):
            spec.require_sandbox_class = [str(x).lower() for x in data["require_sandbox_class"]]
        if "protected_domains" in data and isinstance(data["protected_domains"], list):
            spec.protected_domains = [str(x).lower() for x in data["protected_domains"]]
        return spec


@dataclass
class ToolFinding:
    name: str
    severity: str  # low | medium | high
    reason: str
    action_class: str | None = None
    arguments_excerpt: str | None = None
    url_findings: list[UrlFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "reason": self.reason,
            "action_class": self.action_class,
            "arguments_excerpt": self.arguments_excerpt,
            "urls": [u.to_dict() for u in self.url_findings],
        }


@dataclass
class InboundToolReport:
    blocked: bool
    reason: str | None
    findings: list[ToolFinding]
    sanitized_tools: list[Any]


@dataclass
class OutboundToolReport:
    findings: list[ToolFinding]
    blocked_calls: list[ToolFinding]
    sanitized: bool


# ---------- argument helpers ----------

def _coerce_args(args: Any) -> Any:
    """OpenAI sends tool_call.function.arguments as a JSON string; coerce."""
    if isinstance(args, str):
        try:
            return json.loads(args)
        except (ValueError, TypeError):
            return {"_raw": args}
    return args


def _excerpt_args(args: Any, limit: int = 400) -> str:
    try:
        s = json.dumps(args, default=str)
    except (TypeError, ValueError):
        s = str(args)
    return s if len(s) <= limit else s[:limit] + "…"


def _detect_amount_usd(args: Any) -> float | None:
    """Best-effort hunt for an 'amount' field in dollars."""
    if not isinstance(args, dict):
        return None
    for key in ("amount_usd", "amount", "total", "price", "cost", "value"):
        if key in args:
            v = args[key]
            try:
                return float(v)
            except (TypeError, ValueError):
                continue
    return None


# ---------- inbound: validate request.tools ----------

def inspect_request_tools(
    *,
    request_tools: list[Any] | None,
    registered: dict[str, RegisteredTool],
    policy: ToolPolicy,
) -> InboundToolReport:
    """Validate the ``tools`` array (OpenAI/Anthropic schema) on the request."""
    if not request_tools:
        return InboundToolReport(blocked=False, reason=None, findings=[], sanitized_tools=[])
    if not policy.enforce_registry:
        return InboundToolReport(
            blocked=False, reason=None, findings=[], sanitized_tools=list(request_tools)
        )

    findings: list[ToolFinding] = []
    sanitized: list[Any] = []
    for entry in request_tools:
        name = _extract_tool_name(entry)
        if not name:
            findings.append(
                ToolFinding(
                    name="<unnamed>", severity="medium",
                    reason="tool entry missing name; rejected",
                )
            )
            continue
        reg = registered.get(name)
        if not reg or not reg.enabled:
            findings.append(
                ToolFinding(
                    name=name, severity="high",
                    reason="tool not registered for this tenant — refusing to advertise to model",
                )
            )
            continue
        if reg.schema_hash and policy.schema_mismatch_blocks:
            current = _hash_tool_schema(entry)
            if current != reg.schema_hash:
                findings.append(
                    ToolFinding(
                        name=name, severity="high",
                        reason=(
                            "registered schema_hash mismatch — possible supply-chain "
                            "mutation; refusing to advertise to model"
                        ),
                    )
                )
                continue
        sanitized.append(entry)

    if not sanitized and request_tools:
        return InboundToolReport(
            blocked=True,
            reason=(
                "All tools in the request are unregistered or modified; "
                "register them in the admin console first."
            ),
            findings=findings,
            sanitized_tools=[],
        )
    return InboundToolReport(blocked=False, reason=None, findings=findings, sanitized_tools=sanitized)


def _extract_tool_name(entry: Any) -> str | None:
    if not isinstance(entry, dict):
        return None
    if "function" in entry and isinstance(entry["function"], dict):
        return entry["function"].get("name")
    return entry.get("name")


def _hash_tool_schema(entry: Any) -> str:
    import hashlib

    try:
        canon = json.dumps(entry, sort_keys=True, default=str)
    except (TypeError, ValueError):
        canon = str(entry)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def schema_hash(entry: Any) -> str:
    """Public helper so admins can compute a schema hash to register."""
    return _hash_tool_schema(entry)


# ---------- outbound: validate model-emitted tool calls ----------

def inspect_response_calls(
    response_body: dict[str, Any],
    *,
    registered: dict[str, RegisteredTool],
    policy: ToolPolicy,
    approved: bool,
) -> tuple[dict[str, Any], OutboundToolReport]:
    """Inspect model-emitted tool calls; strip blocked ones from the response.

    Supports both OpenAI's ``choices[].message.tool_calls`` shape and
    Anthropic's ``content[]`` blocks of ``type=tool_use``.
    """
    findings: list[ToolFinding] = []
    blocked: list[ToolFinding] = []
    sanitized = False

    # ---- OpenAI: choices[].message.tool_calls ----
    choices = response_body.get("choices")
    if isinstance(choices, list):
        new_choices: list[Any] = []
        for choice in choices:
            new_choice = dict(choice) if isinstance(choice, dict) else choice
            msg = dict(new_choice.get("message") or {}) if isinstance(new_choice, dict) else None
            tcs = msg.get("tool_calls") if isinstance(msg, dict) else None
            if isinstance(tcs, list):
                kept: list[Any] = []
                for tc in tcs:
                    name = (tc.get("function") or {}).get("name") if isinstance(tc, dict) else None
                    raw_args = (tc.get("function") or {}).get("arguments") if isinstance(tc, dict) else None
                    args = _coerce_args(raw_args)
                    f = _evaluate_call(name, args, registered=registered, policy=policy, approved=approved)
                    findings.append(f) if f.severity == "low" else findings.append(f)
                    if f.severity in {"medium", "high"} and "block" in f.reason.lower():
                        blocked.append(f)
                    else:
                        kept.append(tc)
                if len(kept) != len(tcs):
                    sanitized = True
                    msg["tool_calls"] = kept
                    new_choice["message"] = msg
            new_choices.append(new_choice)
        response_body = dict(response_body)
        response_body["choices"] = new_choices

    # ---- Anthropic: content[].type == 'tool_use' ----
    content = response_body.get("content")
    if isinstance(content, list):
        kept_content: list[Any] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                name = block.get("name")
                args = block.get("input") or {}
                f = _evaluate_call(name, args, registered=registered, policy=policy, approved=approved)
                findings.append(f)
                if f.severity in {"medium", "high"} and "block" in f.reason.lower():
                    blocked.append(f)
                    sanitized = True
                    continue
            kept_content.append(block)
        if sanitized:
            response_body = dict(response_body)
            response_body["content"] = kept_content

    return response_body, OutboundToolReport(findings=findings, blocked_calls=blocked, sanitized=sanitized)


def _evaluate_call(
    name: str | None,
    args: Any,
    *,
    registered: dict[str, RegisteredTool],
    policy: ToolPolicy,
    approved: bool,
) -> ToolFinding:
    if not name:
        return ToolFinding(
            name="<unnamed>",
            severity="high",
            reason="model emitted a tool_call without a name; blocked",
        )

    reg = registered.get(name)
    if policy.enforce_registry and not reg:
        return ToolFinding(
            name=name, severity="high",
            reason=(
                "model attempted to call an unregistered tool; blocked. "
                "Register the tool in the admin console first."
            ),
            arguments_excerpt=_excerpt_args(args),
        )
    if reg and not reg.enabled:
        return ToolFinding(
            name=name, severity="high",
            reason="tool is registered but disabled; blocked",
            arguments_excerpt=_excerpt_args(args),
        )

    declared = reg.action_class if reg else None
    verdict = classify_tool(name, declared=declared)
    action_class = verdict.cls.value

    # Schema validation against the registered JSON Schema.
    if reg and getattr(reg, "schema_json", None):
        sv = validate_arguments(args, tool_schema=reg.schema_json)
        if not sv.ok:
            joined = "; ".join(sv.errors[:3])
            return ToolFinding(
                name=name,
                severity="high",
                reason=(
                    f"tool argument schema validation failed: {joined}; blocked"
                ),
                action_class=action_class,
                arguments_excerpt=_excerpt_args(args),
            )

    cfg = (reg.config if reg else {}) or {}
    allow_domains = list(cfg.get("allow_domains", [])) if isinstance(cfg, dict) else []
    deny_domains = list(policy.deny_domains) + list(cfg.get("deny_domains", [])) if isinstance(cfg, dict) else list(policy.deny_domains)
    allow_private = bool(cfg.get("allow_private_targets", False)) if isinstance(cfg, dict) else False
    protected = list(policy.protected_domains)
    if isinstance(cfg, dict):
        protected.extend(cfg.get("protected_domains", []) or [])

    sandbox_required = bool(cfg.get("sandbox_required", False)) if isinstance(cfg, dict) else False
    if action_class in policy.require_sandbox_class or (reg and reg.name in policy.sandbox_required_for):
        sandbox_required = True

    url_findings: list[UrlFinding] = []
    for url in extract_urls(args):
        v = inspect_url(
            url,
            allow_domains=allow_domains or None,
            deny_domains=deny_domains or None,
            allow_private=allow_private,
            protected_domains=protected or None,
        )
        url_findings.extend(v.findings)
        if not v.allowed:
            return ToolFinding(
                name=name, severity="high",
                reason=f"tool argument URL blocked: {v.blocked_reason}",
                action_class=action_class,
                arguments_excerpt=_excerpt_args(args),
                url_findings=v.findings,
            )

    if sandbox_required:
        sandbox_token = (str(args.get("_sandbox", "")).lower() if isinstance(args, dict) else "")
        if sandbox_token not in {"1", "true", "yes"}:
            return ToolFinding(
                name=name, severity="high",
                reason=(
                    "tool requires sandboxed execution; refusing to relay until "
                    "the orchestrator marks the call with `_sandbox: true` "
                    "(see docs/agent-safety.md §7)."
                ),
                action_class=action_class,
                arguments_excerpt=_excerpt_args(args),
                url_findings=url_findings,
            )

    needs_approval = (
        action_class in policy.require_approval_for
        or (reg.requires_approval if reg else False)
    )
    if needs_approval and not approved:
        return ToolFinding(
            name=name, severity="high",
            reason=(
                f"sensitive tool ({action_class}) requires explicit approval; "
                "blocked. Retry with header `X-Aegis-Approve-Action: 1`."
            ),
            action_class=action_class,
            arguments_excerpt=_excerpt_args(args),
            url_findings=url_findings,
        )

    if action_class == "financial":
        amount = _detect_amount_usd(args) or 0.0
        cap = float(cfg.get("monetary_threshold_usd", policy.monetary_threshold_usd))
        if amount > cap and not approved:
            return ToolFinding(
                name=name, severity="high",
                reason=(
                    f"financial action of ${amount:.2f} exceeds threshold of "
                    f"${cap:.2f}; blocked. Retry with `X-Aegis-Approve-Action: 1`."
                ),
                action_class=action_class,
                arguments_excerpt=_excerpt_args(args),
                url_findings=url_findings,
            )

    sev = "low" if action_class == "read" else "medium"
    return ToolFinding(
        name=name, severity=sev,
        reason=(
            f"allowed ({action_class})"
            + (" — explicit approval recorded" if approved and needs_approval else "")
        ),
        action_class=action_class,
        arguments_excerpt=_excerpt_args(args),
        url_findings=url_findings,
    )
