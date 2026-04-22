"""Policy engine: detection, redaction, and decisioning."""

from .detectors import Finding, Severity, scan_text
from .engine import (
    Decision,
    PolicyDecision,
    PolicyInput,
    PolicySpec,
    apply_outbound,
    evaluate_inbound,
    spec_from_dict,
)
from .injection import (
    UNTRUSTED_CLOSE,
    UNTRUSTED_OPEN,
    InjectionResult,
    scan_injection,
)
from .profiles import COMPLIANCE_PROFILES, build_default_spec

__all__ = [
    "COMPLIANCE_PROFILES",
    "Decision",
    "Finding",
    "InjectionResult",
    "PolicyDecision",
    "PolicyInput",
    "PolicySpec",
    "Severity",
    "UNTRUSTED_CLOSE",
    "UNTRUSTED_OPEN",
    "apply_outbound",
    "build_default_spec",
    "evaluate_inbound",
    "scan_injection",
    "scan_text",
    "spec_from_dict",
]
