"""Built-in compliance profiles.

Profiles are not laws — they are opinionated, defensible defaults that an admin
can ship on day one and refine. Each profile produces a baseline ``PolicySpec``
fragment that the policy engine merges with tenant-specific overrides.
"""

from __future__ import annotations

from typing import Any

# Each profile defines:
#   - which detector categories are enabled
#   - default action per severity (allow|redact|block)
#   - model allow/deny lists
#   - whether to log full request excerpts (regulated data may forbid this)
COMPLIANCE_PROFILES: dict[str, dict[str, Any]] = {
    "baseline": {
        "description": "Sensible defaults for general enterprise use.",
        "categories": [
            "pii", "secret", "pci", "phi", "financial", "network",
            "injection", "exfiltration",
        ],
        "actions": {"low": "allow", "medium": "redact", "high": "block"},
        "model_allow": [],   # empty = allow all configured providers
        "model_deny": [],
        "store_request_excerpts": True,
        "max_request_chars": 200_000,
        "scan_injection": True,
    },
    "gdpr": {
        "description": "EU GDPR — minimise personal data exposure to AI.",
        "categories": ["pii", "secret", "financial", "network", "injection", "exfiltration"],
        "actions": {"low": "redact", "medium": "redact", "high": "block"},
        "model_allow": [],
        "model_deny": [],
        "store_request_excerpts": False,
        "max_request_chars": 100_000,
        "scan_injection": True,
    },
    "hipaa": {
        "description": "US HIPAA — block PHI from leaving controlled inference.",
        "categories": ["phi", "pii", "secret", "injection", "exfiltration"],
        "actions": {"low": "redact", "medium": "block", "high": "block"},
        "model_allow": [],
        "model_deny": [],
        "store_request_excerpts": False,
        "max_request_chars": 80_000,
        "scan_injection": True,
    },
    "pci": {
        "description": "PCI-DSS — never let PAN/CVV reach AI providers.",
        "categories": ["pci", "secret", "pii", "injection", "exfiltration"],
        "actions": {"low": "allow", "medium": "redact", "high": "block"},
        "model_allow": [],
        "model_deny": [],
        "store_request_excerpts": False,
        "max_request_chars": 100_000,
        "scan_injection": True,
    },
    "secrets-only": {
        "description": "Just block credentials and API keys; useful for dev tools.",
        "categories": ["secret", "injection", "exfiltration"],
        "actions": {"low": "allow", "medium": "block", "high": "block"},
        "model_allow": [],
        "model_deny": [],
        "store_request_excerpts": True,
        "max_request_chars": 500_000,
        "scan_injection": True,
    },
    "agent-safety": {
        "description": "For autonomous agents (OpenCLaw / OpenDevin / etc.) — strict on injection, exfiltration, and untrusted scraped content.",
        "categories": ["secret", "injection", "exfiltration", "pii"],
        "actions": {"low": "redact", "medium": "block", "high": "block"},
        "model_allow": [],
        "model_deny": [],
        "store_request_excerpts": True,
        "max_request_chars": 300_000,
        "scan_injection": True,
    },
}


def build_default_spec(profile_names: list[str]) -> dict[str, Any]:
    """Merge several profiles into one effective ``PolicySpec`` dict.

    Merge rules:
    - Categories: union.
    - Actions per severity: take the *strictest* (block > redact > allow).
    - Model allow: intersection if multiple non-empty lists; else union.
    - Model deny: union.
    - store_request_excerpts: AND (any profile that forbids it wins).
    - max_request_chars: min.
    """
    if not profile_names:
        profile_names = ["baseline"]

    profiles = [COMPLIANCE_PROFILES[name] for name in profile_names if name in COMPLIANCE_PROFILES]
    if not profiles:
        profiles = [COMPLIANCE_PROFILES["baseline"]]

    strictness = {"allow": 0, "redact": 1, "block": 2}
    inv_strict = {v: k for k, v in strictness.items()}

    categories: set[str] = set()
    actions: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    deny: set[str] = set()
    allow_lists: list[list[str]] = []
    store_excerpts = True
    max_chars = 10**9
    scan_injection = False

    for p in profiles:
        categories.update(p["categories"])
        for sev, act in p["actions"].items():
            actions[sev] = max(actions[sev], strictness[act])
        deny.update(p["model_deny"])
        if p["model_allow"]:
            allow_lists.append(list(p["model_allow"]))
        store_excerpts = store_excerpts and p["store_request_excerpts"]
        max_chars = min(max_chars, p["max_request_chars"])
        scan_injection = scan_injection or bool(p.get("scan_injection", True))

    if allow_lists:
        allow_set = set(allow_lists[0])
        for lst in allow_lists[1:]:
            allow_set &= set(lst)
        allow_final = sorted(allow_set)
    else:
        allow_final = []

    return {
        "profiles": profile_names,
        "categories": sorted(categories),
        "actions": {sev: inv_strict[score] for sev, score in actions.items()},
        "model_allow": allow_final,
        "model_deny": sorted(deny),
        "store_request_excerpts": store_excerpts,
        "max_request_chars": max_chars,
        "redact_response": True,
        "scan_injection": scan_injection,
        "budgets": None,
        "loop_threshold": 8,
        "loop_window_seconds": 120,
    }
