"""Sensitive-data detectors.

These are intentionally implemented as transparent regex/lexical detectors so
operators can audit and extend them. In production you can swap-in ML-based
detectors (Presidio, internal models) by registering additional ``Detector``
instances in ``DEFAULT_DETECTORS``.

Each detector returns ``Finding`` objects with the matched span so the redactor
can rewrite the text deterministically and the audit log can record what kind
of data was seen (without storing the raw value).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3}[self.value]


@dataclass
class Finding:
    detector: str
    category: str
    severity: Severity
    start: int
    end: int
    excerpt: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "category": self.category,
            "severity": self.severity.value,
            "start": self.start,
            "end": self.end,
            "tags": list(self.tags),
        }


@dataclass
class Detector:
    name: str
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    tags: list[str] = field(default_factory=list)
    validator: callable | None = None  # type: ignore[type-arg]

    def find(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if self.validator and not self.validator(value):
                continue
            out.append(
                Finding(
                    detector=self.name,
                    category=self.category,
                    severity=self.severity,
                    start=m.start(),
                    end=m.end(),
                    excerpt=_mask_value(value),
                    tags=list(self.tags),
                )
            )
        return out


# --- validators -----------------------------------------------------------------

def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 12 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _ssn_ok(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False
    if digits in {"000000000", "111111111", "123456789"}:
        return False
    if digits.startswith("000") or digits[3:5] == "00" or digits.endswith("0000"):
        return False
    return True


# --- detectors ------------------------------------------------------------------

DEFAULT_DETECTORS: list[Detector] = [
    Detector(
        name="email",
        category="pii",
        severity=Severity.LOW,
        pattern=re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
        tags=["pii", "gdpr"],
    ),
    Detector(
        name="phone_us",
        category="pii",
        severity=Severity.LOW,
        pattern=re.compile(
            r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"
        ),
        tags=["pii"],
    ),
    Detector(
        name="ipv4",
        category="network",
        severity=Severity.LOW,
        pattern=re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"),
        tags=["network"],
    ),
    Detector(
        name="ssn_us",
        category="pii",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        validator=_ssn_ok,
        tags=["pii", "hipaa", "us"],
    ),
    Detector(
        name="credit_card",
        category="pci",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(?:\d[ -]?){12,19}\b"),
        validator=_luhn_ok,
        tags=["pci", "financial"],
    ),
    Detector(
        name="iban",
        category="financial",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
        tags=["financial", "gdpr"],
    ),
    Detector(
        name="aws_access_key",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        tags=["secret", "cloud"],
    ),
    Detector(
        name="aws_secret_key",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
        tags=["secret", "cloud"],
        validator=lambda v: any(c.isdigit() for c in v) and any(c.isalpha() for c in v),
    ),
    Detector(
        name="github_token",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        tags=["secret"],
    ),
    Detector(
        name="openai_key",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        tags=["secret"],
    ),
    Detector(
        name="slack_token",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        tags=["secret"],
    ),
    Detector(
        name="private_key_block",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        tags=["secret"],
    ),
    Detector(
        name="jwt",
        category="secret",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        tags=["secret", "auth"],
    ),
    Detector(
        name="medical_record_number",
        category="phi",
        severity=Severity.HIGH,
        pattern=re.compile(r"\bMRN[:#\s-]*\d{5,12}\b", re.IGNORECASE),
        tags=["phi", "hipaa"],
    ),
    Detector(
        name="date_of_birth",
        category="pii",
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"\b(?:DOB|date of birth)[:\s-]*"
            r"\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b",
            re.IGNORECASE,
        ),
        tags=["pii", "hipaa"],
    ),
]


def _mask_value(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def scan_text(
    text: str,
    *,
    detectors: Iterable[Detector] | None = None,
    enabled_categories: Iterable[str] | None = None,
) -> list[Finding]:
    if not text:
        return []
    detectors = detectors or DEFAULT_DETECTORS
    enabled = set(enabled_categories) if enabled_categories else None
    findings: list[Finding] = []
    for det in detectors:
        if enabled and det.category not in enabled:
            continue
        findings.extend(det.find(text))
    findings.sort(key=lambda f: (f.start, -f.end))
    return _dedupe_overlaps(findings)


def _dedupe_overlaps(findings: list[Finding]) -> list[Finding]:
    """Drop lower-severity findings fully contained in a higher-severity one."""
    keep: list[Finding] = []
    for f in findings:
        clobber = False
        for existing in keep:
            if f.start >= existing.start and f.end <= existing.end:
                if f.severity.rank <= existing.severity.rank:
                    clobber = True
                    break
        if not clobber:
            keep.append(f)
    return keep


def redact_text(text: str, findings: list[Finding]) -> str:
    if not findings:
        return text
    out_parts: list[str] = []
    cursor = 0
    for f in sorted(findings, key=lambda x: x.start):
        if f.start < cursor:
            continue
        out_parts.append(text[cursor : f.start])
        token = f"[REDACTED:{f.category.upper()}]"
        out_parts.append(token)
        cursor = f.end
    out_parts.append(text[cursor:])
    return "".join(out_parts)
