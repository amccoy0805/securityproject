"""URL safety inspection for tool/function-call arguments.

Tools that take URLs (``browse``, ``http_request``, etc.) are a primary
exfiltration vector for prompt-injection attacks: the model can be tricked
into fetching ``https://attacker/?leak=secrets``. We protect three things:

1. **SSRF**: refuse loopback (``127.0.0.0/8``, ``::1``), link-local,
   metadata service (``169.254.169.254``), and RFC1918 private ranges by
   default. A tenant can opt in to private targets per-tool.
2. **Domain allow/deny lists**: a per-tool allowlist (most restrictive) and
   tenant-wide denylist.
3. **Suspicious patterns**: URL shorteners and raw IPs in non-HTTP-localhost
   contexts produce a ``low``-severity warning that the audit log captures.

The function returns a verdict the proxy can act on, plus a list of
findings the audit log should keep.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

_PRIVATE_HOST_RE = re.compile(
    r"(?i)^("
    r"localhost|"
    r"localdomain|"
    r"metadata\.google\.internal"
    r")$"
)
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "s.id", "lnkd.in", "trib.al",
    "rb.gy",
}
_SAFE_SCHEMES = {"http", "https"}


@dataclass
class UrlFinding:
    url: str
    reason: str
    severity: str  # "low" | "medium" | "high"

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "reason": self.reason, "severity": self.severity}


@dataclass
class UrlVerdict:
    allowed: bool
    findings: list[UrlFinding] = field(default_factory=list)
    blocked_reason: str | None = None


def _ip_is_safe(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> tuple[bool, str | None]:
    if ip.is_loopback:
        return False, "loopback address"
    if ip.is_link_local:
        return False, "link-local address"
    if ip.is_multicast:
        return False, "multicast address"
    if ip.is_unspecified:
        return False, "unspecified address"
    if ip.is_reserved:
        return False, "reserved address"
    # Cloud metadata service — block even if allow_private is on.
    if str(ip) == "169.254.169.254":
        return False, "cloud metadata service"
    if ip.is_private and not allow_private:
        return False, "private/RFC1918 address"
    return True, None


def _strip_label(label: str) -> str:
    """Normalise a single host label for lookalike comparison."""
    label = label.lower()
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    confusables = str.maketrans({
        "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
        "à": "a", "á": "a", "â": "a", "ä": "a", "ã": "a", "å": "a",
        "è": "e", "é": "e", "ê": "e", "ë": "e",
        "ì": "i", "í": "i", "î": "i", "ï": "i",
        "ò": "o", "ó": "o", "ô": "o", "ö": "o", "õ": "o",
        "ù": "u", "ú": "u", "û": "u", "ü": "u",
        "ñ": "n", "ç": "c",
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    })
    return label.translate(confusables)


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_lookalike(host: str, protected: str) -> bool:
    """Return True if ``host`` looks like an attempt to spoof ``protected``.

    Two cases count as lookalike:

    1. Raw labels differ but normalised (homoglyph-folded, IDN-decoded)
       labels collide — the canonical spoof.
    2. Raw labels are within Levenshtein distance ≤ 2 (or ≤ 3 for longer
       brands) but are not legitimate sub/parent domains.
    """
    raw_host = _registrable(host.lower())
    raw_prot = _registrable(protected.lower())
    if not raw_host or not raw_prot or raw_host == raw_prot:
        return False
    if raw_host.endswith("." + raw_prot) or raw_prot.endswith("." + raw_host):
        return False
    a = _strip_label(raw_host)
    b = _strip_label(raw_prot)
    if a == b:
        return True
    dist = _levenshtein(a, b)
    threshold = 2 if len(b) <= 8 else 3
    return 0 < dist <= threshold


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def inspect_url(
    url: str,
    *,
    allow_domains: list[str] | None = None,
    deny_domains: list[str] | None = None,
    allow_private: bool = False,
    protected_domains: list[str] | None = None,
) -> UrlVerdict:
    if not url or not isinstance(url, str):
        return UrlVerdict(allowed=True)
    parsed = urlsplit(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme in {"javascript", "data", "file", "vbscript"}:
        return UrlVerdict(
            allowed=False,
            blocked_reason=f"disallowed scheme: {scheme or 'empty'}",
            findings=[UrlFinding(url=url, reason=f"scheme {scheme}", severity="high")],
        )
    if scheme not in _SAFE_SCHEMES:
        # ftp, gopher, etc. — uncommon and high-risk for SSRF; default-deny.
        return UrlVerdict(
            allowed=False,
            blocked_reason=f"disallowed scheme: {scheme or 'empty'}",
            findings=[UrlFinding(url=url, reason=f"scheme {scheme}", severity="medium")],
        )

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return UrlVerdict(
            allowed=False,
            blocked_reason="missing host",
            findings=[UrlFinding(url=url, reason="missing host", severity="medium")],
        )

    findings: list[UrlFinding] = []

    if _PRIVATE_HOST_RE.match(host):
        return UrlVerdict(
            allowed=False,
            blocked_reason=f"loopback hostname '{host}'",
            findings=[UrlFinding(url=url, reason="loopback hostname", severity="high")],
        )

    try:
        ip = ipaddress.ip_address(host)
        ok, why = _ip_is_safe(ip, allow_private=allow_private)
        if not ok:
            return UrlVerdict(
                allowed=False,
                blocked_reason=why or "unsafe IP",
                findings=[UrlFinding(url=url, reason=why or "unsafe IP", severity="high")],
            )
        findings.append(UrlFinding(url=url, reason="raw IP literal target", severity="low"))
    except ValueError:
        pass  # not an IP literal — that's fine

    deny_set = {d.lower().lstrip(".") for d in (deny_domains or [])}
    for d in deny_set:
        if host == d or host.endswith("." + d):
            return UrlVerdict(
                allowed=False,
                blocked_reason=f"domain '{host}' matches tenant denylist",
                findings=[UrlFinding(url=url, reason=f"deny '{d}'", severity="high")],
            )

    allow_set = {d.lower().lstrip(".") for d in (allow_domains or [])}
    if allow_set:
        ok = any(host == d or host.endswith("." + d) for d in allow_set)
        if not ok:
            return UrlVerdict(
                allowed=False,
                blocked_reason=(
                    f"domain '{host}' is not on the tool's allowlist "
                    f"({sorted(allow_set)})"
                ),
                findings=[UrlFinding(url=url, reason="allowlist miss", severity="medium")],
            )

    if host in _SHORTENERS:
        findings.append(UrlFinding(url=url, reason=f"URL shortener '{host}'", severity="low"))

    for prot in (protected_domains or []):
        if is_lookalike(host, prot):
            return UrlVerdict(
                allowed=False,
                blocked_reason=(
                    f"host '{host}' looks like a spoof of protected brand "
                    f"'{prot}' (homoglyph / typo lookalike)"
                ),
                findings=[
                    UrlFinding(
                        url=url,
                        reason=f"lookalike of protected '{prot}'",
                        severity="high",
                    )
                ],
            )

    return UrlVerdict(allowed=True, findings=findings)


_URL_IN_TEXT = re.compile(r"https?://[^\s'\"<>)\]]+", re.IGNORECASE)


def extract_urls(value: Any) -> list[str]:
    """Recursively pull URL-shaped strings out of an arbitrary tool-args value."""
    out: list[str] = []
    if isinstance(value, str):
        out.extend(_URL_IN_TEXT.findall(value))
    elif isinstance(value, dict):
        for v in value.values():
            out.extend(extract_urls(v))
    elif isinstance(value, list | tuple):
        for v in value:
            out.extend(extract_urls(v))
    return out
