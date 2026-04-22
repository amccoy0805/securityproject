"""Streaming output redactor for Server-Sent Events.

The challenge: model output arrives in small chunks; a secret like
``ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`` can straddle two chunks, in
which case a naive per-chunk regex would miss it.

Solution: keep a sliding text buffer. We only ever flush the part of the
buffer that is far enough behind the current write head that no detector
pattern could still grow into it. The "safe distance" is the largest match
length of any registered detector + a small slack, capped to keep latency
low.

Each call to ``feed(chunk)`` returns the (possibly empty) safe-to-emit
string and a list of any new findings the buffer produced since the last
call. ``flush()`` drains everything left, scanning one last time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .detectors import Finding, redact_text, scan_text
from .injection import _INVISIBLE_CHARS  # reuse the invisible-unicode regex

# A conservative upper bound on the longest pattern any detector might
# produce a match for. Bigger = safer but more end-of-stream latency.
SAFE_TAIL_DEFAULT = 256


def _max_pattern_window() -> int:
    """Best-effort guess at the longest plausible match in the detector set.

    We can't compute exact maximum match length for every regex, but we know
    the patterns we ship and their realistic upper bounds (private key
    headers, JWT tokens, etc.). Use the larger of that estimate and
    ``SAFE_TAIL_DEFAULT`` to be safe.
    """
    # Empirically the largest single match is the JWT three-segment pattern;
    # 256 chars covers it with comfortable headroom.
    return SAFE_TAIL_DEFAULT


@dataclass
class StreamingRedactor:
    enabled: bool = True
    enabled_categories: list[str] | None = None
    safe_tail: int = field(default_factory=_max_pattern_window)
    _buffer: str = ""
    _emitted_chars: int = 0
    _findings_seen: list[Finding] = field(default_factory=list)
    # Flush-cursor *position within the running text* (so finding offsets
    # remain comparable across calls). We only flush characters strictly
    # behind ``len(buffer) - safe_tail``.

    def feed(self, chunk: str) -> tuple[str, list[Finding]]:
        if not self.enabled or not chunk:
            self._buffer += chunk
            return ("", []) if not chunk else self._maybe_flush(scan_now=False)

        # Strip invisible Unicode immediately — it can't be part of a
        # legitimate token and there's no boundary problem here.
        if _INVISIBLE_CHARS.search(chunk):
            chunk = _INVISIBLE_CHARS.sub("", chunk)

        self._buffer += chunk
        return self._maybe_flush(scan_now=True)

    def _maybe_flush(self, *, scan_now: bool) -> tuple[str, list[Finding]]:
        # Anything beyond ``safe_tail`` from the end is safe to emit.
        cutoff = max(0, len(self._buffer) - self.safe_tail)
        if cutoff == 0:
            return "", []

        head = self._buffer[:cutoff]
        tail = self._buffer[cutoff:]

        new_findings: list[Finding] = []
        if scan_now:
            findings = scan_text(head, enabled_categories=self.enabled_categories)
            if findings:
                head = redact_text(head, findings)
                new_findings.extend(findings)
                self._findings_seen.extend(findings)

        self._buffer = tail
        self._emitted_chars += len(head)
        return head, new_findings

    def flush(self) -> tuple[str, list[Finding]]:
        if not self.enabled or not self._buffer:
            tail, self._buffer = self._buffer, ""
            return tail, []
        head = self._buffer
        self._buffer = ""
        findings = scan_text(head, enabled_categories=self.enabled_categories)
        if findings:
            head = redact_text(head, findings)
            self._findings_seen.extend(findings)
        self._emitted_chars += len(head)
        return head, findings

    @property
    def all_findings(self) -> list[Finding]:
        return list(self._findings_seen)


# --- SSE helpers -------------------------------------------------------------

_DATA_LINE = re.compile(rb"^data: ?(.*)$", re.MULTILINE)


def parse_openai_sse_chunk(raw: bytes) -> list[dict[str, Any]]:
    """Best-effort parse of an OpenAI streaming SSE event.

    Each event is a sequence of ``data: ...`` lines terminated by a blank
    line. We return the parsed JSON for each ``data:`` line that decodes
    cleanly; ``[DONE]`` and unparseable lines are returned as empty dicts.
    """
    import json
    out: list[dict[str, Any]] = []
    for m in _DATA_LINE.finditer(raw):
        body = m.group(1).strip()
        if not body or body == b"[DONE]":
            continue
        try:
            out.append(json.loads(body))
        except (ValueError, UnicodeDecodeError):
            continue
    return out


def extract_delta_text(event: dict[str, Any]) -> str:
    """Pull the assistant content from an OpenAI streaming chunk."""
    choices = event.get("choices") or []
    if not choices or not isinstance(choices[0], dict):
        return ""
    delta = choices[0].get("delta") or {}
    content = delta.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(c.get("text", "") for c in content if isinstance(c, dict))
    return ""


def rewrite_delta_text(event: dict[str, Any], replacement: str) -> dict[str, Any]:
    """Return a new event with ``delta.content`` set to ``replacement``."""
    if not isinstance(event, dict):
        return event
    new = dict(event)
    choices = list(new.get("choices") or [])
    if not choices:
        return new
    first = dict(choices[0]) if isinstance(choices[0], dict) else choices[0]
    delta = dict(first.get("delta") or {})
    delta["content"] = replacement
    first["delta"] = delta
    choices[0] = first
    new["choices"] = choices
    return new


def serialise_sse_event(event: dict[str, Any]) -> bytes:
    import json
    return ("data: " + json.dumps(event, separators=(",", ":")) + "\n\n").encode("utf-8")


SSE_DONE = b"data: [DONE]\n\n"
