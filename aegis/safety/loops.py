"""Runaway-loop detection.

Flags an API key that sends the *same* (or near-same) request many times in a
small window. This is a common failure mode for buggy agent loops — the bot
keeps re-prompting the model with effectively identical context until either
the customer's wallet or the upstream rate limiter intervenes. Aegis
intervenes first.

Detection is a stable hash of the joined input text plus model name; we keep
the most recent N hashes per (tenant, api_key) and trigger when one hash
appears more than ``threshold`` times within ``window``.
"""

from __future__ import annotations

import hashlib
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class LoopVerdict:
    looping: bool
    repeat_count: int
    digest: str
    reason: str | None


class LoopDetector:
    def __init__(self, *, window: timedelta = timedelta(minutes=2), threshold: int = 8, capacity: int = 256):
        self._window = window
        self._threshold = threshold
        self._capacity = capacity
        self._buckets: dict[tuple[str, str], deque[tuple[datetime, str]]] = defaultdict(
            lambda: deque(maxlen=self._capacity)
        )
        self._lock = threading.Lock()

    @staticmethod
    def _digest(model: str | None, text: str) -> str:
        h = hashlib.sha256()
        h.update(((model or "_") + "\x00").encode("utf-8"))
        # Normalise whitespace so trivial newline differences still cluster.
        h.update(" ".join(text.split()).encode("utf-8", errors="ignore"))
        return h.hexdigest()

    def observe(self, *, tenant_id: str, api_key_id: str, model: str | None, text: str) -> LoopVerdict:
        digest = self._digest(model, text)
        now = datetime.utcnow()
        cutoff = now - self._window
        with self._lock:
            bucket = self._buckets[(tenant_id, api_key_id)]
            bucket.append((now, digest))
            while bucket and bucket[0][0] < cutoff:
                bucket.popleft()
            count = sum(1 for _, d in bucket if d == digest)
        if count >= self._threshold:
            return LoopVerdict(
                looping=True,
                repeat_count=count,
                digest=digest[:12],
                reason=(
                    f"This API key has sent the same request {count} times in the last "
                    f"{int(self._window.total_seconds())}s — possible runaway loop."
                ),
            )
        return LoopVerdict(looping=False, repeat_count=count, digest=digest[:12], reason=None)


detector = LoopDetector()
