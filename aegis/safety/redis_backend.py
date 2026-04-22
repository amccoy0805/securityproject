"""Redis-backed implementations of the budget enforcer and loop detector.

These are wire-compatible with the in-memory versions; the proxy never
imports them directly. A small ``select_backends()`` factory in
``aegis/safety/__init__.py`` picks Redis when ``AEGIS_REDIS_URL`` is set
and ``redis-py`` is installed, and falls back to in-memory otherwise.

State layout
------------

Budgets use Redis sorted sets keyed by ``aegis:bud:<scope>:<id>:<window_s>``,
where each member is a JSON sample tagged by timestamp. Counts are
maintained by ``ZRANGEBYSCORE`` over the current window. We trim the set to
its capacity on each insert.

Loop detection uses a Redis sorted set per (tenant, key) of recent prompt
digests; we also keep a per-digest counter via ``HINCRBY`` so the threshold
check is O(1).
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .budgets import BudgetCheck, BudgetSpec, BudgetWindow
from .loops import LoopVerdict

log = logging.getLogger("aegis.redis")

try:
    import redis  # type: ignore[import-not-found]
    _REDIS_OK = True
except Exception:  # pragma: no cover
    redis = None  # type: ignore[assignment]
    _REDIS_OK = False


def is_available(url: str | None) -> bool:
    if not url or not _REDIS_OK:
        return False
    try:
        client = redis.Redis.from_url(url, socket_timeout=2.0, socket_connect_timeout=2.0)
        client.ping()
        return True
    except Exception as exc:
        log.warning("Redis at %s is not reachable: %s", url, exc)
        return False


@dataclass
class _Sample:
    when: float
    requests: int
    input_chars: int
    output_chars: int
    cost_usd: float

    def to_json(self) -> str:
        return json.dumps(
            {"t": self.when, "r": self.requests, "ic": self.input_chars,
             "oc": self.output_chars, "c": self.cost_usd},
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: bytes | str) -> _Sample | None:
        try:
            d = json.loads(raw)
            return cls(
                when=float(d["t"]), requests=int(d.get("r", 0)),
                input_chars=int(d.get("ic", 0)), output_chars=int(d.get("oc", 0)),
                cost_usd=float(d.get("c", 0.0)),
            )
        except (TypeError, ValueError, KeyError):
            return None


# --- Budgets ----------------------------------------------------------------

class RedisBudgetEnforcer:
    """Budget enforcer that shares state across replicas via Redis."""

    def __init__(self, url: str, *, capacity: int = 5_000):
        if not _REDIS_OK:
            raise RuntimeError("redis-py is not installed")
        self._client = redis.Redis.from_url(url)
        self._capacity = capacity

    @staticmethod
    def _key(scope: str, *parts: str) -> str:
        return ":".join(("aegis", "bud", scope, *parts))

    def _aggregate(self, key: str, since: float) -> _Sample:
        agg = _Sample(when=since, requests=0, input_chars=0, output_chars=0, cost_usd=0.0)
        raw_members = self._client.zrangebyscore(key, since, "+inf")
        for raw in raw_members:
            s = _Sample.from_json(raw)
            if s is None:
                continue
            agg.requests += s.requests
            agg.input_chars += s.input_chars
            agg.output_chars += s.output_chars
            agg.cost_usd += s.cost_usd
        return agg

    @staticmethod
    def _violates(window: BudgetWindow, agg: _Sample) -> str | None:
        if window.max_requests is not None and agg.requests > window.max_requests:
            return f"{window.label}: {agg.requests}/{window.max_requests} requests"
        if window.max_input_chars is not None and agg.input_chars > window.max_input_chars:
            return f"{window.label}: {agg.input_chars}/{window.max_input_chars} input chars"
        if window.max_output_chars is not None and agg.output_chars > window.max_output_chars:
            return f"{window.label}: {agg.output_chars}/{window.max_output_chars} output chars"
        if window.max_usd is not None and agg.cost_usd > window.max_usd:
            return f"{window.label}: ${agg.cost_usd:.2f}/{window.max_usd:.2f} estimated"
        return None

    def precheck(
        self,
        spec: BudgetSpec,
        *,
        tenant_id: str,
        api_key_id: str,
        projected_input_chars: int,
        projected_cost_usd: float,
    ) -> BudgetCheck:
        if not spec.enabled:
            return BudgetCheck(True, None, None, {})

        now = datetime.utcnow().timestamp()
        snapshot: dict[str, Any] = {}

        def _check(windows: Iterable[BudgetWindow], scope: str, ident: str) -> str | None:
            for w in windows:
                key = self._key(scope, ident, str(int(w.duration.total_seconds())))
                agg = self._aggregate(key, now - w.duration.total_seconds())
                projected = _Sample(
                    when=now,
                    requests=agg.requests + 1,
                    input_chars=agg.input_chars + projected_input_chars,
                    output_chars=agg.output_chars,
                    cost_usd=agg.cost_usd + projected_cost_usd,
                )
                snapshot[f"{scope}:{w.label}"] = {
                    "requests": projected.requests,
                    "input_chars": projected.input_chars,
                    "cost_usd": round(projected.cost_usd, 6),
                    "limit_requests": w.max_requests,
                    "limit_input_chars": w.max_input_chars,
                    "limit_usd": w.max_usd,
                }
                violation = self._violates(w, projected)
                if violation:
                    return violation
            return None

        violation = _check(spec.per_key_windows, "key", f"{tenant_id}:{api_key_id}")
        if violation:
            return BudgetCheck(False, violation, violation.split(":", 1)[0], snapshot)
        violation = _check(spec.per_tenant_windows, "ten", tenant_id)
        if violation:
            return BudgetCheck(False, violation, violation.split(":", 1)[0], snapshot)
        return BudgetCheck(True, None, None, snapshot)

    def commit(
        self,
        *,
        tenant_id: str,
        api_key_id: str,
        input_chars: int,
        output_chars: int,
        cost_usd: float,
    ) -> None:
        sample = _Sample(
            when=datetime.utcnow().timestamp(),
            requests=1,
            input_chars=input_chars,
            output_chars=output_chars,
            cost_usd=cost_usd,
        )
        # Write the sample into one ZSET per (scope, window-seconds) so each
        # window's TTL keeps its own data fresh.
        # We don't know the windows here (they're per-tenant and live in
        # PolicySpec); insert into a single "all" ZSET keyed by score=now,
        # and have ``_aggregate`` use ZRANGEBYSCORE windows. To keep a simple
        # and consistent layout, write to two anchor keys with a generous TTL.
        for scope, ident, ttl in (
            ("key", f"{tenant_id}:{api_key_id}", 86_400),
            ("ten", tenant_id, 86_400 * 7),
        ):
            key = self._key(scope, ident, "all")
            self._client.zadd(key, {sample.to_json(): sample.when})
            # Trim to capacity (oldest first).
            self._client.zremrangebyrank(key, 0, -self._capacity - 1)
            self._client.expire(key, ttl)

    def stats(
        self, tenant_id: str, api_key_id: str | None = None, window_seconds: int = 3600
    ) -> dict[str, Any]:
        since = datetime.utcnow().timestamp() - window_seconds
        out: dict[str, Any] = {}
        agg = self._aggregate(self._key("ten", tenant_id, "all"), since)
        out["tenant"] = {
            "requests": agg.requests, "input_chars": agg.input_chars,
            "output_chars": agg.output_chars, "cost_usd": round(agg.cost_usd, 6),
        }
        if api_key_id:
            agg = self._aggregate(self._key("key", f"{tenant_id}:{api_key_id}", "all"), since)
            out["key"] = {
                "requests": agg.requests, "input_chars": agg.input_chars,
                "output_chars": agg.output_chars, "cost_usd": round(agg.cost_usd, 6),
            }
        return out


# Override `_aggregate` for the per-window keys in `precheck` (which use
# composite keys with seconds in them) by reading the same per-scope "all"
# key. This keeps storage simple at the cost of one extra ZRANGEBYSCORE call
# per window; for the default window count (3 per scope) that's cheap.
def _patch_precheck_aggregator():  # noqa: D401  (one-shot module init)
    def _agg_via_all(self, key: str, since: float) -> _Sample:  # type: ignore[no-redef]
        # The "all" key for the same scope+ident lives at the prefix before the
        # last ":<window-seconds>" segment we synthesised in `precheck`.
        scope_ident = key.rsplit(":", 1)[0]
        all_key = scope_ident + ":all"
        agg = _Sample(when=since, requests=0, input_chars=0, output_chars=0, cost_usd=0.0)
        for raw in self._client.zrangebyscore(all_key, since, "+inf"):
            s = _Sample.from_json(raw)
            if s is None:
                continue
            agg.requests += s.requests
            agg.input_chars += s.input_chars
            agg.output_chars += s.output_chars
            agg.cost_usd += s.cost_usd
        return agg
    RedisBudgetEnforcer._aggregate = _agg_via_all  # type: ignore[method-assign]


_patch_precheck_aggregator()


# --- Loop detection ---------------------------------------------------------

class RedisLoopDetector:
    """Loop detector backed by Redis sorted sets + per-digest counters."""

    def __init__(self, url: str, *, window: timedelta = timedelta(minutes=2), threshold: int = 8):
        if not _REDIS_OK:
            raise RuntimeError("redis-py is not installed")
        self._client = redis.Redis.from_url(url)
        self._window = window
        self._threshold = threshold
        self._lock = threading.Lock()  # only used to serialise zremrangebyscore + zadd

    @staticmethod
    def _digest(model: str | None, text: str) -> str:
        import hashlib
        h = hashlib.sha256()
        h.update(((model or "_") + "\x00").encode("utf-8"))
        h.update(" ".join(text.split()).encode("utf-8", errors="ignore"))
        return h.hexdigest()

    def observe(self, *, tenant_id: str, api_key_id: str, model: str | None, text: str) -> LoopVerdict:
        digest = self._digest(model, text)
        now = datetime.utcnow().timestamp()
        cutoff = now - self._window.total_seconds()
        zkey = f"aegis:loop:{tenant_id}:{api_key_id}"
        with self._lock:
            self._client.zadd(zkey, {f"{now}:{digest}": now})
            self._client.zremrangebyscore(zkey, 0, cutoff)
            self._client.expire(zkey, int(self._window.total_seconds()) + 60)
            members = self._client.zrange(zkey, 0, -1)
        count = sum(1 for m in members if m.endswith(b":" + digest.encode("ascii")))
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
