"""Crypto helpers: password hashing and API key generation/verification.

API keys have the shape ``aeg_<env>_<prefix>.<secret>`` where:
- ``prefix`` (8 chars) is stored in plain text so admins can identify keys.
- ``secret`` is hashed with bcrypt and only ever stored as a hash.

This means a leaked DB cannot be used to call the gateway; an attacker would
need both the DB row and the original secret half.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass

from passlib.context import CryptContext

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

API_KEY_PREFIX_LEN = 8
API_KEY_SECRET_BYTES = 32


@dataclass
class GeneratedApiKey:
    full: str
    prefix: str
    secret_hash: str


def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd_ctx.verify(plain, hashed)
    except Exception:
        return False


def generate_api_key(env: str = "live") -> GeneratedApiKey:
    prefix = secrets.token_hex(API_KEY_PREFIX_LEN // 2)  # 8 hex chars
    secret = secrets.token_urlsafe(API_KEY_SECRET_BYTES)
    full = f"aeg_{env}_{prefix}.{secret}"
    return GeneratedApiKey(full=full, prefix=prefix, secret_hash=_pwd_ctx.hash(secret))


def split_api_key(full: str) -> tuple[str, str] | None:
    """Return ``(prefix, secret)`` from a presented API key, or None if malformed."""
    if not full or not full.startswith("aeg_"):
        return None
    try:
        body = full.split("_", 2)[2]  # drop ``aeg_<env>_``
        prefix, secret = body.split(".", 1)
    except ValueError:
        return None
    if not prefix or not secret:
        return None
    return prefix, secret


def verify_api_secret(secret: str, secret_hash: str) -> bool:
    try:
        return _pwd_ctx.verify(secret, secret_hash)
    except Exception:
        return False


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
