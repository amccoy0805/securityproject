"""Network identity helpers for API key authentication.

- ``client_ip`` extracts the client's apparent IP from common proxy headers.
- ``ip_allowed`` evaluates a comma-separated list of CIDRs / single IPs.
- ``compare_ips`` supports the "first-seen-IP pinning" feature: once an API
  key has been used, future requests must come from the same /24 (IPv4) or
  /48 (IPv6) unless the admin clears the pin.
"""

from __future__ import annotations

import ipaddress
from typing import Any


def client_ip(request: Any) -> str:
    """Extract the apparent client IP from a Starlette/FastAPI request."""
    headers = getattr(request, "headers", {}) or {}
    for h in ("x-forwarded-for", "x-real-ip"):
        v = headers.get(h)
        if v:
            return v.split(",")[0].strip()
    client = getattr(request, "client", None)
    return getattr(client, "host", "") or "0.0.0.0"


def _entries(value: str) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def ip_allowed(presented: str, allowed: str) -> bool:
    if not allowed.strip():
        return True
    if not presented:
        return False
    try:
        ip = ipaddress.ip_address(presented)
    except ValueError:
        return False
    for entry in _entries(allowed):
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


def same_network(a: str, b: str) -> bool:
    """Return True if a and b are in the same /24 (IPv4) or /48 (IPv6)."""
    if not a or not b:
        return False
    try:
        ia = ipaddress.ip_address(a)
        ib = ipaddress.ip_address(b)
    except ValueError:
        return a == b
    if ia.version != ib.version:
        return False
    prefix = 24 if ia.version == 4 else 48
    return ipaddress.ip_network(f"{a}/{prefix}", strict=False).network_address == \
        ipaddress.ip_network(f"{b}/{prefix}", strict=False).network_address
