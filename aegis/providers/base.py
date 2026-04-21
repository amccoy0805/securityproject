"""Provider adapter contract.

Each adapter knows how to:
- extract the *plain text* from the canonical request body (so the policy
  engine can scan it),
- rewrite the body with redacted text,
- forward the call to the upstream API,
- normalise the response so the proxy can scan/redact assistant output.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class ProviderError(Exception):
    def __init__(self, message: str, *, status_code: int = 502, payload: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload or {"error": {"message": message, "type": "upstream_error"}}


@dataclass
class ProviderResponse:
    status_code: int
    body: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)


class ProviderAdapter(ABC):
    name: str = "abstract"

    def __init__(self, api_key: str | None, base_url: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    # -- request introspection / rewriting -------------------------------------

    @abstractmethod
    def extract_text(self, body: dict[str, Any]) -> str: ...

    @abstractmethod
    def rewrite_text(self, body: dict[str, Any], sanitized: str) -> dict[str, Any]: ...

    @abstractmethod
    def extract_model(self, body: dict[str, Any]) -> str | None: ...

    # -- response handling -----------------------------------------------------

    @abstractmethod
    def extract_output_text(self, body: dict[str, Any]) -> str: ...

    @abstractmethod
    def rewrite_output_text(self, body: dict[str, Any], sanitized: str) -> dict[str, Any]: ...

    # -- transport -------------------------------------------------------------

    @abstractmethod
    async def forward(self, path: str, body: dict[str, Any], extra_headers: dict[str, str]) -> ProviderResponse: ...
