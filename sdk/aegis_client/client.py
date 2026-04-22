"""Tiny synchronous SDK for Aegis."""

from __future__ import annotations

from typing import Any

import httpx


class AegisError(Exception):
    def __init__(self, message: str, *, status_code: int | None = None, payload: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class AegisClient:
    def __init__(self, base_url: str, api_key: str, *, timeout: float = 60.0):
        if not api_key.startswith("aeg_"):
            raise ValueError("Aegis API keys start with 'aeg_'.")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            headers={"Authorization": f"Bearer {api_key}"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> AegisClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        untrusted: bool = False,
        override_budget: bool = False,
        override_loop: bool = False,
        approve_action: bool = False,
        override_ip: bool = False,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if untrusted:
            headers["X-Aegis-Untrusted"] = "1"
        if override_budget:
            headers["X-Aegis-Override-Budget"] = "1"
        if override_loop:
            headers["X-Aegis-Override-Loop"] = "1"
        if approve_action:
            headers["X-Aegis-Approve-Action"] = "1"
        if override_ip:
            headers["X-Aegis-Override-IP"] = "1"
        resp = self._client.post(path, json=body, headers=headers or None)
        try:
            data = resp.json()
        except ValueError:
            data = {"error": {"message": resp.text}}
        if resp.status_code >= 400:
            raise AegisError(
                f"Aegis call to {path} failed ({resp.status_code})",
                status_code=resp.status_code,
                payload=data,
            )
        return data

    def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        *,
        untrusted: bool = False,
        override_budget: bool = False,
        override_loop: bool = False,
        approve_action: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        body = {"model": model, "messages": messages, **kwargs}
        return self._post(
            "/v1/chat/completions",
            body,
            untrusted=untrusted,
            override_budget=override_budget,
            override_loop=override_loop,
            approve_action=approve_action,
        )

    def messages(
        self,
        model: str,
        messages: list[dict[str, Any]],
        *,
        untrusted: bool = False,
        override_budget: bool = False,
        override_loop: bool = False,
        approve_action: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        body = {"model": model, "messages": messages, **kwargs}
        return self._post(
            "/v1/messages",
            body,
            untrusted=untrusted,
            override_budget=override_budget,
            override_loop=override_loop,
            approve_action=approve_action,
        )

    def check(
        self,
        text: str,
        *,
        model: str | None = None,
        scan_response: bool = False,
        untrusted: bool = False,
    ) -> dict[str, Any]:
        return self._post(
            "/v1/policy/check",
            {"text": text, "model": model, "scan_response": scan_response, "untrusted": untrusted},
        )

    @staticmethod
    def wrap_untrusted(text: str) -> str:
        """Mark a chunk of text as untrusted (scraped page, retrieved doc, tool output).

        The gateway elevates injection findings inside these blocks to HIGH
        severity so they get blocked under the standard ``baseline`` profile.
        """
        return f"<aegis:untrusted>\n{text}\n</aegis:untrusted>"

    def my_policy(self) -> dict[str, Any]:
        resp = self._client.get("/v1/policy/me")
        resp.raise_for_status()
        return resp.json()
