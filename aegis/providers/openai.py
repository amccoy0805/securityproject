"""OpenAI / OpenAI-compatible adapter (covers OpenAI, Azure OpenAI, vLLM, Ollama in OpenAI mode)."""

from __future__ import annotations

from typing import Any

import httpx

from .base import ProviderAdapter, ProviderError, ProviderResponse


def _join_messages(messages: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if isinstance(content, list):
            chunks: list[str] = []
            for c in content:
                if isinstance(c, dict):
                    chunks.append(c.get("text", ""))
                else:
                    chunks.append(str(c))
            content = "\n".join(chunks)
        parts.append(f"<<{role}>>\n{content}")
    return "\n\n".join(parts)


def _split_messages(text: str, original: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map redacted joined text back onto message bodies.

    We split on the same ``<<role>>\\n`` markers we used in ``_join_messages``.
    If anything looks off, we fall back to placing the entire text into the
    last user message (safer than dropping content).
    """
    sentinel = "<<"
    blocks = text.split("\n\n")
    if len(blocks) == len(original):
        rebuilt: list[dict[str, Any]] = []
        for blk, msg in zip(blocks, original, strict=False):
            new = dict(msg)
            if blk.startswith(sentinel):
                _, _, body = blk.partition("\n")
                new["content"] = body
            else:
                new["content"] = blk
            rebuilt.append(new)
        return rebuilt
    rebuilt = [dict(m) for m in original]
    for i in range(len(rebuilt) - 1, -1, -1):
        if rebuilt[i].get("role") == "user":
            rebuilt[i]["content"] = text
            break
    return rebuilt


class OpenAIAdapter(ProviderAdapter):
    name = "openai"
    supports_streaming = True

    def extract_text(self, body: dict[str, Any]) -> str:
        if "messages" in body and isinstance(body["messages"], list):
            return _join_messages(body["messages"])
        if "input" in body:
            v = body["input"]
            return v if isinstance(v, str) else str(v)
        if "prompt" in body:
            v = body["prompt"]
            return v if isinstance(v, str) else str(v)
        return ""

    def rewrite_text(self, body: dict[str, Any], sanitized: str) -> dict[str, Any]:
        new = dict(body)
        if "messages" in new and isinstance(new["messages"], list):
            new["messages"] = _split_messages(sanitized, new["messages"])
        elif "input" in new:
            new["input"] = sanitized
        elif "prompt" in new:
            new["prompt"] = sanitized
        return new

    def extract_model(self, body: dict[str, Any]) -> str | None:
        v = body.get("model")
        return str(v) if v else None

    def extract_output_text(self, body: dict[str, Any]) -> str:
        choices = body.get("choices") or []
        out: list[str] = []
        for c in choices:
            msg = c.get("message") or {}
            content = msg.get("content")
            if isinstance(content, str):
                out.append(content)
            elif isinstance(content, list):
                for piece in content:
                    if isinstance(piece, dict) and "text" in piece:
                        out.append(piece["text"])
        if out:
            return "\n".join(out)
        if "output_text" in body:
            return str(body["output_text"])
        return ""

    def rewrite_output_text(self, body: dict[str, Any], sanitized: str) -> dict[str, Any]:
        new = dict(body)
        choices = list(new.get("choices") or [])
        if choices:
            first = dict(choices[0])
            msg = dict(first.get("message") or {})
            msg["content"] = sanitized
            first["message"] = msg
            choices[0] = first
            new["choices"] = choices
        elif "output_text" in new:
            new["output_text"] = sanitized
        return new

    async def forward(self, path: str, body: dict[str, Any], extra_headers: dict[str, str]) -> ProviderResponse:
        if not self.api_key:
            raise ProviderError("OpenAI API key is not configured for this tenant.", status_code=412)
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        for k, v in extra_headers.items():
            if k.lower() in {"openai-organization", "openai-project"}:
                headers[k] = v
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as client:
                resp = await client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise ProviderError(f"Upstream connection failed: {exc!s}") from exc

        try:
            data = resp.json()
        except ValueError:
            data = {"error": {"message": resp.text or "Upstream returned non-JSON response."}}
        return ProviderResponse(status_code=resp.status_code, body=data, headers=dict(resp.headers))

    async def forward_stream(self, path: str, body: dict[str, Any], extra_headers: dict[str, str]):
        if not self.api_key:
            raise ProviderError("OpenAI API key is not configured for this tenant.", status_code=412)
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }
        for k, v in extra_headers.items():
            if k.lower() in {"openai-organization", "openai-project"}:
                headers[k] = v
        client = httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0))
        try:
            async with client.stream("POST", url, json=body, headers=headers) as resp:
                if resp.status_code >= 400:
                    raw = await resp.aread()
                    raise ProviderError(
                        f"Upstream returned HTTP {resp.status_code}",
                        status_code=resp.status_code,
                        payload={"error": {"message": raw.decode("utf-8", "replace")}},
                    )
                async for chunk in resp.aiter_bytes():
                    if chunk:
                        yield chunk
        finally:
            await client.aclose()
