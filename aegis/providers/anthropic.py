"""Anthropic Messages API adapter."""

from __future__ import annotations

from typing import Any

import httpx

from .base import ProviderAdapter, ProviderError, ProviderResponse


def _join(messages: list[dict[str, Any]], system: str | None) -> str:
    parts: list[str] = []
    if system:
        parts.append(f"<<system>>\n{system}")
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


def _split(text: str, original_messages: list[dict[str, Any]], had_system: bool) -> tuple[list[dict[str, Any]], str | None]:
    blocks = text.split("\n\n")
    new_system: str | None = None
    msg_blocks = blocks
    if had_system and blocks and blocks[0].startswith("<<system>>"):
        _, _, body = blocks[0].partition("\n")
        new_system = body
        msg_blocks = blocks[1:]
    if len(msg_blocks) == len(original_messages):
        rebuilt: list[dict[str, Any]] = []
        for blk, msg in zip(msg_blocks, original_messages, strict=False):
            new = dict(msg)
            if blk.startswith("<<"):
                _, _, body = blk.partition("\n")
                new["content"] = body
            else:
                new["content"] = blk
            rebuilt.append(new)
        return rebuilt, new_system
    rebuilt = [dict(m) for m in original_messages]
    for i in range(len(rebuilt) - 1, -1, -1):
        if rebuilt[i].get("role") == "user":
            rebuilt[i]["content"] = text
            break
    return rebuilt, new_system


class AnthropicAdapter(ProviderAdapter):
    name = "anthropic"

    def extract_text(self, body: dict[str, Any]) -> str:
        messages = body.get("messages") or []
        system = body.get("system")
        return _join(messages, system if isinstance(system, str) else None)

    def rewrite_text(self, body: dict[str, Any], sanitized: str) -> dict[str, Any]:
        new = dict(body)
        original = new.get("messages") or []
        had_system = isinstance(new.get("system"), str)
        rebuilt, new_system = _split(sanitized, original, had_system)
        new["messages"] = rebuilt
        if had_system and new_system is not None:
            new["system"] = new_system
        return new

    def extract_model(self, body: dict[str, Any]) -> str | None:
        v = body.get("model")
        return str(v) if v else None

    def extract_output_text(self, body: dict[str, Any]) -> str:
        content = body.get("content") or []
        parts: list[str] = []
        if isinstance(content, list):
            for piece in content:
                if isinstance(piece, dict) and piece.get("type") == "text":
                    parts.append(piece.get("text", ""))
        return "\n".join(parts)

    def rewrite_output_text(self, body: dict[str, Any], sanitized: str) -> dict[str, Any]:
        new = dict(body)
        content = list(new.get("content") or [])
        replaced = False
        for i, piece in enumerate(content):
            if isinstance(piece, dict) and piece.get("type") == "text":
                if not replaced:
                    new_piece = dict(piece)
                    new_piece["text"] = sanitized
                    content[i] = new_piece
                    replaced = True
                else:
                    content[i] = {"type": "text", "text": ""}
        if not replaced:
            content.append({"type": "text", "text": sanitized})
        new["content"] = content
        return new

    async def forward(self, path: str, body: dict[str, Any], extra_headers: dict[str, str]) -> ProviderResponse:
        if not self.api_key:
            raise ProviderError("Anthropic API key is not configured for this tenant.", status_code=412)
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": extra_headers.get("anthropic-version", "2023-06-01"),
            "Content-Type": "application/json",
        }
        if "anthropic-beta" in extra_headers:
            headers["anthropic-beta"] = extra_headers["anthropic-beta"]
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
