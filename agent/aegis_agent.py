"""Aegis Endpoint Agent.

Run this on a developer laptop or CI worker to provide a local OpenAI-compatible
endpoint that transparently forwards through the corporate Aegis gateway:

    aegis-agent --gateway https://aegis.example.com --api-key aeg_live_... --port 11434

Then in the user's app (or shell):

    export OPENAI_BASE_URL=http://127.0.0.1:11434/v1
    export OPENAI_API_KEY=anything-aegis-replaces-it

The agent forwards all requests verbatim to the gateway, swapping in the Aegis
key and adding ``X-Aegis-Endpoint`` so server-side audit logs can attribute
them. No app code change required.
"""

from __future__ import annotations

import argparse
import logging
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

log = logging.getLogger("aegis.agent")


def build_app(gateway: str, api_key: str, hostname: str) -> FastAPI:
    app = FastAPI(title="Aegis Endpoint Agent", version="0.1.0")
    base = gateway.rstrip("/")

    async def forward(path: str, request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            body = {}
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Aegis-Endpoint": hostname,
        }
        for h in ("openai-organization", "openai-project", "anthropic-version", "anthropic-beta"):
            v = request.headers.get(h)
            if v:
                headers[h] = v
        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0)) as client:
            resp = await client.post(f"{base}/{path.lstrip('/')}", json=body, headers=headers)
        try:
            data = resp.json()
        except ValueError:
            data = {"error": {"message": resp.text}}
        return JSONResponse(status_code=resp.status_code, content=data)

    @app.post("/v1/chat/completions")
    async def chat(req: Request): return await forward("/v1/chat/completions", req)

    @app.post("/v1/embeddings")
    async def emb(req: Request): return await forward("/v1/embeddings", req)

    @app.post("/v1/responses")
    async def resp(req: Request): return await forward("/v1/responses", req)

    @app.post("/v1/messages")
    async def msg(req: Request): return await forward("/v1/messages", req)

    @app.get("/healthz")
    async def healthz(): return {"status": "ok", "gateway": base, "host": hostname}

    return app


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Aegis local endpoint agent.")
    p.add_argument("--gateway", default=os.getenv("AEGIS_GATEWAY_URL", "http://127.0.0.1:8080"))
    p.add_argument("--api-key", default=os.getenv("AEGIS_API_KEY"))
    p.add_argument("--port", type=int, default=int(os.getenv("AEGIS_AGENT_PORT", "11434")))
    p.add_argument("--host", default="127.0.0.1")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    import socket

    import uvicorn

    args = parse_args(argv)
    if not args.api_key:
        raise SystemExit("Missing --api-key (or AEGIS_API_KEY env var).")
    app = build_app(args.gateway, args.api_key, hostname=socket.gethostname())
    log.info("Aegis agent forwarding %s -> %s", args.port, args.gateway)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
