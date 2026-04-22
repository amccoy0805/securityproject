"""Aegis FastAPI entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .bootstrap import ensure_initial_tenant
from .config import get_settings
from .db import init_db
from .logging_setup import configure_logging
from .routes.admin_api import router as admin_api_router
from .routes.admin_ui import router as admin_ui_router
from .routes.proxy import router as proxy_router

log = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level, json_logs=settings.env != "dev")
    await init_db()
    await ensure_initial_tenant()
    log.info("Aegis %s ready (env=%s)", __version__, settings.env)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Aegis AI Gateway",
        version=__version__,
        description=(
            "Enterprise security and compliance layer for AI usage. "
            "Mediates traffic to OpenAI, Anthropic, and any OpenAI-compatible provider, "
            "enforcing data classification, redaction, model allow-lists, and audit logging."
        ),
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if "*" in settings.allowed_hosts_list else settings.allowed_hosts_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(proxy_router)
    app.include_router(admin_api_router)
    app.include_router(admin_ui_router)

    @app.get("/healthz", tags=["meta"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


app = create_app()
