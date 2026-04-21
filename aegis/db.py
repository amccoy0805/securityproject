"""SQLAlchemy async engine + session helpers."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _ensure_sqlite_dir(url: str) -> None:
    if url.startswith("sqlite") and ":///" in url:
        path = url.split(":///", 1)[1]
        if path and path != ":memory:":
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)


def get_engine():
    global _engine, _session_factory
    if _engine is None:
        settings = get_settings()
        _ensure_sqlite_dir(settings.database_url)
        _engine = create_async_engine(settings.database_url, future=True, echo=False)
        _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        get_engine()
    assert _session_factory is not None
    return _session_factory


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables. Safe to call repeatedly."""
    from . import models  # noqa: F401  (register models)

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
