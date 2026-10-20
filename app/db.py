# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Database engine, sessions and migrations run at startup."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.config import APP_ROOT, Settings

logger = logging.getLogger(__name__)

ALEMBIC_INI = APP_ROOT / "alembic.ini"

_engine: AsyncEngine | None = None
_engine_url: str | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def init_engine(settings: Settings) -> AsyncEngine:
    """Create the engine and the session factory.

    A different DATABASE_URL always gets a new engine; reusing one across URLs
    would silently connect to the previous database.
    """
    global _engine, _engine_url, _session_factory
    if _engine is not None and _engine_url != settings.database_url:
        _engine = None
        _session_factory = None
    if _engine is None:
        _engine = create_async_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=5,
            echo=False,
        )
        _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
        _engine_url = settings.database_url
    return _engine


async def dispose_engine() -> None:
    global _engine, _engine_url, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _engine_url = None
    _session_factory = None


def session_factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        raise RuntimeError("Database engine is not initialised")
    return _session_factory


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session per request."""
    async with session_factory()() as session:
        yield session


async def run_migrations(engine: AsyncEngine) -> None:
    """Run `alembic upgrade head` on the given engine.

    Idempotent: an already migrated database is left untouched. The migration
    runs on our own connection, so Alembic does not open a second one.
    """

    def upgrade(connection: Connection) -> None:
        config = Config(str(ALEMBIC_INI))
        config.attributes["connection"] = connection
        command.upgrade(config, "head")

    async with engine.begin() as connection:
        await connection.run_sync(upgrade)
