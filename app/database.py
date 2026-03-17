"""
database.py — asyncpg connection pool management.

The pool is created once during app startup (lifespan) and closed on shutdown.
All DB operations acquire a connection from this pool — never open raw connections.

Usage in route/service:
    async with get_connection() as conn:
        row = await conn.fetchrow("SELECT ...")
"""

import asyncpg
from app.config import DATABASE_URL

# Module-level pool reference — set during lifespan startup
_pool: asyncpg.Pool | None = None


async def init_pool() -> None:
    """
    Create the asyncpg connection pool.
    Called once in FastAPI lifespan startup.
    min_size=2  — keep 2 connections warm at all times.
    max_size=10 — never exceed 10 concurrent DB connections.
    """
    global _pool
    _pool = await asyncpg.create_pool(
        dsn=DATABASE_URL,
        min_size=2,
        max_size=10,
        command_timeout=60,        # seconds before a query is killed
        max_inactive_connection_lifetime=300,  # recycle idle connections
    )


async def close_pool() -> None:
    """
    Gracefully close the pool on app shutdown.
    Called once in FastAPI lifespan shutdown.
    """
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


def get_pool() -> asyncpg.Pool:
    """
    Return the active pool.
    Raises RuntimeError if called before init_pool().
    """
    if _pool is None:
        raise RuntimeError(
            "Database pool is not initialised. "
            "Ensure init_pool() is called in the app lifespan."
        )
    return _pool


class get_connection:
    """
    Async context manager that acquires a connection from the pool
    and releases it automatically when the block exits.

    Example:
        async with get_connection() as conn:
            result = await conn.fetch("SELECT * FROM users")
    """

    async def __aenter__(self) -> asyncpg.Connection:
        self._conn = await get_pool().acquire()
        return self._conn

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await get_pool().release(self._conn)