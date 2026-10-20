# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Lukáš Zuzaňák <lukas@zuzanak.eu>
"""Small in-process TTL cache (SPEC 9.4: dashboard responses, status checks)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any


class TTLCache:
    """Cache with a time to live, safe for concurrent use in one process."""

    def __init__(self, ttl_seconds: float) -> None:
        self._ttl = ttl_seconds
        self._values: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get_or_set(self, key: str, factory: Callable[[], Awaitable[Any]]) -> Any:
        """Return the cached value, or compute and store a fresh one."""
        async with self._lock:
            entry = self._values.get(key)
            if entry is not None and entry[0] > time.monotonic():
                return entry[1]
        value = await factory()
        async with self._lock:
            self._values[key] = (time.monotonic() + self._ttl, value)
        return value

    def invalidate(self, key: str | None = None) -> None:
        if key is None:
            self._values.clear()
        else:
            self._values.pop(key, None)
