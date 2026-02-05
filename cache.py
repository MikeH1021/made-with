"""
In-memory TTL cache for scan results.

Simple dict-based cache with time-based expiration. No external
dependencies (no Redis). Thread-safe within a single asyncio event loop.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class CacheEntry:
    value: Any
    expires_at: float


class TTLCache:
    """In-memory cache with per-key TTL expiration."""

    def __init__(self, default_ttl: int = 3600, cleanup_interval: int = 300):
        """
        Args:
            default_ttl: Default time-to-live in seconds (default: 1 hour).
            cleanup_interval: How often to purge expired entries in seconds (default: 5 min).
        """
        self._store: dict[str, CacheEntry] = {}
        self._default_ttl = default_ttl
        self._cleanup_interval = cleanup_interval
        self._cleanup_task: Optional[asyncio.Task] = None

    def get(self, key: str) -> Optional[Any]:
        """Get a value from cache. Returns None if missing or expired."""
        entry = self._store.get(key)
        if entry is None:
            return None
        if time.monotonic() > entry.expires_at:
            del self._store[key]
            return None
        return entry.value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store a value with TTL."""
        ttl = ttl if ttl is not None else self._default_ttl
        self._store[key] = CacheEntry(
            value=value,
            expires_at=time.monotonic() + ttl,
        )

    @property
    def size(self) -> int:
        """Number of entries (including possibly expired ones)."""
        return len(self._store)

    def clear_expired(self) -> int:
        """Remove expired entries. Returns number of entries removed."""
        now = time.monotonic()
        expired_keys = [k for k, v in self._store.items() if now > v.expires_at]
        for key in expired_keys:
            del self._store[key]
        return len(expired_keys)

    def delete(self, key: str) -> bool:
        """Remove a specific key. Returns True if key existed."""
        return self._store.pop(key, None) is not None

    async def _cleanup_loop(self) -> None:
        """Background task that periodically purges expired entries."""
        while True:
            await asyncio.sleep(self._cleanup_interval)
            self.clear_expired()

    def start_cleanup(self) -> None:
        """Start the background cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    def stop_cleanup(self) -> None:
        """Stop the background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
