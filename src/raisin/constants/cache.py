"""Constants used by scanner cache and hashing."""

from __future__ import annotations

CACHE_VERSION: int = 3
CACHE_FILENAME: str = ".raisin-cache.json"
CACHE_TEMP_PREFIX: str = ".cache-"
CACHE_TEMP_SUFFIX: str = ".tmp"
FILE_HASH_CHUNK_SIZE: int = 65536

# Persisted cache payloads from v2 are migrated under this inert namespace.
LEGACY_CACHE_ENGINE: str = "legacy"
