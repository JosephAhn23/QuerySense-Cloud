"""
Large Query Store — unlimited query text with compression.

pg_stat_statements truncates queries at track_activity_query_size (default 1024,
max 1MB). pganalyze advertises "No limit on query text length" by collecting
full query text from logs.

This module stores full query text with zstandard compression and SHA-256 hash
lookup. A 10KB query compresses to ~2KB; a 100KB query compresses to ~15KB.

Usage:
    from querysense.storage.large_query import LargeQueryStore

    store = LargeQueryStore()
    qhash = store.store("SELECT ... (100KB of SQL)")
    original = store.get(qhash)
    assert len(original) == 100_000
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DB_PATH = Path.home() / ".querysense" / "query_store.db"

_HAS_ZSTD = False
try:
    import zstandard as zstd

    _HAS_ZSTD = True
except ImportError:
    pass

_HAS_ZLIB = True
import zlib


@dataclass
class StoredQuery:
    """Metadata for a stored query."""

    query_hash: str
    length: int
    compressed_length: int
    compression_ratio: float
    first_seen: str
    last_seen: str
    access_count: int
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_hash": self.query_hash,
            "length": self.length,
            "compressed_length": self.compressed_length,
            "compression_ratio": round(self.compression_ratio, 2),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "access_count": self.access_count,
            "fingerprint": self.fingerprint,
        }


@dataclass
class StoreStats:
    """Overall store statistics."""

    total_queries: int = 0
    total_raw_bytes: int = 0
    total_compressed_bytes: int = 0
    avg_compression_ratio: float = 0.0
    largest_query_bytes: int = 0
    db_size_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_queries": self.total_queries,
            "total_raw_bytes": self.total_raw_bytes,
            "total_compressed_bytes": self.total_compressed_bytes,
            "avg_compression_ratio": round(self.avg_compression_ratio, 2),
            "largest_query_bytes": self.largest_query_bytes,
            "db_size_bytes": self.db_size_bytes,
        }


class LargeQueryStore:
    """
    Persistent, compressed query text store.

    Uses zstandard (preferred) or zlib for compression, backed by SQLite.
    Queries are addressed by SHA-256 hash for deduplication.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._compressor = zstd.ZstdCompressor(level=3) if _HAS_ZSTD else None
        self._decompressor = zstd.ZstdDecompressor() if _HAS_ZSTD else None
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS queries (
                    query_hash TEXT PRIMARY KEY,
                    raw_length INTEGER NOT NULL,
                    compressed BLOB NOT NULL,
                    compressed_length INTEGER NOT NULL,
                    compression_type TEXT NOT NULL DEFAULT 'zstd',
                    fingerprint TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    access_count INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_queries_fingerprint
                    ON queries(fingerprint);
                CREATE INDEX IF NOT EXISTS idx_queries_last_seen
                    ON queries(last_seen);
            """)

    # ── Store / Retrieve ─────────────────────────────────────────────

    def store(self, query: str, fingerprint: str = "") -> str:
        """
        Compress and store a query. Returns SHA-256 hash for lookup.

        Deduplicates automatically — storing the same query twice just
        updates last_seen and access_count.
        """
        query_bytes = query.encode("utf-8")
        query_hash = hashlib.sha256(query_bytes).hexdigest()[:16]
        now = datetime.now(timezone.utc).isoformat()

        compressed, comp_type = self._compress(query_bytes)

        with sqlite3.connect(str(self.db_path)) as conn:
            existing = conn.execute(
                "SELECT query_hash FROM queries WHERE query_hash = ?",
                (query_hash,),
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE queries SET last_seen = ?, access_count = access_count + 1 "
                    "WHERE query_hash = ?",
                    (now, query_hash),
                )
            else:
                conn.execute(
                    "INSERT INTO queries "
                    "(query_hash, raw_length, compressed, compressed_length, "
                    "compression_type, fingerprint, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        query_hash,
                        len(query_bytes),
                        compressed,
                        len(compressed),
                        comp_type,
                        fingerprint,
                        now,
                        now,
                    ),
                )

        return query_hash

    def get(self, query_hash: str) -> str | None:
        """Retrieve and decompress a query by hash."""
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT compressed, compression_type FROM queries WHERE query_hash = ?",
                (query_hash,),
            ).fetchone()

            if not row:
                return None

            return self._decompress(row[0], row[1])

    def get_metadata(self, query_hash: str) -> StoredQuery | None:
        """Get metadata without decompressing."""
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT query_hash, raw_length, compressed_length, fingerprint, "
                "first_seen, last_seen, access_count "
                "FROM queries WHERE query_hash = ?",
                (query_hash,),
            ).fetchone()

            if not row:
                return None

            return StoredQuery(
                query_hash=row[0],
                length=row[1],
                compressed_length=row[2],
                compression_ratio=row[1] / max(row[2], 1),
                fingerprint=row[3],
                first_seen=row[4],
                last_seen=row[5],
                access_count=row[6],
            )

    def search_by_fingerprint(self, fingerprint: str) -> list[StoredQuery]:
        """Find all query variants sharing a fingerprint."""
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT query_hash, raw_length, compressed_length, fingerprint, "
                "first_seen, last_seen, access_count "
                "FROM queries WHERE fingerprint = ? ORDER BY last_seen DESC",
                (fingerprint,),
            ).fetchall()

            return [
                StoredQuery(
                    query_hash=r[0],
                    length=r[1],
                    compressed_length=r[2],
                    compression_ratio=r[1] / max(r[2], 1),
                    fingerprint=r[3],
                    first_seen=r[4],
                    last_seen=r[5],
                    access_count=r[6],
                )
                for r in rows
            ]

    def stats(self) -> StoreStats:
        """Get overall store statistics."""
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute("""
                SELECT
                    COUNT(*),
                    COALESCE(SUM(raw_length), 0),
                    COALESCE(SUM(compressed_length), 0),
                    COALESCE(MAX(raw_length), 0)
                FROM queries
            """).fetchone()

            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0

            return StoreStats(
                total_queries=row[0],
                total_raw_bytes=row[1],
                total_compressed_bytes=row[2],
                avg_compression_ratio=row[1] / max(row[2], 1) if row[2] > 0 else 0,
                largest_query_bytes=row[3],
                db_size_bytes=db_size,
            )

    def cleanup(self, max_age_days: int = 90) -> int:
        """Remove queries not accessed in max_age_days. Returns count removed."""
        from datetime import timedelta

        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=max_age_days)
        ).isoformat()

        with sqlite3.connect(str(self.db_path)) as conn:
            cur = conn.execute(
                "DELETE FROM queries WHERE last_seen < ?", (cutoff,)
            )
            return cur.rowcount

    # ── Compression ──────────────────────────────────────────────────

    def _compress(self, data: bytes) -> tuple[bytes, str]:
        """Compress using zstd (preferred) or zlib."""
        if self._compressor:
            return self._compressor.compress(data), "zstd"
        return zlib.compress(data, level=6), "zlib"

    def _decompress(self, data: bytes, comp_type: str) -> str:
        """Decompress based on stored compression type."""
        if comp_type == "zstd" and self._decompressor:
            return self._decompressor.decompress(data).decode("utf-8")
        if comp_type == "zlib":
            return zlib.decompress(data).decode("utf-8")
        if comp_type == "zstd" and not self._decompressor:
            raise ImportError(
                "zstandard not installed. Install with: pip install zstandard"
            )
        return data.decode("utf-8")
