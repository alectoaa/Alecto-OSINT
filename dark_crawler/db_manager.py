"""
dark_crawler/db_manager.py
------------------------
SQLite tabanlı onion node kalıcılığı.
"""

import asyncio
import sqlite3
import time
import urllib.parse
from pathlib import Path
from typing import Iterable

DB_PATH = Path(__file__).parent / "found_nodes.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    source TEXT,
    tags TEXT,
    discovered_by TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    last_seen REAL,
    last_checked REAL,
    hit_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nodes_active ON nodes(active);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);
"""


def _normalize_onion_url(url: str) -> str | None:
    if not url:
        return None
    url = url.strip()
    if not url:
        return None

    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    if not hostname.lower().endswith(".onion"):
        return None

    path = parsed.path or ""
    if parsed.query:
        path += "?" + parsed.query
    if parsed.fragment:
        path += "#" + parsed.fragment

    normalized = f"http://{hostname}{path}"
    return normalized


class DBManager:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialized = False

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_sync(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    async def initialize(self) -> None:
        if self._initialized:
            return
        await asyncio.to_thread(self._initialize_sync)
        self._initialized = True

    async def add_node(
        self,
        url: str,
        source: str = "",
        tags: str = "",
        discovered_by: str = "",
        active: int = 1,
    ) -> None:
        normalized = _normalize_onion_url(url)
        if not normalized:
            return
        now = time.time()

        def _insert() -> None:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO nodes (url, source, tags, discovered_by, active, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(url) DO UPDATE SET
                        source = COALESCE(NULLIF(source, ''), excluded.source),
                        tags = COALESCE(NULLIF(tags, ''), tags),
                        discovered_by = COALESCE(NULLIF(discovered_by, ''), discovered_by),
                        last_seen = excluded.last_seen
                    """,
                    (normalized, source, tags, discovered_by, active, now),
                )
                conn.commit()

        await asyncio.to_thread(_insert)

    async def bulk_add_nodes(self, records: Iterable[tuple[str, str, str]]) -> int:
        normalized_records = []
        for url, source, tags in records:
            normalized = _normalize_onion_url(url)
            if normalized:
                normalized_records.append((normalized, source, tags, time.time()))

        if not normalized_records:
            return 0

        def _insert_many() -> int:
            with self._connect() as conn:
                count = 0
                for url, source, tags, seen_at in normalized_records:
                    cursor = conn.execute(
                        """
                        INSERT INTO nodes (url, source, tags, discovered_by, active, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(url) DO UPDATE SET
                            source = COALESCE(NULLIF(source, ''), source),
                            tags = COALESCE(NULLIF(tags, ''), tags),
                            last_seen = excluded.last_seen
                        """,
                        (url, source, tags, "index_fetch", 1, seen_at),
                    )
                    if cursor.rowcount:
                        count += 1
                conn.commit()
                return count

        return await asyncio.to_thread(_insert_many)

    async def get_active_nodes(self, limit: int = 50) -> list[dict]:
        def _select() -> list[dict]:
            with self._connect() as conn:
                cursor = conn.execute(
                    "SELECT url, source, tags, active, last_seen, hit_count FROM nodes "
                    "WHERE active = 1 ORDER BY last_seen DESC, hit_count DESC LIMIT ?",
                    (limit,),
                )
                return [dict(row) for row in cursor.fetchall()]

        return await asyncio.to_thread(_select)

    async def node_count(self) -> int:
        def _count() -> int:
            with self._connect() as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM nodes")
                return int(cursor.fetchone()[0])

        return await asyncio.to_thread(_count)

    async def touch_node(self, url: str) -> None:
        normalized = _normalize_onion_url(url)
        if not normalized:
            return

        def _touch() -> None:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE nodes SET last_checked = ?, hit_count = hit_count + 1 WHERE url = ?",
                    (time.time(), normalized),
                )
                conn.commit()

        await asyncio.to_thread(_touch)
