"""Local index of public breach catalogue metadata (never leaked account rows)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import aiohttp

DB_PATH = Path(__file__).with_name("breach_catalog.sqlite3")
HIBP_CATALOG = "https://haveibeenpwned.com/api/v3/breaches"


class BreachCatalog:
    def __init__(self, path: Path = DB_PATH):
        self.path = path

    def _connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("""CREATE TABLE IF NOT EXISTS breaches (
            name TEXT PRIMARY KEY, title TEXT NOT NULL, domain TEXT NOT NULL,
            breach_date TEXT, added_date TEXT, pwn_count INTEGER,
            data_classes TEXT NOT NULL, verified INTEGER NOT NULL,
            indexed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        return db

    async def refresh(self) -> int:
        timeout = aiohttp.ClientTimeout(total=25)
        async with aiohttp.ClientSession(timeout=timeout, headers={"user-agent": "OSINT-Breach-Monitor"}) as session:
            async with session.get(HIBP_CATALOG) as response:
                response.raise_for_status()
                catalog = await response.json(content_type=None)
        rows = []
        for item in catalog:
            if not isinstance(item, dict) or not isinstance(item.get("Name"), str):
                continue
            classes = item.get("DataClasses", [])
            if not isinstance(classes, list):
                classes = []
            rows.append((
                item["Name"][:160], str(item.get("Title") or item["Name"])[:200],
                str(item.get("Domain") or "")[:200], str(item.get("BreachDate") or "")[:10],
                str(item.get("AddedDate") or "")[:30],
                item.get("PwnCount") if isinstance(item.get("PwnCount"), int) else None,
                json.dumps([x[:80] for x in classes[:30] if isinstance(x, str)]),
                int(bool(item.get("IsVerified"))),
            ))
        if not rows:
            raise ValueError("The breach catalogue response was empty or invalid")
        with self._connect() as db:
            db.execute("DELETE FROM breaches")
            db.executemany("""INSERT INTO breaches
                (name,title,domain,breach_date,added_date,pwn_count,data_classes,verified,indexed_at)
                VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
                ON CONFLICT(name) DO UPDATE SET title=excluded.title, domain=excluded.domain,
                breach_date=excluded.breach_date, added_date=excluded.added_date,
                pwn_count=excluded.pwn_count, data_classes=excluded.data_classes,
                verified=excluded.verified, indexed_at=CURRENT_TIMESTAMP""", rows)
        return len(rows)

    def search(self, query: str = "", limit: int = 100) -> list[dict]:
        query = query.strip()[:120]
        with self._connect() as db:
            if query:
                pattern = f"%{query}%"
                records = db.execute("""SELECT name,title,domain,breach_date,added_date,
                    pwn_count,data_classes,verified,indexed_at FROM breaches
                    WHERE name LIKE ? OR title LIKE ? OR domain LIKE ?
                    ORDER BY COALESCE(breach_date,'') DESC LIMIT ?""",
                    (pattern, pattern, pattern, max(1, min(limit, 500)))).fetchall()
            else:
                records = db.execute("""SELECT name,title,domain,breach_date,added_date,
                    pwn_count,data_classes,verified,indexed_at FROM breaches
                    ORDER BY COALESCE(breach_date,'') DESC LIMIT ?""",
                    (max(1, min(limit, 500)),)).fetchall()
        return [{**dict(row), "data_classes": json.loads(row["data_classes"])} for row in records]
