from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Iterable, List

import psycopg

from .models import LureDeployment


class StateStore:
    def __init__(self, db_url: str) -> None:
        self.db_url = db_url
        self._init_db()

    def _init_db(self) -> None:
        if self.db_url.startswith("postgres"):
            with self._pg_connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS lures (
                        lure_id TEXT PRIMARY KEY,
                        lure_type TEXT NOT NULL,
                        subnet TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        ttl_seconds INTEGER NOT NULL,
                        metadata TEXT NOT NULL
                    )
                    """
                )
        else:
            with self._sqlite_connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS lures (
                        lure_id TEXT PRIMARY KEY,
                        lure_type TEXT NOT NULL,
                        subnet TEXT NOT NULL,
                        hostname TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        ttl_seconds INTEGER NOT NULL,
                        metadata TEXT NOT NULL
                    )
                    """
                )

    @contextmanager
    def _sqlite_connect(self):
        path = self.db_url.replace("sqlite:///", "")
        conn = sqlite3.connect(path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def _pg_connect(self):
        conn = psycopg.connect(self.db_url)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def add_lure(self, lure: LureDeployment) -> None:
        if self.db_url.startswith("postgres"):
            with self._pg_connect() as conn:
                conn.execute(
                    """
                    INSERT INTO lures VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (lure_id) DO UPDATE
                    SET lure_type = EXCLUDED.lure_type,
                        subnet = EXCLUDED.subnet,
                        hostname = EXCLUDED.hostname,
                        created_at = EXCLUDED.created_at,
                        ttl_seconds = EXCLUDED.ttl_seconds,
                        metadata = EXCLUDED.metadata
                    """,
                    (
                        lure.lure_id,
                        lure.lure_type,
                        lure.subnet,
                        lure.hostname,
                        lure.created_at.isoformat(),
                        lure.ttl_seconds,
                        str(lure.metadata),
                    ),
                )
        else:
            with self._sqlite_connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO lures VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        lure.lure_id,
                        lure.lure_type,
                        lure.subnet,
                        lure.hostname,
                        lure.created_at.isoformat(),
                        lure.ttl_seconds,
                        str(lure.metadata),
                    ),
                )

    def list_lures(self) -> List[LureDeployment]:
        if self.db_url.startswith("postgres"):
            with self._pg_connect() as conn:
                rows = conn.execute("SELECT * FROM lures").fetchall()
        else:
            with self._sqlite_connect() as conn:
                rows = conn.execute("SELECT * FROM lures").fetchall()
        lures: List[LureDeployment] = []
        for row in rows:
            lures.append(
                LureDeployment(
                    lure_id=row[0],
                    lure_type=row[1],
                    subnet=row[2],
                    hostname=row[3],
                    created_at=datetime.fromisoformat(row[4]),
                    ttl_seconds=row[5],
                    metadata={"raw": row[6]},
                )
            )
        return lures

    def expired_lures(self, now: datetime) -> Iterable[LureDeployment]:
        for lure in self.list_lures():
            if (now - lure.created_at).total_seconds() > lure.ttl_seconds:
                yield lure

    def remove_lure(self, lure_id: str) -> None:
        if self.db_url.startswith("postgres"):
            with self._pg_connect() as conn:
                conn.execute("DELETE FROM lures WHERE lure_id = %s", (lure_id,))
        else:
            with self._sqlite_connect() as conn:
                conn.execute("DELETE FROM lures WHERE lure_id = ?", (lure_id,))
