from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import List, Optional

from .models import Token, TokenAccess


class TokenStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tokens (
                    token_id TEXT PRIMARY KEY,
                    token_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    metadata TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accesses (
                    token_id TEXT NOT NULL,
                    accessed_at TEXT NOT NULL,
                    src_ip TEXT,
                    user_agent TEXT,
                    extra TEXT NOT NULL
                )
                """
            )

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def add_token(self, token: Token) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO tokens VALUES (?, ?, ?, ?, ?, ?)",
                (
                    token.token_id,
                    token.token_type,
                    token.value,
                    token.created_at.isoformat(),
                    token.expires_at.isoformat() if token.expires_at else None,
                    str(token.metadata),
                ),
            )

    def list_tokens(self) -> List[Token]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM tokens").fetchall()
        return [
            Token(
                token_id=row[0],
                token_type=row[1],
                value=row[2],
                created_at=datetime.fromisoformat(row[3]),
                expires_at=datetime.fromisoformat(row[4]) if row[4] else None,
                metadata={"raw": row[5]},
            )
            for row in rows
        ]

    def get_token(self, token_id: str) -> Optional[Token]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tokens WHERE token_id = ?", (token_id,)).fetchone()
        if not row:
            return None
        return Token(
            token_id=row[0],
            token_type=row[1],
            value=row[2],
            created_at=datetime.fromisoformat(row[3]),
            expires_at=datetime.fromisoformat(row[4]) if row[4] else None,
            metadata={"raw": row[5]},
        )

    def add_access(self, access: TokenAccess) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO accesses VALUES (?, ?, ?, ?, ?)",
                (
                    access.token_id,
                    access.accessed_at.isoformat(),
                    access.src_ip,
                    access.user_agent,
                    str(access.extra),
                ),
            )
