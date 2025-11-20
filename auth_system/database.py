"""Database helpers for secure user storage."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

DB_PATH = Path("auth.db")


@contextmanager
def get_connection(readonly: bool = False) -> Iterator[sqlite3.Connection]:
    """Context-managed SQLite connection with safe defaults."""
    uri = f"file:{DB_PATH}?mode={'ro' if readonly else 'rwc'}"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        if not readonly:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
        yield conn
        if not readonly:
            conn.commit()
    finally:
        conn.close()


def initialize() -> None:
    """Create the database schema if it does not exist."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                credentials TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )


def store_user(username: str, credentials: str, totp_secret: str) -> None:
    """Insert a new user securely using parameterized queries."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, credentials, totp_secret) VALUES (?, ?, ?);",
            (username, credentials, totp_secret),
        )


def get_user(username: str) -> Optional[sqlite3.Row]:
    """Retrieve a user record by username."""
    with get_connection(readonly=True) as conn:
        cursor = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        return cursor.fetchone()
