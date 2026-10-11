"""Versioned SQLite schema with forward-only migrations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    import sqlite3

# Each entry migrates the schema from version ``index`` to ``index + 1``; the
# version is kept in ``PRAGMA user_version``. Append new migrations; never
# edit a released one.
MIGRATIONS: Final[tuple[tuple[str, ...], ...]] = (
    (
        """
        CREATE TABLE rule_state (
            rule_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            updated_at TEXT NOT NULL
        ) STRICT
        """,
        """
        CREATE TABLE delivery (
            event_id TEXT NOT NULL,
            recipient TEXT NOT NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            text TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            next_attempt_at TEXT,
            last_attempt_at TEXT,
            provider_message_id TEXT,
            PRIMARY KEY (event_id, recipient)
        ) STRICT
        """,
        "CREATE INDEX delivery_updated_at ON delivery (updated_at)",
        "CREATE TABLE send_attempt (id INTEGER PRIMARY KEY, at TEXT NOT NULL) STRICT",
        "CREATE INDEX send_attempt_at ON send_attempt (at)",
        "CREATE TABLE suppressed (recipient TEXT PRIMARY KEY, count INTEGER NOT NULL) STRICT",
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT",
    ),
)

SCHEMA_VERSION: Final = len(MIGRATIONS)


class SchemaTooNewError(RuntimeError):
    """The database was written by a newer release; it is left untouched."""


def schema_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("PRAGMA user_version").fetchone()
    return int(row[0])


def migrate(
    connection: sqlite3.Connection,
    migrations: tuple[tuple[str, ...], ...] = MIGRATIONS,
) -> int:
    """Bring the schema up to date, one transaction per step; return the final version.

    The connection must be in autocommit mode so that transactions are explicit.
    """
    version = schema_version(connection)
    if version > len(migrations):
        raise SchemaTooNewError(  # noqa: TRY003  # the versions are the useful detail
            f"database schema version {version} is newer than supported {len(migrations)}"
        )
    for index in range(version, len(migrations)):
        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in migrations[index]:
                connection.execute(statement)
            # PRAGMA does not accept parameters; the value is a loop integer.
            connection.execute(f"PRAGMA user_version = {index + 1:d}")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")
    return len(migrations)
