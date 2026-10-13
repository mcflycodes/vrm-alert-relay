"""Versioned SQLite schema with forward-only migrations."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    import sqlite3

# Each entry migrates the schema from version ``index`` to ``index + 1``; the
# version is kept in ``PRAGMA user_version``. Append new migrations; never
# edit a released one. (Version 1 was changed in place before any release.)
# ``send_attempt`` holds real provider calls only: dry-run sends are never
# stored, so they can never displace evidence of a real one.
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
            rule_id TEXT,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            text TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            next_attempt_at TEXT,
            last_attempt_at TEXT,
            provider_message_id TEXT,
            covers INTEGER NOT NULL DEFAULT 0,
            recovered INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (event_id, recipient)
        ) STRICT
        """,
        "CREATE INDEX delivery_updated_at ON delivery (updated_at)",
        """
        CREATE TABLE send_attempt (
            id INTEGER PRIMARY KEY,
            event_id TEXT NOT NULL,
            recipient TEXT NOT NULL,
            attempt INTEGER NOT NULL,
            at TEXT NOT NULL,
            UNIQUE (event_id, recipient, attempt)
        ) STRICT
        """,
        "CREATE INDEX send_attempt_at ON send_attempt (at)",
        "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT",
    ),
    # 2 (0.1.1): what a delivery reports; null for records written before.
    ("ALTER TABLE delivery ADD COLUMN origin TEXT",),
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

    The version is read again after each write lock is taken, so a concurrent
    migration is never applied twice. The connection must be in autocommit
    mode so that transactions are explicit.
    """
    target = len(migrations)
    if schema_version(connection) == target:
        return target  # Up to date: no write lock, so a read-only file can still be read.
    while True:
        connection.execute("BEGIN IMMEDIATE")
        try:
            version = schema_version(connection)
            if version < target:
                for statement in migrations[version]:
                    connection.execute(statement)
                # PRAGMA does not accept parameters; the value is a checked integer.
                connection.execute(f"PRAGMA user_version = {version + 1:d}")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")
        if version >= target:
            break
    if version > target:
        raise SchemaTooNewError(  # noqa: TRY003  # the versions are the useful detail
            f"database schema version {version} is newer than supported {target}"
        )
    return target
