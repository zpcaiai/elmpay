"""Shared SQLite transaction boundary for B118-B127 offline control planes."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator

from .common import ValidationError


MIGRATION = Path(__file__).resolve().parents[1] / "migrations/V120_127__release_control.sql"


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, traceback))
        finally:
            self.close()


class DurableStore:
    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        if self.database == ":memory:":
            raise ValidationError("durable controls require a filesystem-backed SQLite database")
        path = Path(self.database)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not MIGRATION.is_file():
            raise ValidationError("release-control database migration is missing")
        with self.connect() as connection:
            connection.executescript(MIGRATION.read_text(encoding="utf-8"))
            self._upgrade_legacy_schema(connection)

    @staticmethod
    def _upgrade_legacy_schema(connection: sqlite3.Connection) -> None:
        """Apply the one safe additive upgrade needed by existing control DBs.

        Historical usage rows cannot be assigned a pricing version without
        inventing billing provenance, so the upgrade intentionally leaves the
        new column NULL. Invoice issuance fails closed on those rows while all
        newly metered usage is required to persist an exact version binding.
        """

        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(usage_event)").fetchall()
        }
        if "pricing_version_id" not in columns:
            connection.execute(
                "ALTER TABLE usage_event ADD COLUMN pricing_version_id TEXT "
                "REFERENCES pricing_version(pricing_version_id)"
            )
        export_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(commercial_audit_export)"
            ).fetchall()
        }
        if "manifest_json" not in export_columns:
            connection.execute(
                "ALTER TABLE commercial_audit_export ADD COLUMN manifest_json TEXT"
            )
        if "receipt_json" not in export_columns:
            connection.execute(
                "ALTER TABLE commercial_audit_export ADD COLUMN receipt_json TEXT"
            )
        reconciliation_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(reconciliation_source_receipt)"
            ).fetchall()
        }
        if "receipt_json" not in reconciliation_columns:
            connection.execute(
                "ALTER TABLE reconciliation_source_receipt ADD COLUMN receipt_json TEXT"
            )

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            timeout=10,
            isolation_level=None,
            factory=_ClosingConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
