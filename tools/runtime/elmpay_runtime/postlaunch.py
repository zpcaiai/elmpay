"""Fenced post-launch scheduler and three-way reconciliation controls (B125)."""
from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Mapping

from .common import ValidationError, require_mapping, require_text, sha256_json
from .downstream_receipt import verify_downstream_receipt
from .durable import DurableStore


def _current(value: datetime | None = None) -> datetime:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc)


class PostLaunchControl:
    def __init__(self, database: str) -> None:
        self.store = DurableStore(database)

    def acquire(self, job_key: str, owner_id: str, *, lease_seconds: int = 60, now: datetime | None = None) -> int:
        require_text(job_key, "job_key")
        require_text(owner_id, "owner_id")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 10 <= lease_seconds <= 3600:
            raise ValidationError("lease_seconds must be between 10 and 3600")
        current = _current(now)
        lease_until = current + timedelta(seconds=lease_seconds)
        with self.store.transaction() as connection:
            row = connection.execute("SELECT owner_id,fence_token,lease_until FROM job_lease WHERE job_key=?", (job_key,)).fetchone()
            if row and datetime.fromisoformat(row["lease_until"]) > current and row["owner_id"] != owner_id:
                raise ValidationError("job lease is held by another owner")
            token = 1 if not row else row["fence_token"] + 1
            connection.execute(
                "INSERT INTO job_lease VALUES(?,?,?,?,?) ON CONFLICT(job_key) DO UPDATE SET owner_id=excluded.owner_id,fence_token=excluded.fence_token,lease_until=excluded.lease_until,updated_at=excluded.updated_at",
                (job_key, owner_id, token, lease_until.isoformat(), current.isoformat()),
            )
        return token

    def assert_fence(self, job_key: str, owner_id: str, token: int, *, now: datetime | None = None) -> None:
        current = _current(now)
        with self.store.connect() as connection:
            row = connection.execute("SELECT owner_id,fence_token,lease_until FROM job_lease WHERE job_key=?", (job_key,)).fetchone()
        if not row or row["owner_id"] != owner_id or row["fence_token"] != token or datetime.fromisoformat(row["lease_until"]) <= current:
            raise ValidationError("stale or expired fencing token")

    @staticmethod
    def window(kind: str, anchor: datetime) -> tuple[datetime, datetime]:
        value = anchor.astimezone(timezone.utc)
        if kind == "DAILY":
            start = value.replace(hour=0, minute=0, second=0, microsecond=0)
            return start, start + timedelta(days=1)
        if kind == "WEEKLY":
            start = (value - timedelta(days=value.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
            return start, start + timedelta(days=7)
        if kind == "MONTHLY":
            start = value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=monthrange(start.year, start.month)[1])
            return start, end
        raise ValidationError("window kind must be DAILY, WEEKLY, or MONTHLY")

    def reconcile(
        self,
        *,
        tenant_id: str,
        window_id: str,
        window_kind: str,
        period_start: datetime,
        period_end: datetime,
        currency: str,
        source_receipts: Mapping[str, Any],
        trust: Mapping[str, Any],
        job_key: str,
        owner_id: str,
        fence_token: int,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Verify three source adapters and persist a fenced reconciliation.

        Totals are never accepted as caller arguments.  Each total must be
        emitted by its configured adapter as an exact, signed and replay-
        protected source receipt for this tenant/window/currency.
        """

        self.assert_fence(job_key, owner_id, fence_token, now=now)
        if period_start.tzinfo is None or period_end.tzinfo is None or period_end <= period_start:
            raise ValidationError("reconciliation period must be an increasing timezone-aware interval")
        if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValidationError("reconciliation currency must be uppercase ISO-4217")
        if window_kind not in {"DAILY", "WEEKLY", "MONTHLY"}:
            raise ValidationError("window kind must be DAILY, WEEKLY, or MONTHLY")
        receipts = require_mapping(source_receipts, "source_receipts")
        required_sources = {
            "transaction": ("ledger_reconciliation_source", False),
            "provider": ("provider_reconciliation_source", True),
            "bank": ("bank_reconciliation_source", True),
        }
        if set(receipts) != set(required_sources):
            raise ValidationError("source receipt set must be transaction, provider, and bank")
        start_text = period_start.astimezone(timezone.utc).isoformat()
        end_text = period_end.astimezone(timezone.utc).isoformat()
        totals: dict[str, int] = {}
        verified: dict[str, dict[str, Any]] = {}
        signer_identities: set[str] = set()
        current = _current(now)
        for source, (role, independent) in required_sources.items():
            receipt = require_mapping(receipts[source], f"source_receipts.{source}")
            fields = require_mapping(receipt.get("fields"), f"source_receipts.{source}.fields")
            required_fields = {
                "source", "tenantId", "windowId", "windowKind", "periodStart",
                "periodEnd", "currency", "totalMinor", "recordCount", "sourceSnapshotDigest",
            }
            if set(fields) != required_fields:
                raise ValidationError(f"{source} source receipt field set is invalid")
            expected_binding = {
                "source": source,
                "tenantId": tenant_id,
                "windowId": window_id,
                "windowKind": window_kind,
                "periodStart": start_text,
                "periodEnd": end_text,
                "currency": currency,
            }
            if any(fields.get(key) != value for key, value in expected_binding.items()):
                raise ValidationError(f"{source} source receipt window binding mismatch")
            total = fields.get("totalMinor")
            count = fields.get("recordCount")
            snapshot = fields.get("sourceSnapshotDigest")
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise ValidationError(f"{source} total must be non-negative integer minor units")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValidationError(f"{source} record count must be a non-negative integer")
            if not isinstance(snapshot, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot):
                raise ValidationError(f"{source} source snapshot digest is invalid")
            receipt_digest, signer = verify_downstream_receipt(
                receipt,
                trust,
                receipt_type="RECONCILIATION_SOURCE_TOTAL",
                outcome="FINAL",
                fields=fields,
                required_role=role,
                require_independent=independent,
                now=current,
            )
            if signer.identity in signer_identities:
                raise ValidationError("reconciliation sources require distinct signer identities")
            signer_identities.add(signer.identity)
            totals[source] = total
            verified[source] = {
                "receiptDigest": receipt_digest,
                "signerIdentity": signer.identity,
                "recordCount": count,
                "sourceSnapshotDigest": snapshot,
            }
        transaction_total_minor = totals["transaction"]
        provider_total_minor = totals["provider"]
        bank_total_minor = totals["bank"]
        open_delta = max(transaction_total_minor, provider_total_minor, bank_total_minor) - min(transaction_total_minor, provider_total_minor, bank_total_minor)
        status = "CLOSED" if open_delta == 0 else "BLOCKED"
        record = {
            "tenantId": require_text(tenant_id, "tenant_id"),
            "windowId": require_text(window_id, "window_id"),
            "windowKind": window_kind,
            "periodStart": start_text,
            "periodEnd": end_text,
            "currency": currency,
            "transactionTotalMinor": transaction_total_minor,
            "providerTotalMinor": provider_total_minor,
            "bankTotalMinor": bank_total_minor,
            "openDeltaMinor": open_delta,
            "status": status,
            "fenceToken": fence_token,
            "sourceReceipts": {source: item["receiptDigest"] for source, item in verified.items()},
        }
        digest = sha256_json({key: value for key, value in record.items() if key != "fenceToken"})
        with self.store.transaction() as connection:
            fence = connection.execute("SELECT owner_id,fence_token,lease_until FROM job_lease WHERE job_key=?", (job_key,)).fetchone()
            if (
                not fence
                or fence["owner_id"] != owner_id
                or fence["fence_token"] != fence_token
                or datetime.fromisoformat(fence["lease_until"]) <= _current(now)
            ):
                raise ValidationError("stale or expired fencing token")
            prior = connection.execute("SELECT digest FROM reconciliation_window WHERE tenant_id=? AND window_id=?", (tenant_id, window_id)).fetchone()
            if prior and prior["digest"] != digest:
                raise ValidationError("reconciliation window is immutable")
            if not prior:
                connection.execute(
                    "INSERT INTO reconciliation_window VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (tenant_id, window_id, window_kind, record["periodStart"], record["periodEnd"], currency, transaction_total_minor, provider_total_minor, bank_total_minor, open_delta, status, fence_token, digest),
                )
                for source, item in verified.items():
                    connection.execute(
                        "INSERT INTO reconciliation_source_receipt VALUES(?,?,?,?,?,?,?,?)",
                        (tenant_id, window_id, source, item["signerIdentity"], totals[source],
                         item["recordCount"], item["sourceSnapshotDigest"], item["receiptDigest"]),
                    )
        return {**record, "digest": digest, "allowedToClose": status == "CLOSED", "reason": None if status == "CLOSED" else "open_reconciliation_delta"}
