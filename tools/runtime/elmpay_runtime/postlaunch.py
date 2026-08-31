"""Fenced post-launch scheduler and three-way reconciliation controls (B125)."""
from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timedelta, timezone
import re
import time
from typing import Any, Mapping

from .common import (
    ValidationError,
    canonical_json,
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from .downstream_receipt import verify_downstream_receipt
from .durable import DurableStore


def _current(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValidationError("post-launch control time must be timezone-aware")
    return current.astimezone(timezone.utc)


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
        if anchor.tzinfo is None:
            raise ValidationError("window anchor must be timezone-aware")
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

        current = _current(now)
        started_monotonic = time.monotonic()
        self.assert_fence(job_key, owner_id, fence_token, now=current)
        job_parts = job_key.split(":")
        if (
            len(job_parts) != 3
            or job_parts[0] != "reconcile"
            or job_parts[1] != tenant_id
            or job_parts[2] != window_kind
        ):
            raise ValidationError(
                "reconciliation lease is not bound to tenant and window kind"
            )
        if window_kind not in {"DAILY", "WEEKLY", "MONTHLY"}:
            raise ValidationError("window kind must be DAILY, WEEKLY, or MONTHLY")
        if period_start.tzinfo is None or period_end.tzinfo is None or period_end <= period_start:
            raise ValidationError("reconciliation period must be an increasing timezone-aware interval")
        normalized_start = period_start.astimezone(timezone.utc)
        normalized_end = period_end.astimezone(timezone.utc)
        expected_start, expected_end = self.window(window_kind, normalized_start)
        if normalized_start != expected_start or normalized_end != expected_end:
            raise ValidationError("reconciliation period must match its complete canonical window")
        expected_window_id = f"{window_kind.lower()}:{expected_start.isoformat()}"
        if window_id != expected_window_id:
            raise ValidationError("reconciliation window id is not canonical")
        if normalized_end > current:
            raise ValidationError("reconciliation period must be complete before closure")
        if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValidationError("reconciliation currency must be uppercase ISO-4217")
        receipts = require_mapping(source_receipts, "source_receipts")
        required_sources = {
            "transaction": ("ledger_reconciliation_source", False),
            "provider": ("provider_reconciliation_source", True),
            "bank": ("bank_reconciliation_source", True),
        }
        if set(receipts) != set(required_sources):
            raise ValidationError("source receipt set must be transaction, provider, and bank")
        start_text = normalized_start.isoformat()
        end_text = normalized_end.isoformat()
        with self.store.connect() as connection:
            existing_window = connection.execute(
                "SELECT window_kind,period_start,period_end,currency,"
                "transaction_total_minor,provider_total_minor,bank_total_minor,"
                "open_delta_minor,status,digest FROM reconciliation_window "
                "WHERE tenant_id=? AND window_id=?",
                (tenant_id, window_id),
            ).fetchone()
            existing_receipt_rows = connection.execute(
                "SELECT source,signer_identity,total_minor,record_count,"
                "source_snapshot_digest,receipt_digest,receipt_json "
                "FROM reconciliation_source_receipt WHERE tenant_id=? AND window_id=?",
                (tenant_id, window_id),
            ).fetchall()
        existing_receipts = {row["source"]: row for row in existing_receipt_rows}
        if not existing_window and existing_receipts:
            raise ValidationError(
                "stored reconciliation source receipts are incomplete or corrupt; fields/payload binding is invalid"
            )
        if existing_window and set(existing_receipts) != set(required_sources):
            raise ValidationError(
                "stored reconciliation source receipts are incomplete or corrupt; fields/payload binding is invalid"
            )
        totals: dict[str, int] = {}
        verified: dict[str, dict[str, Any]] = {}
        signer_identities: set[str] = set()
        for source, (role, independent) in required_sources.items():
            receipt = require_mapping(receipts[source], f"source_receipts.{source}")
            fields = require_mapping(receipt.get("fields"), f"source_receipts.{source}.fields")
            required_fields = {
                "source", "tenantId", "windowId", "windowKind", "periodStart",
                "periodEnd", "currency", "totalMinor", "recordCount", "itemDigests",
                "sourceSnapshotDigest",
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
            raw_item_digests = require_list(fields.get("itemDigests"), f"{source}.itemDigests")
            if len(raw_item_digests) > 100_000:
                raise ValidationError(f"{source} item digest set exceeds the safety limit")
            item_digests: list[str] = []
            for index, item_digest in enumerate(raw_item_digests):
                if not isinstance(item_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", item_digest):
                    raise ValidationError(f"{source} item digest {index} is invalid")
                item_digests.append(item_digest)
            if len(set(item_digests)) != len(item_digests):
                raise ValidationError(f"{source} item digest set contains duplicates")
            item_digests.sort()
            if count != len(item_digests):
                raise ValidationError(f"{source} record count does not match item digests")
            if not isinstance(snapshot, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot):
                raise ValidationError(f"{source} source snapshot digest is invalid")
            if snapshot != sha256_json(item_digests):
                raise ValidationError(f"{source} source snapshot digest does not bind item digests")
            stored = existing_receipts.get(source) if existing_window else None
            if stored:
                receipt_digest = sha256_json(receipt)
                signer_identity = require_text(
                    receipt.get("actor", receipt.get("verifier")),
                    f"source_receipts.{source}.identity",
                )
                if (
                    not stored["receipt_json"]
                    or stored["receipt_json"] != canonical_json(receipt).decode("utf-8")
                    or stored["receipt_digest"] != receipt_digest
                    or stored["signer_identity"] != signer_identity
                    or stored["total_minor"] != total
                    or stored["record_count"] != count
                    or stored["source_snapshot_digest"] != snapshot
                ):
                    raise ValidationError(
                        "stored reconciliation source receipts are incomplete or corrupt; fields/payload binding is invalid"
                    )
            else:
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
                signer_identity = signer.identity
            if signer_identity in signer_identities:
                raise ValidationError("reconciliation sources require distinct signer identities")
            signer_identities.add(signer_identity)
            totals[source] = total
            verified[source] = {
                "receiptDigest": receipt_digest,
                "receiptJson": canonical_json(receipt).decode("utf-8"),
                "signerIdentity": signer_identity,
                "recordCount": count,
                "sourceSnapshotDigest": snapshot,
                "itemDigests": tuple(item_digests),
            }
        transaction_total_minor = totals["transaction"]
        provider_total_minor = totals["provider"]
        bank_total_minor = totals["bank"]
        open_delta = max(transaction_total_minor, provider_total_minor, bank_total_minor) - min(transaction_total_minor, provider_total_minor, bank_total_minor)
        item_snapshots = {
            tuple(item["itemDigests"])
            for item in verified.values()
        }
        item_level_match = len(item_snapshots) == 1
        reasons: list[str] = []
        if open_delta != 0:
            reasons.append("open_reconciliation_delta")
        if not item_level_match:
            reasons.append("item_level_snapshot_mismatch")
        status = "CLOSED" if not reasons else "BLOCKED"
        item_set_digest = (
            sha256_json(list(next(iter(item_snapshots)))) if item_level_match else None
        )
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
            "itemLevelMatch": item_level_match,
            "itemSetDigest": item_set_digest,
            "reasons": reasons,
            "status": status,
            "fenceToken": fence_token,
            "sourceReceipts": {source: item["receiptDigest"] for source, item in verified.items()},
        }
        digest = sha256_json({key: value for key, value in record.items() if key != "fenceToken"})
        with self.store.transaction() as connection:
            completion_time = current + timedelta(
                seconds=max(0.0, time.monotonic() - started_monotonic)
            )
            fence = connection.execute("SELECT owner_id,fence_token,lease_until FROM job_lease WHERE job_key=?", (job_key,)).fetchone()
            if (
                not fence
                or fence["owner_id"] != owner_id
                or fence["fence_token"] != fence_token
                or datetime.fromisoformat(fence["lease_until"]) <= completion_time
            ):
                raise ValidationError("stale or expired fencing token")
            prior = connection.execute("SELECT window_kind,period_start,period_end,currency,transaction_total_minor,provider_total_minor,bank_total_minor,open_delta_minor,status,digest FROM reconciliation_window WHERE tenant_id=? AND window_id=?", (tenant_id, window_id)).fetchone()
            intended_window = (
                window_kind, record["periodStart"], record["periodEnd"], currency,
                transaction_total_minor, provider_total_minor, bank_total_minor,
                open_delta, status, digest,
            )
            if prior and tuple(prior) != intended_window:
                raise ValidationError("reconciliation window is immutable or corrupt")
            if not prior:
                connection.execute(
                    "INSERT INTO reconciliation_window VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (tenant_id, window_id, window_kind, record["periodStart"], record["periodEnd"], currency, transaction_total_minor, provider_total_minor, bank_total_minor, open_delta, status, fence_token, digest),
                )
                for source, item in verified.items():
                    connection.execute(
                        "INSERT INTO reconciliation_source_receipt VALUES(?,?,?,?,?,?,?,?,?)",
                        (tenant_id, window_id, source, item["signerIdentity"], totals[source],
                         item["recordCount"], item["sourceSnapshotDigest"],
                         item["receiptDigest"], item["receiptJson"]),
                    )
            else:
                stored_receipts = connection.execute(
                    "SELECT source,signer_identity,total_minor,record_count,"
                    "source_snapshot_digest,receipt_digest,receipt_json "
                    "FROM reconciliation_source_receipt WHERE tenant_id=? AND window_id=? "
                    "ORDER BY source",
                    (tenant_id, window_id),
                ).fetchall()
                intended_receipts = sorted(
                    (
                        source, item["signerIdentity"], totals[source],
                        item["recordCount"], item["sourceSnapshotDigest"],
                        item["receiptDigest"], item["receiptJson"],
                    )
                    for source, item in verified.items()
                )
                if [tuple(row) for row in stored_receipts] != intended_receipts:
                    raise ValidationError(
                        "stored reconciliation source receipts are incomplete or corrupt; fields/payload binding is invalid"
                    )
        return {
            **record,
            "digest": digest,
            "allowedToClose": status == "CLOSED",
            "reason": None if status == "CLOSED" else reasons[0],
        }
