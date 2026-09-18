"""Enterprise Immutable Double-Entry Financial Ledger & Invariant Verification (B72-B73)."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence
import uuid

from .common import ValidationError, require_text, parse_instant
from .durable import DurableStore


def _current(now: datetime | None = None) -> datetime:
    return now or datetime.now(timezone.utc)


def _to_dt(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return parse_instant(value, field)


GENESIS_HASH = "0" * 64

STANDARD_CHART_OF_ACCOUNTS = {
    # Assets (Normal balance: DEBIT)
    "1001_CASH_IN_TRANSIT": {"name": "Cash In Transit", "category": "ASSET", "normal": "DEBIT"},
    "1002_SETTLEMENT_RECEIVABLE": {"name": "Settlement Receivable", "category": "ASSET", "normal": "DEBIT"},
    "1003_BANK_ACCOUNT": {"name": "Bank Operating Account", "category": "ASSET", "normal": "DEBIT"},
    # Liabilities (Normal balance: CREDIT)
    "2001_MERCHANT_PAYABLE": {"name": "Merchant Payable", "category": "LIABILITY", "normal": "CREDIT"},
    "2002_CUSTOMER_CREDIT": {"name": "Customer Credit Balance", "category": "LIABILITY", "normal": "CREDIT"},
    "2003_DISPUTE_RESERVE": {"name": "Dispute Reserve", "category": "LIABILITY", "normal": "CREDIT"},
    "2004_TAX_PAYABLE": {"name": "Tax Withholding Payable", "category": "LIABILITY", "normal": "CREDIT"},
    # Equity (Normal balance: CREDIT)
    "3001_RETAINED_EARNINGS": {"name": "Retained Earnings", "category": "EQUITY", "normal": "CREDIT"},
    # Revenue (Normal balance: CREDIT)
    "4001_PROCESSING_FEE_REVENUE": {"name": "Platform Processing Fee Revenue", "category": "REVENUE", "normal": "CREDIT"},
    # Expenses (Normal balance: DEBIT)
    "5001_INTERCHANGE_EXPENSE": {"name": "Interchange & Gateway Expense", "category": "EXPENSE", "normal": "DEBIT"},
    "5002_BAD_DEBT_EXPENSE": {"name": "Bad Debt & Unrecovered Chargeback", "category": "EXPENSE", "normal": "DEBIT"},
}


class FinancialDoubleEntryLedger:
    """Immutable double-entry financial ledger enforcing strict debit=credit balance, SHA-256 hash chaining, and trial balances."""

    def __init__(self, store_or_db: DurableStore | Path | str) -> None:
        if isinstance(store_or_db, DurableStore):
            self.store = store_or_db
        else:
            self.store = DurableStore(Path(store_or_db))

    def _canonical_legs_str(self, legs: Sequence[Any]) -> str:
        # Handle dict or sqlite3.Row
        def _field(item: Any, *keys: str) -> Any:
            for k in keys:
                try:
                    val = item[k]
                    if val is not None:
                        return val
                except (KeyError, IndexError, TypeError):
                    pass
            return None

        # Sort canonically for deterministic cryptographic hashing
        sorted_legs = sorted(
            legs,
            key=lambda l: (
                str(_field(l, "account_code", "accountCode")),
                str(_field(l, "direction")),
                int(_field(l, "amount_minor", "amountMinor")),
            ),
        )
        return json.dumps(
            [
                {
                    "accountCode": _field(l, "account_code", "accountCode"),
                    "direction": _field(l, "direction"),
                    "amountMinor": int(_field(l, "amount_minor", "amountMinor")),
                }
                for l in sorted_legs
            ],
            separators=(",", ":"),
            sort_keys=True,
        )

    def _compute_entry_hash(
        self,
        *,
        tenant_id: str,
        sequence_num: int,
        prev_entry_hash: str,
        entry_id: str,
        transaction_type: str,
        source_event_id: str,
        currency: str,
        total_amount_minor: int,
        legs: Sequence[Mapping[str, Any]],
        posted_at: str,
    ) -> str:
        canonical_legs = self._canonical_legs_str(legs)
        raw = f"{tenant_id}|{sequence_num}|{prev_entry_hash}|{entry_id}|{transaction_type}|{source_event_id}|{currency}|{total_amount_minor}|{canonical_legs}|{posted_at}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def post_journal_entry(
        self,
        tenant_id: str,
        *,
        transaction_type: str,
        source_event_id: str,
        currency: str,
        legs: Sequence[Mapping[str, Any]],
        entry_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Post an immutable, balanced double-entry transaction to the financial ledger."""
        require_text(tenant_id, "tenant_id")
        require_text(transaction_type, "transaction_type")
        require_text(source_event_id, "source_event_id")
        require_text(currency, "currency")

        if not legs or len(legs) < 2:
            raise ValidationError("A double-entry transaction must have at least 2 legs (debit and credit)")

        curr = currency.upper()
        now_iso = _current(now).isoformat()

        # Validate legs
        total_debits = 0
        total_credits = 0
        sanitized_legs = []

        for idx, leg in enumerate(legs):
            acct = require_text(leg.get("account_code") or leg.get("accountCode"), f"legs[{idx}].account_code")
            dirn = str(leg.get("direction", "")).upper()
            if dirn not in ("DEBIT", "CREDIT"):
                raise ValidationError(f"Invalid leg direction: '{dirn}'. Must be DEBIT or CREDIT")

            amt = leg.get("amount_minor")
            if amt is None:
                amt = leg.get("amountMinor")
            if not isinstance(amt, int) or amt <= 0:
                raise ValidationError(f"Leg amount must be a positive integer in minor units (got {amt})")

            if dirn == "DEBIT":
                total_debits += amt
            else:
                total_credits += amt

            sanitized_legs.append({
                "accountCode": acct,
                "direction": dirn,
                "amountMinor": amt,
            })

        # Double-entry invariant check
        if total_debits != total_credits:
            raise ValidationError(
                f"Double-entry imbalance: total debits ({total_debits}) != total credits ({total_credits})"
            )

        total_amount_minor = total_debits
        eid = entry_id or f"JRN_{uuid.uuid4().hex[:12]}"

        with self.store.transaction() as conn:
            # Idempotency check on source_event_id
            existing = conn.execute(
                "SELECT * FROM financial_double_entry_journal WHERE tenant_id=? AND source_event_id=?",
                (tenant_id, source_event_id),
            ).fetchone()
            if existing:
                existing_legs = conn.execute(
                    "SELECT * FROM financial_journal_leg WHERE entry_id=?",
                    (existing["entry_id"],),
                ).fetchall()
                return {
                    "entryId": existing["entry_id"],
                    "tenantId": existing["tenant_id"],
                    "sequenceNum": existing["sequence_num"],
                    "prevEntryHash": existing["prev_entry_hash"],
                    "entryHash": existing["entry_hash"],
                    "transactionType": existing["transaction_type"],
                    "sourceEventId": existing["source_event_id"],
                    "currency": existing["currency"],
                    "totalAmountMinor": existing["total_amount_minor"],
                    "postedAt": existing["posted_at"],
                    "legs": [
                        {"legId": l["leg_id"], "accountCode": l["account_code"], "direction": l["direction"], "amountMinor": l["amount_minor"]}
                        for l in existing_legs
                    ],
                    "isDuplicate": True,
                }

            # Monotonic sequence & hash chain
            last_entry = conn.execute(
                "SELECT sequence_num, entry_hash FROM financial_double_entry_journal "
                "WHERE tenant_id=? ORDER BY sequence_num DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()

            if last_entry:
                seq_num = last_entry["sequence_num"] + 1
                prev_hash = last_entry["entry_hash"]
            else:
                seq_num = 1
                prev_hash = GENESIS_HASH

            entry_hash = self._compute_entry_hash(
                tenant_id=tenant_id,
                sequence_num=seq_num,
                prev_entry_hash=prev_hash,
                entry_id=eid,
                transaction_type=transaction_type,
                source_event_id=source_event_id,
                currency=curr,
                total_amount_minor=total_amount_minor,
                legs=sanitized_legs,
                posted_at=now_iso,
            )

            conn.execute(
                "INSERT INTO financial_double_entry_journal ("
                "  entry_id, tenant_id, sequence_num, prev_entry_hash, entry_hash, transaction_type, "
                "  source_event_id, currency, total_amount_minor, posted_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    eid,
                    tenant_id,
                    seq_num,
                    prev_hash,
                    entry_hash,
                    transaction_type,
                    source_event_id,
                    curr,
                    total_amount_minor,
                    now_iso,
                ),
            )

            created_legs = []
            for sleg in sanitized_legs:
                leg_id = f"LEG_{uuid.uuid4().hex[:12]}"
                conn.execute(
                    "INSERT INTO financial_journal_leg (leg_id, entry_id, account_code, direction, amount_minor) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (leg_id, eid, sleg["accountCode"], sleg["direction"], sleg["amountMinor"]),
                )
                created_legs.append({
                    "legId": leg_id,
                    "accountCode": sleg["accountCode"],
                    "direction": sleg["direction"],
                    "amountMinor": sleg["amountMinor"],
                })

        return {
            "entryId": eid,
            "tenantId": tenant_id,
            "sequenceNum": seq_num,
            "prevEntryHash": prev_hash,
            "entryHash": entry_hash,
            "transactionType": transaction_type,
            "sourceEventId": source_event_id,
            "currency": curr,
            "totalAmountMinor": total_amount_minor,
            "postedAt": now_iso,
            "legs": created_legs,
            "isDuplicate": False,
        }

    def reverse_journal_entry(
        self,
        tenant_id: str,
        *,
        original_entry_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Post a full reversal of an existing journal entry (swap DEBIT <-> CREDIT)."""
        require_text(tenant_id, "tenant_id")
        require_text(original_entry_id, "original_entry_id")
        require_text(reason, "reason")

        with self.store.connect() as conn:
            orig = conn.execute(
                "SELECT * FROM financial_double_entry_journal WHERE tenant_id=? AND entry_id=?",
                (tenant_id, original_entry_id),
            ).fetchone()
            if not orig:
                raise ValidationError(f"Journal entry '{original_entry_id}' not found")

            orig_legs = conn.execute(
                "SELECT * FROM financial_journal_leg WHERE entry_id=?",
                (original_entry_id,),
            ).fetchall()

        reversal_legs = []
        for l in orig_legs:
            reversal_legs.append({
                "accountCode": l["account_code"],
                "direction": "CREDIT" if l["direction"] == "DEBIT" else "DEBIT",
                "amountMinor": l["amount_minor"],
            })

        rev_source_event = f"REV_{orig['source_event_id']}_{uuid.uuid4().hex[:6]}"
        return self.post_journal_entry(
            tenant_id,
            transaction_type="REVERSAL",
            source_event_id=rev_source_event,
            currency=orig["currency"],
            legs=reversal_legs,
            now=now,
        )

    def verify_chain_integrity(self, tenant_id: str) -> dict[str, Any]:
        """Verify the cryptographic hash chain and internal balance across all entries for a tenant."""
        require_text(tenant_id, "tenant_id")

        with self.store.connect() as conn:
            entries = conn.execute(
                "SELECT * FROM financial_double_entry_journal WHERE tenant_id=? ORDER BY sequence_num ASC",
                (tenant_id,),
            ).fetchall()

            if not entries:
                return {"valid": True, "entriesAudited": 0, "issues": []}

            issues = []
            expected_prev_hash = GENESIS_HASH

            for idx, entry in enumerate(entries):
                expected_seq = idx + 1
                seq = entry["sequence_num"]
                eid = entry["entry_id"]

                if seq != expected_seq:
                    issues.append(f"Entry {eid} sequence discontinuity: expected {expected_seq}, found {seq}")

                if entry["prev_entry_hash"] != expected_prev_hash:
                    issues.append(
                        f"Entry {eid} prev_entry_hash mismatch: expected {expected_prev_hash}, found {entry['prev_entry_hash']}"
                    )

                legs = conn.execute(
                    "SELECT account_code, direction, amount_minor FROM financial_journal_leg WHERE entry_id=?",
                    (eid,),
                ).fetchall()

                debits = sum(l["amount_minor"] for l in legs if l["direction"] == "DEBIT")
                credits = sum(l["amount_minor"] for l in legs if l["direction"] == "CREDIT")

                if debits != credits:
                    issues.append(f"Entry {eid} imbalance: debits ({debits}) != credits ({credits})")
                if debits != entry["total_amount_minor"]:
                    issues.append(f"Entry {eid} total_amount_minor mismatch: header {entry['total_amount_minor']} vs debits {debits}")

                # Recompute hash
                recomputed_hash = self._compute_entry_hash(
                    tenant_id=tenant_id,
                    sequence_num=seq,
                    prev_entry_hash=entry["prev_entry_hash"],
                    entry_id=eid,
                    transaction_type=entry["transaction_type"],
                    source_event_id=entry["source_event_id"],
                    currency=entry["currency"],
                    total_amount_minor=entry["total_amount_minor"],
                    legs=legs,
                    posted_at=entry["posted_at"],
                )

                if recomputed_hash != entry["entry_hash"]:
                    issues.append(f"Entry {eid} cryptographic hash tampering: expected {entry['entry_hash']}, computed {recomputed_hash}")

                expected_prev_hash = entry["entry_hash"]

            return {
                "valid": len(issues) == 0,
                "entriesAudited": len(entries),
                "issues": issues,
            }

    def generate_trial_balance(
        self,
        tenant_id: str,
        *,
        as_of: str | datetime | None = None,
    ) -> dict[str, Any]:
        """Generate a double-entry Trial Balance report verifying total debits == total credits across all accounts."""
        require_text(tenant_id, "tenant_id")

        as_of_dt = _to_dt(as_of, "as_of") if as_of else _current()
        as_of_iso = as_of_dt.isoformat()

        with self.store.connect() as conn:
            query = (
                "SELECT l.account_code, l.direction, SUM(l.amount_minor) as sum_amt, j.currency "
                "FROM financial_journal_leg l "
                "JOIN financial_double_entry_journal j ON l.entry_id = j.entry_id "
                "WHERE j.tenant_id = ? AND j.posted_at <= ? "
                "GROUP BY l.account_code, l.direction, j.currency"
            )
            rows = conn.execute(query, (tenant_id, as_of_iso)).fetchall()

        # Group by currency
        balances_by_currency: dict[str, dict[str, Any]] = {}

        for row in rows:
            curr = row["currency"]
            if curr not in balances_by_currency:
                balances_by_currency[curr] = {
                    "totalDebitsMinor": 0,
                    "totalCreditsMinor": 0,
                    "accounts": {},
                }

            acct = row["account_code"]
            dirn = row["direction"]
            amt = int(row["sum_amt"])

            curr_dict = balances_by_currency[curr]
            if acct not in curr_dict["accounts"]:
                coa_info = STANDARD_CHART_OF_ACCOUNTS.get(acct, {"name": acct, "category": "OTHER", "normal": "DEBIT"})
                curr_dict["accounts"][acct] = {
                    "accountCode": acct,
                    "accountName": coa_info["name"],
                    "category": coa_info["category"],
                    "normalDirection": coa_info["normal"],
                    "debitMinor": 0,
                    "creditMinor": 0,
                    "netBalanceMinor": 0,
                }

            acct_data = curr_dict["accounts"][acct]
            if dirn == "DEBIT":
                acct_data["debitMinor"] += amt
                curr_dict["totalDebitsMinor"] += amt
            else:
                acct_data["creditMinor"] += amt
                curr_dict["totalCreditsMinor"] += amt

        # Compute net balances per account
        reports = []
        is_all_balanced = True

        for curr, data in balances_by_currency.items():
            tot_debits = data["totalDebitsMinor"]
            tot_credits = data["totalCreditsMinor"]
            is_balanced = (tot_debits == tot_credits)
            if not is_balanced:
                is_all_balanced = False

            account_list = []
            for acct, acct_data in sorted(data["accounts"].items()):
                # If normal direction is DEBIT: net = debit - credit
                # If normal direction is CREDIT: net = credit - debit
                if acct_data["normalDirection"] == "DEBIT":
                    acct_data["netBalanceMinor"] = acct_data["debitMinor"] - acct_data["creditMinor"]
                else:
                    acct_data["netBalanceMinor"] = acct_data["creditMinor"] - acct_data["debitMinor"]
                account_list.append(acct_data)

            reports.append({
                "currency": curr,
                "totalDebitsMinor": tot_debits,
                "totalCreditsMinor": tot_credits,
                "isBalanced": is_balanced,
                "differenceMinor": abs(tot_debits - tot_credits),
                "accounts": account_list,
            })

        return {
            "tenantId": tenant_id,
            "asOf": as_of_iso,
            "isBalanced": is_all_balanced,
            "currenciesCount": len(reports),
            "reports": reports,
        }

    def get_account_balance(
        self,
        tenant_id: str,
        *,
        account_code: str,
        currency: str,
        as_of: str | datetime | None = None,
    ) -> dict[str, Any]:
        """Fetch balance summary for a specific account."""
        require_text(tenant_id, "tenant_id")
        require_text(account_code, "account_code")
        require_text(currency, "currency")

        tb = self.generate_trial_balance(tenant_id, as_of=as_of)
        curr = currency.upper()

        for rep in tb.get("reports", []):
            if rep["currency"] == curr:
                for acct in rep["accounts"]:
                    if acct["accountCode"] == account_code:
                        return {
                            "tenantId": tenant_id,
                            "accountCode": account_code,
                            "currency": curr,
                            "debitMinor": acct["debitMinor"],
                            "creditMinor": acct["creditMinor"],
                            "netBalanceMinor": acct["netBalanceMinor"],
                            "normalDirection": acct["normalDirection"],
                            "category": acct["category"],
                        }

        coa_info = STANDARD_CHART_OF_ACCOUNTS.get(account_code, {"name": account_code, "category": "OTHER", "normal": "DEBIT"})
        return {
            "tenantId": tenant_id,
            "accountCode": account_code,
            "currency": curr,
            "debitMinor": 0,
            "creditMinor": 0,
            "netBalanceMinor": 0,
            "normalDirection": coa_info["normal"],
            "category": coa_info["category"],
        }
