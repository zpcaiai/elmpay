"""Enterprise treasury cash pooling, virtual sub-accounts, and automated sweeping engine."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
import uuid

from .common import ValidationError, require_text
from .durable import DurableStore


def _current(now: datetime | None = None) -> datetime:
    return now or datetime.now(timezone.utc)


class TreasuryPoolManager:
    """Manages multi-entity treasury cash pools, virtual sub-accounts, and automated sweeping."""

    def __init__(self, store_or_db: DurableStore | Path | str) -> None:
        if isinstance(store_or_db, DurableStore):
            self.store = store_or_db
        else:
            self.store = DurableStore(Path(store_or_db))

    def create_pool(
        self,
        tenant_id: str,
        *,
        pool_name: str,
        master_account_id: str,
        currency: str = "CNY",
        initial_master_balance_minor: int = 0,
        pool_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Initialize a master corporate treasury cash pool."""
        require_text(tenant_id, "tenant_id")
        require_text(pool_name, "pool_name")
        require_text(master_account_id, "master_account_id")

        if not isinstance(initial_master_balance_minor, int) or initial_master_balance_minor < 0:
            raise ValidationError("initial_master_balance_minor must be a non-negative integer")

        pid = pool_id or f"POOL_{uuid.uuid4().hex[:12]}"
        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            existing = conn.execute(
                "SELECT pool_id FROM treasury_pool WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
            if existing:
                raise ValidationError(f"treasury pool already exists for tenant '{tenant_id}'")

            conn.execute(
                "INSERT INTO treasury_pool("
                "pool_id, tenant_id, pool_name, master_account_id, master_balance_minor, currency, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (pid, tenant_id, pool_name, master_account_id, initial_master_balance_minor, currency, now_iso, now_iso),
            )

        return self.get_pool_status(tenant_id, pid)

    def create_virtual_account(
        self,
        tenant_id: str,
        pool_id: str,
        *,
        account_number: str,
        account_name: str,
        entity_type: str = "STORE",
        sweep_policy: str = "ZERO_BALANCE",
        target_balance_minor: int = 0,
        initial_balance_minor: int = 0,
        va_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Create a virtual sub-account with an automated sweeping policy."""
        require_text(tenant_id, "tenant_id")
        require_text(pool_id, "pool_id")
        require_text(account_number, "account_number")
        require_text(account_name, "account_name")

        valid_entities = {"STORE", "BRANCH", "DISTRIBUTOR", "MERCHANT"}
        if entity_type not in valid_entities:
            raise ValidationError(f"invalid entity_type '{entity_type}', expected one of {sorted(valid_entities)}")

        valid_policies = {"ZERO_BALANCE", "TARGET_BALANCE", "MANUAL"}
        if sweep_policy not in valid_policies:
            raise ValidationError(f"invalid sweep_policy '{sweep_policy}', expected one of {sorted(valid_policies)}")

        if not isinstance(target_balance_minor, int) or target_balance_minor < 0:
            raise ValidationError("target_balance_minor must be non-negative integer")
        if not isinstance(initial_balance_minor, int) or initial_balance_minor < 0:
            raise ValidationError("initial_balance_minor must be non-negative integer")

        sub_id = va_id or f"VA_{uuid.uuid4().hex[:12]}"
        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            pool = conn.execute(
                "SELECT * FROM treasury_pool WHERE tenant_id=? AND pool_id=?",
                (tenant_id, pool_id),
            ).fetchone()
            if not pool:
                raise ValidationError(f"treasury pool '{pool_id}' not found")

            conn.execute(
                "INSERT INTO treasury_virtual_account("
                "va_id, tenant_id, pool_id, account_number, account_name, entity_type, "
                "balance_minor, sweep_policy, target_balance_minor, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)",
                (
                    sub_id,
                    tenant_id,
                    pool_id,
                    account_number,
                    account_name,
                    entity_type,
                    initial_balance_minor,
                    sweep_policy,
                    target_balance_minor,
                    now_iso,
                    now_iso,
                ),
            )

        return self.get_virtual_account(tenant_id, sub_id)

    def deposit_to_virtual_account(
        self,
        tenant_id: str,
        pool_id: str,
        va_id: str,
        amount_minor: int,
        *,
        actor_id: str = "system",
        notes: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Deposit incoming revenue funds into a virtual sub-account."""
        if not isinstance(amount_minor, int) or amount_minor <= 0:
            raise ValidationError("deposit amount_minor must be a positive integer")

        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            va = conn.execute(
                "SELECT * FROM treasury_virtual_account WHERE tenant_id=? AND pool_id=? AND va_id=?",
                (tenant_id, pool_id, va_id),
            ).fetchone()
            if not va:
                raise ValidationError(f"virtual account '{va_id}' not found")
            if va["status"] != "ACTIVE":
                raise ValidationError(f"virtual account '{va_id}' is not active")

            new_bal = va["balance_minor"] + amount_minor
            conn.execute(
                "UPDATE treasury_virtual_account SET balance_minor=?, updated_at=? WHERE va_id=?",
                (new_bal, now_iso, va_id),
            )

            jid = f"JRN_{uuid.uuid4().hex[:12]}"
            conn.execute(
                "INSERT INTO treasury_transfer_journal("
                "journal_id, tenant_id, pool_id, source_account_id, dest_account_id, "
                "transfer_type, amount_minor, source_balance_after_minor, dest_balance_after_minor, "
                "actor_id, notes, created_at) "
                "VALUES (?, ?, ?, 'EXTERNAL_PAYMENT', ?, 'DEPOSIT', ?, 0, ?, ?, ?, ?)",
                (jid, tenant_id, pool_id, va_id, amount_minor, new_bal, actor_id, notes, now_iso),
            )

        return self.get_virtual_account(tenant_id, va_id)

    def execute_sweep(
        self,
        tenant_id: str,
        pool_id: str,
        *,
        va_id: str | None = None,
        actor_id: str = "treasury_sweeper",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Execute automated sweeping from virtual sub-accounts to master pool."""
        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        swept_transfers = []

        with self.store.transaction() as conn:
            pool = conn.execute(
                "SELECT * FROM treasury_pool WHERE tenant_id=? AND pool_id=?",
                (tenant_id, pool_id),
            ).fetchone()
            if not pool:
                raise ValidationError(f"treasury pool '{pool_id}' not found")

            # Check invariant before
            tot_sub_before = conn.execute(
                "SELECT SUM(balance_minor) as s FROM treasury_virtual_account WHERE tenant_id=? AND pool_id=?",
                (tenant_id, pool_id),
            ).fetchone()["s"] or 0
            pool_total_before = pool["master_balance_minor"] + tot_sub_before

            if va_id:
                sub_accounts = conn.execute(
                    "SELECT * FROM treasury_virtual_account WHERE tenant_id=? AND pool_id=? AND va_id=?",
                    (tenant_id, pool_id, va_id),
                ).fetchall()
            else:
                sub_accounts = conn.execute(
                    "SELECT * FROM treasury_virtual_account WHERE tenant_id=? AND pool_id=? AND status='ACTIVE'",
                    (tenant_id, pool_id),
                ).fetchall()

            current_master_bal = pool["master_balance_minor"]

            for sub in sub_accounts:
                bal = sub["balance_minor"]
                policy = sub["sweep_policy"]
                target = sub["target_balance_minor"]

                if policy == "ZERO_BALANCE":
                    sweep_amt = bal
                elif policy == "TARGET_BALANCE":
                    sweep_amt = max(0, bal - target)
                else:
                    sweep_amt = 0

                if sweep_amt <= 0:
                    continue

                new_sub_bal = bal - sweep_amt
                current_master_bal += sweep_amt

                conn.execute(
                    "UPDATE treasury_virtual_account SET balance_minor=?, updated_at=? WHERE va_id=?",
                    (new_sub_bal, now_iso, sub["va_id"]),
                )

                jid = f"JRN_{uuid.uuid4().hex[:12]}"
                conn.execute(
                    "INSERT INTO treasury_transfer_journal("
                    "journal_id, tenant_id, pool_id, source_account_id, dest_account_id, "
                    "transfer_type, amount_minor, source_balance_after_minor, dest_balance_after_minor, "
                    "actor_id, notes, created_at) "
                    "VALUES (?, ?, ?, ?, ?, 'SWEEP', ?, ?, ?, ?, ?, ?)",
                    (
                        jid,
                        tenant_id,
                        pool_id,
                        sub["va_id"],
                        pool["master_account_id"],
                        sweep_amt,
                        new_sub_bal,
                        current_master_bal,
                        actor_id,
                        f"Automated sweep via {policy}",
                        now_iso,
                    ),
                )
                swept_transfers.append({
                    "vaId": sub["va_id"],
                    "accountNumber": sub["account_number"],
                    "sweptAmountMinor": sweep_amt,
                    "subBalanceAfterMinor": new_sub_bal,
                    "masterBalanceAfterMinor": current_master_bal,
                })

            conn.execute(
                "UPDATE treasury_pool SET master_balance_minor=?, updated_at=? WHERE pool_id=?",
                (current_master_bal, now_iso, pool_id),
            )

            # Assert double-entry invariant after
            tot_sub_after = conn.execute(
                "SELECT SUM(balance_minor) as s FROM treasury_virtual_account WHERE tenant_id=? AND pool_id=?",
                (tenant_id, pool_id),
            ).fetchone()["s"] or 0
            pool_total_after = current_master_bal + tot_sub_after

            if pool_total_before != pool_total_after:
                raise ValidationError("double-entry mathematical conservation violated during sweep")

        status = self.get_pool_status(tenant_id, pool_id)
        status["sweptTransfers"] = swept_transfers
        return status

    def allocate_funds(
        self,
        tenant_id: str,
        pool_id: str,
        dest_va_id: str,
        amount_minor: int,
        *,
        actor_id: str = "treasury_allocator",
        notes: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Allocate operational advance funds from master pool to a virtual sub-account."""
        if not isinstance(amount_minor, int) or amount_minor <= 0:
            raise ValidationError("allocation amount_minor must be a positive integer")

        now_dt = _current(now)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            pool = conn.execute(
                "SELECT * FROM treasury_pool WHERE tenant_id=? AND pool_id=?",
                (tenant_id, pool_id),
            ).fetchone()
            if not pool:
                raise ValidationError(f"treasury pool '{pool_id}' not found")

            if pool["master_balance_minor"] < amount_minor:
                raise ValidationError(
                    f"insufficient master pool balance ({pool['master_balance_minor']}) for allocation of {amount_minor}"
                )

            va = conn.execute(
                "SELECT * FROM treasury_virtual_account WHERE tenant_id=? AND pool_id=? AND va_id=?",
                (tenant_id, pool_id, dest_va_id),
            ).fetchone()
            if not va:
                raise ValidationError(f"virtual account '{dest_va_id}' not found")

            new_master_bal = pool["master_balance_minor"] - amount_minor
            new_sub_bal = va["balance_minor"] + amount_minor

            conn.execute(
                "UPDATE treasury_pool SET master_balance_minor=?, updated_at=? WHERE pool_id=?",
                (new_master_bal, now_iso, pool_id),
            )
            conn.execute(
                "UPDATE treasury_virtual_account SET balance_minor=?, updated_at=? WHERE va_id=?",
                (new_sub_bal, now_iso, dest_va_id),
            )

            jid = f"JRN_{uuid.uuid4().hex[:12]}"
            conn.execute(
                "INSERT INTO treasury_transfer_journal("
                "journal_id, tenant_id, pool_id, source_account_id, dest_account_id, "
                "transfer_type, amount_minor, source_balance_after_minor, dest_balance_after_minor, "
                "actor_id, notes, created_at) "
                "VALUES (?, ?, ?, ?, ?, 'ALLOCATE', ?, ?, ?, ?, ?, ?)",
                (
                    jid,
                    tenant_id,
                    pool_id,
                    pool["master_account_id"],
                    dest_va_id,
                    amount_minor,
                    new_master_bal,
                    new_sub_bal,
                    actor_id,
                    notes,
                    now_iso,
                ),
            )

        return self.get_pool_status(tenant_id, pool_id)

    def get_virtual_account(self, tenant_id: str, va_id: str) -> dict[str, Any]:
        """Retrieve details of a virtual sub-account."""
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM treasury_virtual_account WHERE tenant_id=? AND va_id=?",
                (tenant_id, va_id),
            ).fetchone()
            if not row:
                raise ValidationError(f"virtual account '{va_id}' not found")

            return {
                "vaId": row["va_id"],
                "tenantId": row["tenant_id"],
                "poolId": row["pool_id"],
                "accountNumber": row["account_number"],
                "accountName": row["account_name"],
                "entityType": row["entity_type"],
                "balanceMinor": row["balance_minor"],
                "sweepPolicy": row["sweep_policy"],
                "targetBalanceMinor": row["target_balance_minor"],
                "status": row["status"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }

    def get_pool_status(self, tenant_id: str, pool_id: str) -> dict[str, Any]:
        """Query master treasury pool, virtual sub-accounts, total funds, and journal history."""
        with self.store.connect() as conn:
            pool = conn.execute(
                "SELECT * FROM treasury_pool WHERE tenant_id=? AND pool_id=?",
                (tenant_id, pool_id),
            ).fetchone()
            if not pool:
                raise ValidationError(f"treasury pool '{pool_id}' not found")

            vas = conn.execute(
                "SELECT * FROM treasury_virtual_account WHERE tenant_id=? AND pool_id=? ORDER BY account_number ASC",
                (tenant_id, pool_id),
            ).fetchall()

            journals = conn.execute(
                "SELECT * FROM treasury_transfer_journal WHERE tenant_id=? AND pool_id=? ORDER BY created_at DESC LIMIT 50",
                (tenant_id, pool_id),
            ).fetchall()

            master_bal = pool["master_balance_minor"]
            sub_bal = sum(v["balance_minor"] for v in vas)
            total_funds = master_bal + sub_bal

            return {
                "poolId": pool["pool_id"],
                "tenantId": pool["tenant_id"],
                "poolName": pool["pool_name"],
                "masterAccountId": pool["master_account_id"],
                "masterBalanceMinor": master_bal,
                "subAccountsTotalMinor": sub_bal,
                "totalPooledFundsMinor": total_funds,
                "currency": pool["currency"],
                "virtualAccountsCount": len(vas),
                "virtualAccounts": [
                    {
                        "vaId": v["va_id"],
                        "accountNumber": v["account_number"],
                        "accountName": v["account_name"],
                        "entityType": v["entity_type"],
                        "balanceMinor": v["balance_minor"],
                        "sweepPolicy": v["sweep_policy"],
                        "targetBalanceMinor": v["target_balance_minor"],
                        "status": v["status"],
                    }
                    for v in vas
                ],
                "recentJournals": [
                    {
                        "journalId": j["journal_id"],
                        "transferType": j["transfer_type"],
                        "sourceAccountId": j["source_account_id"],
                        "destAccountId": j["dest_account_id"],
                        "amountMinor": j["amount_minor"],
                        "sourceBalanceAfterMinor": j["source_balance_after_minor"],
                        "destBalanceAfterMinor": j["dest_balance_after_minor"],
                        "actorId": j["actor_id"],
                        "notes": j["notes"],
                        "createdAt": j["created_at"],
                    }
                    for j in journals
                ],
                "createdAt": pool["created_at"],
                "updatedAt": pool["updated_at"],
            }
