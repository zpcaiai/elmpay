from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

# Ensure tools/runtime is accessible for direct import
RUNTIME_DIR = Path(__file__).resolve().parents[1] / "tools" / "runtime"
if str(RUNTIME_DIR) not in sys.path:
    sys.path.insert(0, str(RUNTIME_DIR))

from tools.runtime.elmpay_runtime.common import ValidationError
from tools.runtime.elmpay_runtime.durable import DurableStore
from tools.runtime.elmpay_runtime.subscription_proration import SubscriptionProrationEngine
from tools.runtime.elmpay_runtime.financial_ledger import (
    FinancialDoubleEntryLedger,
    GENESIS_HASH,
    STANDARD_CHART_OF_ACCOUNTS,
)


class TestEnterpriseProrationLedgerE3E4(unittest.TestCase):
    """Rigorous E3 and E4 test suite for subscription proration, credit wallet, and double-entry general ledger."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_proration_ledger.db"
        self.store = DurableStore(self.db_path)
        self.sub_engine = SubscriptionProrationEngine(self.store)
        self.fin_ledger = FinancialDoubleEntryLedger(self.store)
        self.tenant_id = "TENANT_CORP_01"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # E3: Functional, State Transitions & Financial Math Invariants
    # -------------------------------------------------------------------------

    def test_e3_plan_creation_and_validation(self) -> None:
        """Verify plan registration, interval checking, and duplicate prevention."""
        p1 = self.sub_engine.create_plan(
            self.tenant_id,
            plan_code="STARTER_MONTHLY",
            name="Starter Plan Monthly",
            billing_interval="MONTHLY",
            amount_minor=9900,
            currency="CNY",
        )
        self.assertEqual(p1["planCode"], "STARTER_MONTHLY")
        self.assertEqual(p1["amountMinor"], 9900)
        self.assertEqual(p1["billingInterval"], "MONTHLY")

        # Duplicate plan code in same tenant fails
        with self.assertRaises(ValidationError):
            self.sub_engine.create_plan(
                self.tenant_id,
                plan_code="STARTER_MONTHLY",
                name="Duplicate",
                billing_interval="MONTHLY",
                amount_minor=5000,
                currency="CNY",
            )

        # Invalid interval fails
        with self.assertRaises(ValidationError):
            self.sub_engine.create_plan(
                self.tenant_id,
                plan_code="INVALID_INTERVAL",
                name="Bad Interval",
                billing_interval="BIWEEKLY",
                amount_minor=1000,
                currency="CNY",
            )

        # Cross-tenant same plan code succeeds
        p2 = self.sub_engine.create_plan(
            "TENANT_OTHER",
            plan_code="STARTER_MONTHLY",
            name="Other Tenant Starter",
            billing_interval="MONTHLY",
            amount_minor=12000,
            currency="CNY",
        )
        self.assertEqual(p2["tenantId"], "TENANT_OTHER")

    def test_e3_subscription_lifecycle_pause_resume(self) -> None:
        """Verify subscription creation, pause, and resume state transitions."""
        plan = self.sub_engine.create_plan(
            self.tenant_id,
            plan_code="PRO_ANNUAL",
            name="Pro Annual",
            billing_interval="ANNUAL",
            amount_minor=120000,
            currency="USD",
        )

        now = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        sub = self.sub_engine.create_subscription(
            self.tenant_id,
            customer_id="CUST_100",
            plan_id=plan["planId"],
            current_period_start=now,
            current_period_end=now + timedelta(days=365),
        )
        self.assertEqual(sub["status"], "ACTIVE")

        # Pause subscription
        paused = self.sub_engine.pause_subscription(self.tenant_id, sub["subscriptionId"])
        self.assertEqual(paused["status"], "PAUSED")

        # Cannot pause already paused
        with self.assertRaises(ValidationError):
            self.sub_engine.pause_subscription(self.tenant_id, sub["subscriptionId"])

        # Resume subscription
        resumed = self.sub_engine.resume_subscription(self.tenant_id, sub["subscriptionId"])
        self.assertEqual(resumed["status"], "ACTIVE")

    def test_e3_mid_cycle_proration_upgrade(self) -> None:
        """Mid-cycle plan upgrade: exact integer calculation of unused old credit and new charge."""
        # Old plan: 1,000 minor ($10.00) / 30 days
        plan_basic = self.sub_engine.create_plan(
            self.tenant_id,
            plan_code="BASIC_30D",
            name="Basic 30-Day",
            billing_interval="MONTHLY",
            amount_minor=1000,
            currency="USD",
        )
        # New plan: 3,000 minor ($30.00) / 30 days
        plan_pro = self.sub_engine.create_plan(
            self.tenant_id,
            plan_code="PRO_30D",
            name="Pro 30-Day",
            billing_interval="MONTHLY",
            amount_minor=3000,
            currency="USD",
        )

        t0 = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(days=30)  # Total 30 days = 2,592,000 seconds
        sub = self.sub_engine.create_subscription(
            self.tenant_id,
            customer_id="CUST_UPGRADE",
            plan_id=plan_basic["planId"],
            current_period_start=t0,
            current_period_end=t1,
        )

        # Upgrade exactly halfway through: 15 days elapsed (50% remaining)
        t_upgrade = t0 + timedelta(days=15)
        adj = self.sub_engine.change_plan(
            self.tenant_id,
            subscription_id=sub["subscriptionId"],
            new_plan_id=plan_pro["planId"],
            effective_at=t_upgrade,
        )

        self.assertEqual(adj["changeType"], "UPGRADE")
        self.assertEqual(adj["unusedOldCreditMinor"], 500)  # 1000 * 15/30 = 500
        self.assertEqual(adj["newPlanChargeMinor"], 1500)   # 3000 * 15/30 = 1500
        self.assertEqual(adj["netPayableMinor"], 1000)      # 1500 - 500 = 1000
        self.assertEqual(adj["creditBalanceAppliedMinor"], 0)
        self.assertEqual(adj["finalChargeDueMinor"], 1000)
        self.assertEqual(adj["creditRefundedToWalletMinor"], 0)

        # Verify subscription record points to new plan
        sub_updated = self.sub_engine.get_subscription(self.tenant_id, sub["subscriptionId"])
        self.assertEqual(sub_updated["planId"], plan_pro["planId"])

    def test_e3_mid_cycle_proration_downgrade_with_wallet_credit(self) -> None:
        """Mid-cycle plan downgrade: excess unused old credit credited to customer wallet."""
        plan_pro = self.sub_engine.create_plan(
            self.tenant_id,
            plan_code="PRO_TIER",
            name="Pro Tier",
            billing_interval="MONTHLY",
            amount_minor=3000,
            currency="CNY",
        )
        plan_basic = self.sub_engine.create_plan(
            self.tenant_id,
            plan_code="BASIC_TIER",
            name="Basic Tier",
            billing_interval="MONTHLY",
            amount_minor=1000,
            currency="CNY",
        )

        t0 = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(days=30)
        sub = self.sub_engine.create_subscription(
            self.tenant_id,
            customer_id="CUST_DOWNGRADE",
            plan_id=plan_pro["planId"],
            current_period_start=t0,
            current_period_end=t1,
        )

        # Downgrade at day 15 (50% remaining)
        t_downgrade = t0 + timedelta(days=15)
        adj = self.sub_engine.change_plan(
            self.tenant_id,
            subscription_id=sub["subscriptionId"],
            new_plan_id=plan_basic["planId"],
            effective_at=t_downgrade,
        )

        self.assertEqual(adj["changeType"], "DOWNGRADE")
        self.assertEqual(adj["unusedOldCreditMinor"], 1500)  # 3000 * 15/30 = 1500
        self.assertEqual(adj["newPlanChargeMinor"], 500)    # 1000 * 15/30 = 500
        self.assertEqual(adj["netPayableMinor"], -1000)     # 500 - 1500 = -1000
        self.assertEqual(adj["finalChargeDueMinor"], 0)
        self.assertEqual(adj["creditRefundedToWalletMinor"], 1000)

        # Customer wallet now has 1,000 minor in credit balance
        wallet_bal = self.sub_engine.get_customer_credit_balance(self.tenant_id, "CUST_DOWNGRADE", "CNY")
        self.assertEqual(wallet_bal, 1000)

    def test_e3_future_upgrade_auto_consumes_credit_wallet(self) -> None:
        """Future upgrade automatically deducts from customer credit balance wallet."""
        # Seed customer with 800 minor credit
        self.sub_engine.grant_customer_credit(
            self.tenant_id,
            customer_id="CUST_WALLET_TEST",
            amount_minor=800,
            currency="CNY",
            reason="Promotional Credit Bonus",
        )
        self.assertEqual(
            self.sub_engine.get_customer_credit_balance(self.tenant_id, "CUST_WALLET_TEST", "CNY"),
            800,
        )

        p1 = self.sub_engine.create_plan(self.tenant_id, plan_code="P1", name="P1", billing_interval="MONTHLY", amount_minor=1000, currency="CNY")
        p2 = self.sub_engine.create_plan(self.tenant_id, plan_code="P2", name="P2", billing_interval="MONTHLY", amount_minor=3000, currency="CNY")

        t0 = datetime(2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(days=30)
        sub = self.sub_engine.create_subscription(
            self.tenant_id,
            customer_id="CUST_WALLET_TEST",
            plan_id=p1["planId"],
            current_period_start=t0,
            current_period_end=t1,
        )

        # Upgrade at day 15: net charge required = 1000 minor.
        # Customer has 800 minor in wallet: 800 applied, final charge due = 200 minor!
        t_up = t0 + timedelta(days=15)
        adj = self.sub_engine.change_plan(
            self.tenant_id,
            subscription_id=sub["subscriptionId"],
            new_plan_id=p2["planId"],
            effective_at=t_up,
            allow_credit_deduction=True,
        )

        self.assertEqual(adj["netPayableMinor"], 1000)
        self.assertEqual(adj["creditBalanceAppliedMinor"], 800)
        self.assertEqual(adj["finalChargeDueMinor"], 200)

        # Wallet is now drained to 0
        rem_bal = self.sub_engine.get_customer_credit_balance(self.tenant_id, "CUST_WALLET_TEST", "CNY")
        self.assertEqual(rem_bal, 0)

    def test_e3_cancel_at_period_end_vs_immediate_prorated(self) -> None:
        """Cancel subscription: test period end vs immediate prorated refund."""
        plan = self.sub_engine.create_plan(
            self.tenant_id,
            plan_code="SUB_CANCEL_PLAN",
            name="Cancel Test Plan",
            billing_interval="MONTHLY",
            amount_minor=6000,
            currency="CNY",
        )

        t0 = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(days=30)

        # 1. Cancel at period end
        sub1 = self.sub_engine.create_subscription(
            self.tenant_id,
            customer_id="CUST_C1",
            plan_id=plan["planId"],
            current_period_start=t0,
            current_period_end=t1,
        )
        res1 = self.sub_engine.cancel_subscription(self.tenant_id, subscription_id=sub1["subscriptionId"], immediate=False)
        self.assertTrue(res1["cancelAtPeriodEnd"])
        self.assertEqual(res1["status"], "ACTIVE")

        # 2. Immediate cancel with prorated refund at day 20 (10 days / 33.33% remaining)
        sub2 = self.sub_engine.create_subscription(
            self.tenant_id,
            customer_id="CUST_C2",
            plan_id=plan["planId"],
            current_period_start=t0,
            current_period_end=t1,
        )
        t_cancel = t0 + timedelta(days=20)
        res2 = self.sub_engine.cancel_subscription(
            self.tenant_id,
            subscription_id=sub2["subscriptionId"],
            immediate=True,
            refund_prorated=True,
            effective_at=t_cancel,
        )
        self.assertEqual(res2["status"], "CANCELED")
        self.assertEqual(res2["refundedMinor"], 2000)  # 6000 * 10/30 = 2000

        # Customer wallet has 2000 minor credited
        c2_bal = self.sub_engine.get_customer_credit_balance(self.tenant_id, "CUST_C2", "CNY")
        self.assertEqual(c2_bal, 2000)

    def test_e3_double_entry_balanced_payment_capture(self) -> None:
        """Double-entry ledger: payment capture with revenue recognition and merchant liability."""
        legs = [
            {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 10000},
            {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 9700},
            {"accountCode": "4001_PROCESSING_FEE_REVENUE", "direction": "CREDIT", "amountMinor": 300},
        ]
        entry = self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="PAYMENT_CAPTURED",
            source_event_id="EVT_PAY_001",
            currency="CNY",
            legs=legs,
        )

        self.assertEqual(entry["sequenceNum"], 1)
        self.assertEqual(entry["prevEntryHash"], GENESIS_HASH)
        self.assertEqual(len(entry["entryHash"]), 64)
        self.assertEqual(entry["totalAmountMinor"], 10000)

        # Integrity verification
        audit = self.fin_ledger.verify_chain_integrity(self.tenant_id)
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["entriesAudited"], 1)

        # Trial balance
        tb = self.fin_ledger.generate_trial_balance(self.tenant_id)
        self.assertTrue(tb["isBalanced"])
        rep = tb["reports"][0]
        self.assertEqual(rep["currency"], "CNY")
        self.assertEqual(rep["totalDebitsMinor"], 10000)
        self.assertEqual(rep["totalCreditsMinor"], 10000)
        self.assertEqual(rep["differenceMinor"], 0)

    def test_e3_double_entry_hash_chain_and_reversal(self) -> None:
        """Verify continuous SHA-256 hash chaining and full accounting reversals."""
        # Entry 1: Payment Captured ($50.00)
        e1 = self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="PAYMENT_CAPTURED",
            source_event_id="EVT_001",
            currency="USD",
            legs=[
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 5000},
                {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 5000},
            ],
        )
        self.assertEqual(e1["sequenceNum"], 1)

        # Entry 2: Bank Settlement ($50.00)
        e2 = self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="BANK_SETTLEMENT",
            source_event_id="EVT_002",
            currency="USD",
            legs=[
                {"accountCode": "1003_BANK_ACCOUNT", "direction": "DEBIT", "amountMinor": 5000},
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "CREDIT", "amountMinor": 5000},
            ],
        )
        self.assertEqual(e2["sequenceNum"], 2)
        self.assertEqual(e2["prevEntryHash"], e1["entryHash"])

        # Entry 3: Reversal of Entry 1
        rev = self.fin_ledger.reverse_journal_entry(
            self.tenant_id,
            original_entry_id=e1["entryId"],
            reason="Customer Chargeback / Fraud Reversal",
        )
        self.assertEqual(rev["sequenceNum"], 3)
        self.assertEqual(rev["prevEntryHash"], e2["entryHash"])
        self.assertEqual(rev["transactionType"], "REVERSAL")

        # Verify integrity of all 3 entries
        audit = self.fin_ledger.verify_chain_integrity(self.tenant_id)
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["entriesAudited"], 3)

        # Trial balance remains balanced
        tb = self.fin_ledger.generate_trial_balance(self.tenant_id)
        self.assertTrue(tb["isBalanced"])

    def test_e3_trial_balance_sheet_multi_currency(self) -> None:
        """Trial balance maintains separate exact balance sheets for multiple currencies."""
        # CNY transaction
        self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="CNY_SALE",
            source_event_id="SALE_CNY",
            currency="CNY",
            legs=[
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 8800},
                {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 8800},
            ],
        )
        # EUR transaction
        self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="EUR_SALE",
            source_event_id="SALE_EUR",
            currency="EUR",
            legs=[
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 4200},
                {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 4200},
            ],
        )

        tb = self.fin_ledger.generate_trial_balance(self.tenant_id)
        self.assertTrue(tb["isBalanced"])
        self.assertEqual(tb["currenciesCount"], 2)

        cny_rep = next(r for r in tb["reports"] if r["currency"] == "CNY")
        self.assertEqual(cny_rep["totalDebitsMinor"], 8800)
        self.assertEqual(cny_rep["totalCreditsMinor"], 8800)
        self.assertTrue(cny_rep["isBalanced"])

        eur_rep = next(r for r in tb["reports"] if r["currency"] == "EUR")
        self.assertEqual(eur_rep["totalDebitsMinor"], 4200)
        self.assertEqual(eur_rep["totalCreditsMinor"], 4200)
        self.assertTrue(eur_rep["isBalanced"])

    # -------------------------------------------------------------------------
    # E4: Concurrency, Fault Injection, Tampering & Security Boundaries
    # -------------------------------------------------------------------------

    def test_e4_debit_credit_imbalance_fail_closed(self) -> None:
        """Fail-closed: entry where Debits != Credits must be rejected with ValidationError."""
        unbalanced_legs = [
            {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 10000},
            {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 9500},
            # Missing 500 minor on credit side!
        ]
        with self.assertRaises(ValidationError) as ctx:
            self.fin_ledger.post_journal_entry(
                self.tenant_id,
                transaction_type="BAD_TRANSACTION",
                source_event_id="BAD_001",
                currency="USD",
                legs=unbalanced_legs,
            )
        self.assertIn("Double-entry imbalance", str(ctx.exception))

        # Ledger remains empty; sequence unchanged
        audit = self.fin_ledger.verify_chain_integrity(self.tenant_id)
        self.assertEqual(audit["entriesAudited"], 0)

    def test_e4_negative_leg_amount_fail_closed(self) -> None:
        """Fail-closed: negative leg amount must be rejected."""
        negative_legs = [
            {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": -500},
            {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": -500},
        ]
        with self.assertRaises(ValidationError):
            self.fin_ledger.post_journal_entry(
                self.tenant_id,
                transaction_type="NEGATIVE_TX",
                source_event_id="NEG_001",
                currency="CNY",
                legs=negative_legs,
            )

    def test_e4_hash_chain_tampering_detection(self) -> None:
        """Security: deliberate tampering with a ledger entry must be caught by chain integrity audit."""
        # Post two valid entries
        e1 = self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="TX1",
            source_event_id="S1",
            currency="CNY",
            legs=[
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 1000},
                {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 1000},
            ],
        )
        e2 = self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="TX2",
            source_event_id="S2",
            currency="CNY",
            legs=[
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 2000},
                {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 2000},
            ],
        )

        # Integrity passes initially
        self.assertTrue(self.fin_ledger.verify_chain_integrity(self.tenant_id)["valid"])

        # Tamper directly with the database: corrupt e1 entry_hash
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE financial_double_entry_journal SET entry_hash=? WHERE entry_id=?",
                ("a" * 64, e1["entryId"]),
            )

        # Chain audit must now detect the tampering
        tampered_audit = self.fin_ledger.verify_chain_integrity(self.tenant_id)
        self.assertFalse(tampered_audit["valid"])
        self.assertTrue(any("cryptographic hash tampering" in issue for issue in tampered_audit["issues"]))

    def test_e4_idempotent_source_event_deduplication(self) -> None:
        """Idempotency: duplicate source_event_id returns original entry without re-posting."""
        legs = [
            {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 5000},
            {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 5000},
        ]
        first = self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="SALE",
            source_event_id="UNIQUE_EVENT_123",
            currency="USD",
            legs=legs,
        )
        self.assertFalse(first["isDuplicate"])
        self.assertEqual(first["sequenceNum"], 1)

        second = self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="SALE",
            source_event_id="UNIQUE_EVENT_123",
            currency="USD",
            legs=legs,
        )
        self.assertTrue(second["isDuplicate"])
        self.assertEqual(second["entryId"], first["entryId"])
        self.assertEqual(second["sequenceNum"], 1)

        # Audit still sees only 1 entry
        audit = self.fin_ledger.verify_chain_integrity(self.tenant_id)
        self.assertEqual(audit["entriesAudited"], 1)

    def test_e4_multi_threaded_concurrent_proration_and_ledger_stress(self) -> None:
        """Concurrency stress: 10 concurrent threads updating subscriptions and posting ledger transactions."""
        plan_a = self.sub_engine.create_plan(
            self.tenant_id, plan_code="TIER_A", name="Tier A", billing_interval="MONTHLY", amount_minor=1000, currency="CNY"
        )
        plan_b = self.sub_engine.create_plan(
            self.tenant_id, plan_code="TIER_B", name="Tier B", billing_interval="MONTHLY", amount_minor=2000, currency="CNY"
        )

        now = datetime.now(timezone.utc)
        subs = []
        for i in range(10):
            s = self.sub_engine.create_subscription(
                self.tenant_id,
                customer_id=f"CONC_CUST_{i}",
                plan_id=plan_a["planId"],
                current_period_start=now,
                current_period_end=now + timedelta(days=30),
            )
            subs.append(s["subscriptionId"])

        def worker_task(idx: int) -> None:
            # 1. Proration change
            self.sub_engine.change_plan(
                self.tenant_id,
                subscription_id=subs[idx],
                new_plan_id=plan_b["planId"],
            )
            # 2. Financial ledger entry
            self.fin_ledger.post_journal_entry(
                self.tenant_id,
                transaction_type="CONCURRENT_SALE",
                source_event_id=f"CONC_EVT_{idx}_{uuid.uuid4().hex[:6]}",
                currency="CNY",
                legs=[
                    {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 1000 * (idx + 1)},
                    {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 1000 * (idx + 1)},
                ],
            )

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(worker_task, i) for i in range(10)]
            for f in futures:
                f.result()

        # Verify all 10 subscriptions updated to TIER_B
        for s_id in subs:
            s_obj = self.sub_engine.get_subscription(self.tenant_id, s_id)
            self.assertEqual(s_obj["planId"], plan_b["planId"])

        # Verify ledger chain integrity across all 10 entries
        audit = self.fin_ledger.verify_chain_integrity(self.tenant_id)
        self.assertTrue(audit["valid"], f"Audit failed: {audit['issues']}")
        self.assertEqual(audit["entriesAudited"], 10)

        # Trial balance must be strictly balanced
        tb = self.fin_ledger.generate_trial_balance(self.tenant_id)
        self.assertTrue(tb["isBalanced"])

    def _run_cli(self, *args: str) -> tuple[int, str]:
        cmd = [sys.executable, "tools/runtime/control.py", *args]
        env = dict(os.environ)
        env["PYTHONPATH"] = f"tools/runtime:{env.get('PYTHONPATH', '')}"
        res = subprocess.run(cmd, capture_output=True, text=True, env=env)
        return res.returncode, res.stdout.strip()

    def test_e4_cli_controls_e2e(self) -> None:
        """CLI Control Plane: test subscription and double-entry ledger CLI execution."""
        # 1. subscription-plan-create CLI
        ret, out = self._run_cli(
            "subscription-plan-create",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--code", "CLI_PLAN_01",
            "--name", "CLI Created Plan",
            "--interval", "MONTHLY",
            "--amount-minor", "5000",
            "--currency", "CNY",
        )
        self.assertEqual(ret, 0, f"CLI plan create failed: {out}")
        p_data = json.loads(out)
        self.assertEqual(p_data["planCode"], "CLI_PLAN_01")
        plan_id = p_data["planId"]

        # 2. subscription-create CLI
        now = datetime.now(timezone.utc)
        t_end = now + timedelta(days=30)
        ret, out = self._run_cli(
            "subscription-create",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--customer-id", "CLI_CUST_1",
            "--plan-id", plan_id,
            "--start", now.isoformat(),
            "--end", t_end.isoformat(),
        )
        self.assertEqual(ret, 0, f"CLI sub create failed: {out}")
        sub_data = json.loads(out)
        sub_id = sub_data["subscriptionId"]

        # 3. subscription-credit-balance CLI
        ret, out = self._run_cli(
            "subscription-credit-balance",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--customer-id", "CLI_CUST_1",
            "--currency", "CNY",
        )
        self.assertEqual(ret, 0, f"CLI credit balance failed: {out}")
        bal_data = json.loads(out)
        self.assertEqual(bal_data["balanceMinor"], 0)

        # 4. ledger-journal-post CLI
        legs_file = Path(self.temp_dir.name) / "cli_legs.json"
        legs_file.write_text(json.dumps([
            {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 3000},
            {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 3000},
        ]), encoding="utf-8")

        ret, out = self._run_cli(
            "ledger-journal-post",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--type", "CLI_PAYMENT",
            "--source-event", "CLI_EVT_001",
            "--currency", "CNY",
            "--legs", str(legs_file),
        )
        self.assertEqual(ret, 0, f"CLI journal post failed: {out}")
        j_data = json.loads(out)
        self.assertEqual(j_data["totalAmountMinor"], 3000)

        # 5. ledger-balance-audit CLI
        ret, out = self._run_cli(
            "ledger-balance-audit",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
        )
        self.assertEqual(ret, 0, f"CLI balance audit failed: {out}")
        aud_data = json.loads(out)
        self.assertTrue(aud_data["integrity"]["valid"])
        self.assertTrue(aud_data["trialBalance"]["isBalanced"])


if __name__ == "__main__":
    unittest.main()
