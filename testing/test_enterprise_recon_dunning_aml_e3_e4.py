"""E3/E4 tests for enterprise three-way reconciliation, recurring mandates/dunning, and AML/sanctions screening."""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.runtime.elmpay_runtime.common import ValidationError
from tools.runtime.elmpay_runtime.durable import DurableStore
from tools.runtime.elmpay_runtime.statement_recon import StatementReconciliationEngine
from tools.runtime.elmpay_runtime.mandates_dunning import MandatesDunningEngine
from tools.runtime.elmpay_runtime.aml_sanctions import AmlSanctionsEngine


class TestStatementReconciliationEngineE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_recon.db"
        self.store = DurableStore(self.db_path)
        self.engine = StatementReconciliationEngine(self.store)
        self.tenant_id = "tenant_recon_corp"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_statement_ingest_and_hash_digest(self) -> None:
        """E3: Statement ingestion parses records, enforces validation, and computes deterministic SHA-256 digest."""
        items = [
            {"channel_txn_id": "ch_tx_001", "internal_txn_id": "pi_001", "amount_minor": 10000, "fee_minor": 30, "txn_type": "PAYMENT"},
            {"channel_txn_id": "ch_tx_002", "internal_txn_id": "pi_002", "amount_minor": 25000, "fee_minor": 75, "txn_type": "PAYMENT"},
            {"channel_txn_id": "ch_tx_003", "internal_txn_id": "pi_003", "amount_minor": 5000, "fee_minor": 15, "txn_type": "REFUND"},
        ]

        batch = self.engine.ingest_statement(
            tenant_id=self.tenant_id,
            channel_id="alipay_direct",
            statement_date="2026-09-18",
            file_name="alipay_statement_20260918.csv",
            items=items,
            currency="CNY",
        )

        self.assertEqual(batch["total_records"], 3)
        self.assertEqual(batch["total_amount_minor"], 40000)
        self.assertEqual(len(batch["file_digest"]), 64)
        self.assertEqual(batch["status"], "INGESTED")

        # Empty items fails closed
        with self.assertRaises(ValidationError):
            self.engine.ingest_statement(
                tenant_id=self.tenant_id,
                channel_id="alipay_direct",
                statement_date="2026-09-18",
                file_name="empty.csv",
                items=[],
            )

        # Invalid txn_type fails closed
        with self.assertRaises(ValidationError):
            self.engine.ingest_statement(
                tenant_id=self.tenant_id,
                channel_id="alipay_direct",
                statement_date="2026-09-18",
                file_name="bad.csv",
                items=[{"channel_txn_id": "ch_bad", "amount_minor": 1000, "txn_type": "INVALID_TYPE"}],
            )

    def test_e3_three_way_cross_reconciliation_matching(self) -> None:
        """E3: Multi-stream cross-reconciliation detects matched, amount mismatch, unilateral platform missing, and unilateral channel missing."""
        # Ingest statement with 3 channel items
        items = [
            {"channel_txn_id": "ch_matched", "internal_txn_id": "pi_matched", "amount_minor": 10000, "fee_minor": 30},
            {"channel_txn_id": "ch_amt_diff", "internal_txn_id": "pi_amt_diff", "amount_minor": 20000, "fee_minor": 60},
            {"channel_txn_id": "ch_plat_missing", "internal_txn_id": None, "amount_minor": 30000, "fee_minor": 90},
        ]
        batch = self.engine.ingest_statement(
            tenant_id=self.tenant_id,
            channel_id="stripe_eu",
            statement_date="2026-09-18",
            file_name="stripe_statement.json",
            items=items,
            currency="EUR",
        )

        # Internal platform ledger:
        # pi_matched: matches 10,000
        # pi_amt_diff: 19,000 on platform vs 20,000 on channel (AMOUNT_MISMATCH)
        # pi_chan_missing: on platform but missing from channel statement (UNILATERAL_CHANNEL_MISSING)
        internal_txns = [
            {"internal_txn_id": "pi_matched", "amount_minor": 10000, "currency": "EUR"},
            {"internal_txn_id": "pi_amt_diff", "amount_minor": 19000, "currency": "EUR"},
            {"internal_txn_id": "pi_chan_missing", "amount_minor": 15000, "currency": "EUR"},
        ]

        bank_clearing = [
            {"channel_txn_id": "ch_matched", "amount_minor": 10000},
        ]

        res = self.engine.reconcile_three_way(
            tenant_id=self.tenant_id,
            batch_id=batch["batch_id"],
            internal_transactions=internal_txns,
            bank_clearing_records=bank_clearing,
        )

        self.assertEqual(res["status"], "DISCREPANCY_FOUND")
        self.assertEqual(res["matched_count"], 1)
        self.assertEqual(res["discrepancy_count"], 3)

        disc_types = [d["type"] for d in res["discrepancies"]]
        self.assertIn("AMOUNT_MISMATCH", disc_types)
        self.assertIn("UNILATERAL_PLATFORM_MISSING", disc_types)
        self.assertIn("UNILATERAL_CHANNEL_MISSING", disc_types)

    def test_e3_discrepancy_adjustment_four_eyes_enforcement(self) -> None:
        """E3: Discrepancy resolution enforces Maker-Checker separation of duties; maker == checker fails closed."""
        items = [{"channel_txn_id": "ch_alone", "amount_minor": 5000}]
        batch = self.engine.ingest_statement(
            tenant_id=self.tenant_id,
            channel_id="wechat_pay",
            statement_date="2026-09-18",
            file_name="wechat_bill.csv",
            items=items,
        )
        res = self.engine.reconcile_three_way(self.tenant_id, batch["batch_id"], internal_transactions=[])
        disc_id = res["discrepancies"][0]["discrepancy_id"]

        # Maker stage
        prop = self.engine.propose_discrepancy_adjustment(
            tenant_id=self.tenant_id,
            discrepancy_id=disc_id,
            proposed_action="WRITE_OFF",
            maker_id="finance_officer_alice",
            notes="Small balance rounding write off",
        )
        self.assertEqual(prop["status"], "PENDING_APPROVAL")

        # Checker stage: Maker trying to approve own proposal MUST fail closed
        with self.assertRaises(ValidationError) as ctx:
            self.engine.approve_discrepancy_adjustment(
                tenant_id=self.tenant_id,
                discrepancy_id=disc_id,
                checker_id="finance_officer_alice",  # Same as maker!
            )
        self.assertIn("maker and checker cannot be the same individual", str(ctx.exception))

        # Independent checker approves
        app = self.engine.approve_discrepancy_adjustment(
            tenant_id=self.tenant_id,
            discrepancy_id=disc_id,
            checker_id="treasury_director_bob",  # Independent checker
        )
        self.assertEqual(app["status"], "WRITTEN_OFF")
        self.assertEqual(app["checker_id"], "treasury_director_bob")

    def test_e4_concurrent_discrepancy_approval_race(self) -> None:
        """E4: Concurrent racing approvals on the same discrepancy must be strictly atomic (1 win, 9 fail)."""
        items = [{"channel_txn_id": "ch_race", "amount_minor": 8000}]
        batch = self.engine.ingest_statement(
            tenant_id=self.tenant_id,
            channel_id="unionpay",
            statement_date="2026-09-18",
            file_name="unionpay.csv",
            items=items,
        )
        res = self.engine.reconcile_three_way(self.tenant_id, batch["batch_id"], internal_transactions=[])
        disc_id = res["discrepancies"][0]["discrepancy_id"]

        self.engine.propose_discrepancy_adjustment(
            tenant_id=self.tenant_id,
            discrepancy_id=disc_id,
            proposed_action="MANUAL_SETTLE",
            maker_id="finance_maker",
        )

        wins = 0
        losses = 0

        def _approve_worker(idx: int) -> bool:
            try:
                self.engine.approve_discrepancy_adjustment(
                    tenant_id=self.tenant_id,
                    discrepancy_id=disc_id,
                    checker_id=f"finance_checker_{idx}",
                )
                return True
            except ValidationError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_approve_worker, i) for i in range(10)]
            for f in concurrent.futures.as_completed(futures):
                if f.result():
                    wins += 1
                else:
                    losses += 1

        self.assertEqual(wins, 1)
        self.assertEqual(losses, 9)


class TestMandatesDunningEngineE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_mandates.db"
        self.store = DurableStore(self.db_path)
        self.engine = MandatesDunningEngine(self.store)
        self.tenant_id = "tenant_mandate_corp"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_mandate_registration_and_quota_charge(self) -> None:
        """E3: Mandate creation validates scheme, bounds, and enforces ceiling limit upon recurring charge."""
        mandate = self.engine.register_mandate(
            tenant_id=self.tenant_id,
            customer_id="cust_enterprise_01",
            payment_method_ref="pm_bacs_direct_debit_9988",
            mandate_type="BACS_DIRECT_DEBIT",
            max_amount_per_charge_minor=100_000,  # Max 1,000.00 GBP
            currency="GBP",
        )
        self.assertEqual(mandate["status"], "ACTIVE")
        self.assertEqual(len(mandate["signature_digest"]), 64)

        # Valid charge below ceiling
        ch = self.engine.execute_mandate_charge(
            tenant_id=self.tenant_id,
            mandate_id=mandate["mandate_id"],
            invoice_id="inv_rec_001",
            amount_minor=85_000,
        )
        self.assertEqual(ch["status"], "AUTHORIZED")

        # Charge exceeding ceiling fails closed
        with self.assertRaises(ValidationError) as ctx:
            self.engine.execute_mandate_charge(
                tenant_id=self.tenant_id,
                mandate_id=mandate["mandate_id"],
                invoice_id="inv_rec_002",
                amount_minor=100_001,
            )
        self.assertIn("exceeds authorized mandate ceiling", str(ctx.exception))

    def test_e3_soft_vs_hard_decline_and_smart_dunning_progression(self) -> None:
        """E3: Hard decline suspends mandate immediately; soft decline executes multi-step dunning retry."""
        # 1. Hard decline test
        m_hard = self.engine.register_mandate(
            tenant_id=self.tenant_id,
            customer_id="cust_hard",
            payment_method_ref="pm_card_stolen",
            mandate_type="CARD_RECURRING_TOKEN",
            max_amount_per_charge_minor=50_000,
        )
        triage_hard = self.engine.evaluate_charge_failure(
            tenant_id=self.tenant_id,
            mandate_id=m_hard["mandate_id"],
            invoice_id="inv_hard_01",
            decline_code="CARD_STOLEN",
        )
        self.assertEqual(triage_hard["decline_type"], "HARD")
        self.assertEqual(triage_hard["status"], "EXHAUSTED")
        self.assertEqual(triage_hard["mandate_status"], "SUSPENDED")

        # 2. Soft decline test
        m_soft = self.engine.register_mandate(
            tenant_id=self.tenant_id,
            customer_id="cust_soft",
            payment_method_ref="pm_sepa_debit",
            mandate_type="SEPA_DIRECT_DEBIT",
            max_amount_per_charge_minor=50_000,
        )
        triage_soft = self.engine.evaluate_charge_failure(
            tenant_id=self.tenant_id,
            mandate_id=m_soft["mandate_id"],
            invoice_id="inv_soft_01",
            decline_code="INSUFFICIENT_FUNDS",
        )
        self.assertEqual(triage_soft["decline_type"], "SOFT")
        self.assertEqual(triage_soft["status"], "IN_PROGRESS")
        dunning_id = triage_soft["dunning_id"]

        # Retry attempt 2 (failed)
        r2 = self.engine.process_dunning_retry(self.tenant_id, dunning_id, simulate_outcome="FAILED")
        self.assertEqual(r2["status"], "IN_PROGRESS")
        self.assertEqual(r2["attempts"], 2)

        # Retry attempt 3 (failed)
        r3 = self.engine.process_dunning_retry(self.tenant_id, dunning_id, simulate_outcome="FAILED")
        self.assertEqual(r3["status"], "IN_PROGRESS")
        self.assertEqual(r3["attempts"], 3)

        # Retry attempt 4 (succeeded! -> recovered)
        r4 = self.engine.process_dunning_retry(self.tenant_id, dunning_id, simulate_outcome="SUCCESS")
        self.assertEqual(r4["status"], "RECOVERED")
        self.assertEqual(r4["mandate_status"], "ACTIVE")

    def test_e4_concurrent_mandate_charge_atomic_quota(self) -> None:
        """E4: High concurrency recurring charges verify thread safety and durable status inspection."""
        m = self.engine.register_mandate(
            tenant_id=self.tenant_id,
            customer_id="cust_conc",
            payment_method_ref="pm_token_99",
            mandate_type="CARD_RECURRING_TOKEN",
            max_amount_per_charge_minor=200_000,
        )

        def _charge_worker(idx: int) -> bool:
            try:
                res = self.engine.execute_mandate_charge(
                    tenant_id=self.tenant_id,
                    mandate_id=m["mandate_id"],
                    invoice_id=f"inv_conc_{idx}",
                    amount_minor=10_000,
                )
                return res["status"] == "AUTHORIZED"
            except ValidationError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_charge_worker, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(sum(1 for r in results if r), 10)


class TestAmlSanctionsEngineE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_aml.db"
        self.store = DurableStore(self.db_path)
        self.engine = AmlSanctionsEngine(self.store)
        self.tenant_id = "tenant_aml_corp"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_watchlist_management_and_fuzzy_token_screening(self) -> None:
        """E3: Watchlist screening matches exact name, aliases, and fuzzy tokens while clearing non-matches."""
        self.engine.add_watchlist_entry(
            list_source="OFAC_SDN",
            entity_name="Acme Sanctioned Logistics Group",
            entity_type="ORGANIZATION",
            country_iso="RU",
            aliases=["ASLG Holdings", "Acme Petrotrans"],
        )

        # 1. Exact match -> CONFIRMED_BLOCK
        res_exact = self.engine.screen_entity(self.tenant_id, "Acme Sanctioned Logistics Group")
        self.assertEqual(res_exact["decision"], "CONFIRMED_BLOCK")
        self.assertEqual(res_exact["match_confidence"], 100)

        # 2. Alias match -> CONFIRMED_BLOCK
        res_alias = self.engine.screen_entity(self.tenant_id, "ASLG Holdings")
        self.assertEqual(res_alias["decision"], "CONFIRMED_BLOCK")

        # 3. Token overlap -> POTENTIAL_MATCH
        res_fuzzy = self.engine.screen_entity(self.tenant_id, "Acme Sanctioned Shipping")
        self.assertEqual(res_fuzzy["decision"], "POTENTIAL_MATCH")
        self.assertGreaterEqual(res_fuzzy["match_confidence"], 65)

        # 4. Clean customer -> CLEAR
        res_clean = self.engine.screen_entity(self.tenant_id, "Shanghai Cloud Technology Co Ltd")
        self.assertEqual(res_clean["decision"], "CLEAR")

    def test_e3_large_transaction_reporting_threshold(self) -> None:
        """E3: Transactions meeting or exceeding threshold (>= 5,000,000 minor) must be recorded for FIU reporting."""
        # Under threshold (4,000,000 minor = 40,000 CNY)
        under = self.engine.evaluate_large_transaction(
            tenant_id=self.tenant_id,
            transaction_id="txn_normal_01",
            amount_minor=4_000_000,
            customer_name="Regular Merchant",
            threshold_minor=5_000_000,
        )
        self.assertFalse(under["is_reportable"])
        self.assertEqual(under["report_status"], "EXEMPT")

        # Over threshold (6,500,000 minor = 65,000 CNY)
        over = self.engine.evaluate_large_transaction(
            tenant_id=self.tenant_id,
            transaction_id="txn_large_01",
            amount_minor=6_500_000,
            customer_name="High Value Trader",
            threshold_minor=5_000_000,
        )
        self.assertTrue(over["is_reportable"])
        self.assertEqual(over["report_status"], "RECORDED")
        self.assertIsNotNone(over["report_id"])

    def test_e3_structuring_smurfing_pattern_detection(self) -> None:
        """E3: Smurfing detection identifies multiple transactions clustered right beneath reporting limits."""
        threshold = 5_000_000  # 50,000 CNY limit
        # 3 transactions between 4,000,000 (80%) and 4,999,999
        smurf_txns = [
            {"transaction_id": "tx_smurf_1", "amount_minor": 4_800_000},
            {"transaction_id": "tx_smurf_2", "amount_minor": 4_900_000},
            {"transaction_id": "tx_smurf_3", "amount_minor": 4_850_000},
        ]

        res = self.engine.detect_structuring_activity(
            tenant_id=self.tenant_id,
            customer_id="cust_suspicious_smurfer",
            transactions=smurf_txns,
            threshold_minor=threshold,
        )
        self.assertTrue(res["is_suspicious"])
        self.assertEqual(res["indicator"], "STRUCTURING_SMURFING")
        self.assertIsNotNone(res["sar_id"])

        # Legitimate distributed transactions -> Not suspicious
        clean_txns = [
            {"transaction_id": "tx_clean_1", "amount_minor": 100_000},
            {"transaction_id": "tx_clean_2", "amount_minor": 200_000},
        ]
        clean_res = self.engine.detect_structuring_activity(
            tenant_id=self.tenant_id,
            customer_id="cust_normal",
            transactions=clean_txns,
            threshold_minor=threshold,
        )
        self.assertFalse(clean_res["is_suspicious"])

    def test_e4_concurrent_aml_screening_durability(self) -> None:
        """E4: High concurrency AML screening requests durably write audit screening logs without contention."""
        self.engine.add_watchlist_entry("UN_CONSOLIDATED", "Blocked Target Global", "ORGANIZATION", "IR")

        def _screen_worker(idx: int) -> bool:
            try:
                res = self.engine.screen_entity(self.tenant_id, f"Random Corp {idx}")
                return bool(res["screening_id"])
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_screen_worker, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(sum(1 for r in results if r), 10)
        with self.store.connect() as conn:
            cnt = conn.execute("SELECT COUNT(*) FROM aml_screening_log WHERE tenant_id = ?", (self.tenant_id,)).fetchone()[0]
        self.assertEqual(cnt, 10)


class TestCliEnterpriseReconDunningAml(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_cli_recon_dunning.db"
        self.tenant_id = "tenant_cli_recon"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_cli(self, *args: str) -> tuple[int, str]:
        cmd = [sys.executable, "tools/runtime/control.py", *args]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.returncode, res.stdout.strip()

    def test_cli_recon_suite(self) -> None:
        """CLI: Verify recon-batch-ingest, recon-run-three-way, and recon-adjust-discrepancy."""
        # 1. Ingest
        items_file = Path(self.temp_dir.name) / "recon_items.json"
        items_file.write_text(json.dumps([
            {"channel_txn_id": "ch_cli_1", "internal_txn_id": "pi_cli_1", "amount_minor": 20000},
        ]), encoding="utf-8")

        code, out = self._run_cli(
            "recon-batch-ingest",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--channel", "alipay",
            "--date", "2026-09-18",
            "--file-name", "alipay.json",
            "--items", str(items_file),
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        ing = json.loads(out)
        batch_id = ing["batch_id"]

        # 2. Run three way (with amount discrepancy: 18000 vs 20000)
        int_file = Path(self.temp_dir.name) / "internal_txns.json"
        int_file.write_text(json.dumps([
            {"internal_txn_id": "pi_cli_1", "amount_minor": 18000},
        ]), encoding="utf-8")

        code, out = self._run_cli(
            "recon-run-three-way",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--batch-id", batch_id,
            "--internal-txns", str(int_file),
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        rc = json.loads(out)
        self.assertEqual(rc["discrepancy_count"], 1)
        disc_id = rc["discrepancies"][0]["discrepancy_id"]

        # 3. Adjust discrepancy with maker + checker
        code, out = self._run_cli(
            "recon-adjust-discrepancy",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--discrepancy-id", disc_id,
            "--action", "WRITE_OFF",
            "--maker-id", "maker_cli",
            "--checker-id", "checker_cli",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        adj = json.loads(out)
        self.assertEqual(adj["status"], "WRITTEN_OFF")

    def test_cli_mandate_and_dunning_suite(self) -> None:
        """CLI: Verify mandate-create, mandate-charge, dunning-evaluate-failure, and dunning-retry."""
        # 1. Mandate create
        code, out = self._run_cli(
            "mandate-create",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--customer-id", "cust_cli_mandate",
            "--payment-method", "pm_cli_card_tok",
            "--type", "CARD_RECURRING_TOKEN",
            "--max-amount", "80000",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        m = json.loads(out)
        mid = m["mandate_id"]

        # 2. Mandate charge
        code, out = self._run_cli(
            "mandate-charge",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--mandate-id", mid,
            "--invoice-id", "inv_cli_01",
            "--amount-minor", "50000",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        ch = json.loads(out)
        self.assertEqual(ch["status"], "AUTHORIZED")

        # 3. Dunning evaluate soft failure
        code, out = self._run_cli(
            "dunning-evaluate-failure",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--mandate-id", mid,
            "--invoice-id", "inv_cli_02",
            "--decline-code", "INSUFFICIENT_FUNDS",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        dn = json.loads(out)
        self.assertEqual(dn["status"], "IN_PROGRESS")
        did = dn["dunning_id"]

        # 4. Dunning retry
        code, out = self._run_cli(
            "dunning-retry",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--dunning-id", did,
            "--outcome", "SUCCESS",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        ret = json.loads(out)
        self.assertEqual(ret["status"], "RECOVERED")

    def test_cli_aml_suite(self) -> None:
        """CLI: Verify aml-sanctions-screen, aml-large-tx-check, and aml-structuring-detect."""
        # 1. Screen clean entity
        code, out = self._run_cli(
            "aml-sanctions-screen",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--entity-name", "Standard Good Merchant Ltd",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        sc = json.loads(out)
        self.assertEqual(sc["decision"], "CLEAR")

        # 2. Large tx check
        code, out = self._run_cli(
            "aml-large-tx-check",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--txn-id", "tx_large_cli",
            "--amount-minor", "8000000",
            "--customer-name", "Large Whale Trader",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        lt = json.loads(out)
        self.assertTrue(lt["is_reportable"])

        # 3. Structuring detect
        tx_file = Path(self.temp_dir.name) / "structuring_txns.json"
        tx_file.write_text(json.dumps([
            {"transaction_id": "tx1", "amount_minor": 4900000},
            {"transaction_id": "tx2", "amount_minor": 4950000},
            {"transaction_id": "tx3", "amount_minor": 4800000},
        ]), encoding="utf-8")

        code, out = self._run_cli(
            "aml-structuring-detect",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--customer-id", "cust_cli_smurf",
            "--transactions", str(tx_file),
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        st = json.loads(out)
        self.assertTrue(st["is_suspicious"])


if __name__ == "__main__":
    unittest.main()
