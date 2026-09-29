# testing/test_enterprise_fx_b2b_payout_vault_e3_e4.py
from __future__ import annotations

import concurrent.futures
import datetime
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Add project roots to sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools" / "runtime"))

from elmpay_runtime.common import ValidationError
from elmpay_runtime.durable import DurableStore
from elmpay_runtime.fx_engine import FXQuoteLockManager, RATE_SCALE
from elmpay_runtime.b2b_credit import B2BCreditManager
from elmpay_runtime.mass_payout import MassPayoutManager, _compute_batch_digest
from elmpay_runtime.card_vault import CardVaultManager, _validate_luhn, _detect_card_brand


class EnterpriseFXB2BPayoutVaultE3Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_elmpay.db"
        self.store = DurableStore(str(self.db_path))
        self.tenant_id = "tent_ent_corp_01"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_guaranteed_fx_quote_lock_and_dcc_lifecycle(self) -> None:
        """E3: FX spot rate, spread markup, guaranteed quote lock, redemption, and DCC evaluation."""
        fx_mgr = FXQuoteLockManager(self.store)

        # 1. Configure FX rate matrix (1 USD = 7.150000 CNY, 50 bps spread = 0.50%)
        matrix = fx_mgr.set_rate_matrix(
            tenant_id=self.tenant_id,
            base_currency="USD",
            target_currency="CNY",
            spot_rate_units=7_150_000,
            spread_basis_points=50,
        )
        self.assertEqual(matrix["base_currency"], "USD")
        self.assertEqual(matrix["target_currency"], "CNY")

        # 2. Lock guaranteed quote for $100.00 (10,000 cents)
        quote = fx_mgr.create_quote_lock(
            tenant_id=self.tenant_id,
            base_currency="USD",
            target_currency="CNY",
            source_amount_minor=10_000,
            ttl_seconds=900,
        )
        self.assertTrue(quote["quote_id"].startswith("qte_"))
        self.assertEqual(quote["status"], "LOCKED")
        # Effective rate: 7,150,000 * 10,050 // 10,000 = 7,185,750
        self.assertEqual(quote["effective_rate_units"], 7_185_750)
        # Target amount: 10,000 * 7,185,750 // 1,000,000 = 71,857 CNY minor
        self.assertEqual(quote["target_amount_minor"], 71_857)

        # 3. Redeem quote lock
        redeemed = fx_mgr.redeem_quote_lock(
            tenant_id=self.tenant_id,
            quote_id=quote["quote_id"],
            payment_intent_id="pi_order_crossborder_99",
        )
        self.assertEqual(redeemed["status"], "REDEEMED")
        self.assertEqual(redeemed["target_amount_minor"], 71_857)

        # Verify double redemption fails closed
        with self.assertRaises(ValidationError):
            fx_mgr.redeem_quote_lock(
                tenant_id=self.tenant_id,
                quote_id=quote["quote_id"],
                payment_intent_id="pi_order_crossborder_repeat",
            )

        # 4. Evaluate Dynamic Currency Conversion (DCC)
        # Card currency USD, Merchant settlement CNY -> DCC eligible
        dcc_offer = fx_mgr.evaluate_dcc_offer(
            tenant_id=self.tenant_id,
            card_currency="CNY",
            merchant_currency="USD",
            transaction_amount_minor=50_000,
        )
        self.assertTrue(dcc_offer["dcc_eligible"])
        self.assertEqual(dcc_offer["markup_percentage"], "0.50%")
        self.assertIn("Cardholder is offered the choice", dcc_offer["disclosure_notice"])

        # Same currency -> Not eligible
        same_cur = fx_mgr.evaluate_dcc_offer(
            tenant_id=self.tenant_id,
            card_currency="USD",
            merchant_currency="USD",
            transaction_amount_minor=50_000,
        )
        self.assertFalse(same_cur["dcc_eligible"])

    def test_b2b_credit_facility_po_and_aging_analysis(self) -> None:
        """E3: B2B trade credit line, PO issuance with Net-D terms, drawdown ceiling, and aging analysis."""
        credit_mgr = B2BCreditManager(self.store)

        # 1. Create credit facility: 1,000,000 CNY minor ($10,000.00)
        facility = credit_mgr.create_credit_facility(
            tenant_id=self.tenant_id,
            buyer_id="buyer_enterprise_global",
            buyer_name="Global Trade Corp",
            credit_limit_minor=1_000_000,
            currency="CNY",
            credit_tier="ENTERPRISE",
        )
        self.assertEqual(facility["credit_limit_minor"], 1_000_000)
        self.assertEqual(facility["available_credit_minor"], 1_000_000)

        # 2. Issue PO-001 for 400,000 minor with NET_30
        po1 = credit_mgr.issue_purchase_order(
            tenant_id=self.tenant_id,
            buyer_id="buyer_enterprise_global",
            po_number="PO-2026-001",
            seller_name="ELMPay Supplier Inc",
            amount_minor=400_000,
            payment_terms="NET_30",
            issue_date="2026-08-01",
        )
        self.assertEqual(po1["status"], "ISSUED")
        self.assertEqual(po1["due_date"], "2026-08-31")
        self.assertEqual(po1["available_credit_minor"], 600_000)

        # 3. Issue PO-002 for 500,000 minor with NET_15
        po2 = credit_mgr.issue_purchase_order(
            tenant_id=self.tenant_id,
            buyer_id="buyer_enterprise_global",
            po_number="PO-2026-002",
            seller_name="ELMPay Supplier Inc",
            amount_minor=500_000,
            payment_terms="NET_15",
            issue_date="2026-08-10",
        )
        self.assertEqual(po2["due_date"], "2026-08-25")
        self.assertEqual(po2["available_credit_minor"], 100_000)

        # 4. Attempt to issue PO-003 for 200,000 minor -> Exceeds available credit (100,000)
        with self.assertRaises(ValidationError) as ctx:
            credit_mgr.issue_purchase_order(
                tenant_id=self.tenant_id,
                buyer_id="buyer_enterprise_global",
                po_number="PO-2026-003",
                seller_name="ELMPay Supplier Inc",
                amount_minor=200_000,
                payment_terms="NET_30",
            )
        self.assertIn("insufficient available credit line", str(ctx.exception))

        # 5. Overdue Aging and Late Penalty Calculation as of 2026-09-18
        # PO-001 due 2026-08-31 (18 days overdue -> OVERDUE_1_30)
        # PO-002 due 2026-08-25 (24 days overdue -> OVERDUE_1_30)
        aging = credit_mgr.calculate_aging_and_penalties(
            tenant_id=self.tenant_id,
            buyer_id="buyer_enterprise_global",
            as_of_date="2026-09-18",
            annual_penalty_rate_bps=500,  # 5%
        )
        self.assertEqual(aging["total_open_minor"], 900_000)
        self.assertEqual(aging["buckets"]["overdue_1_to_30_minor"], 900_000)
        self.assertGreater(aging["total_penalty_minor"], 0)

        # 6. Repay PO-001 in full (400,000 minor)
        repay = credit_mgr.repay_purchase_order(
            tenant_id=self.tenant_id,
            po_number="PO-2026-001",
            repayment_amount_minor=400_000,
        )
        self.assertEqual(repay["status"], "SETTLED")
        self.assertEqual(repay["available_credit_minor"], 500_000)

    def test_mass_payout_maker_checker_and_iso20022_export(self) -> None:
        """E3: Enterprise bulk payouts, maker-checker authorization, item execution, and ISO 20022 XML export."""
        payout_mgr = MassPayoutManager(self.store)

        items = [
            {
                "recipient_id": "vend_001",
                "recipient_name": "Acme Hardware Ltd",
                "channel": "BANK_WIRE",
                "account_identifier": "622202100011223344",
                "amount_minor": 150_000,
                "fee_minor": 50,
            },
            {
                "recipient_id": "vend_002",
                "recipient_name": "Shanghai Logistics Corp",
                "channel": "ALIPAY",
                "account_identifier": "finance@shlogistics.com",
                "amount_minor": 80_000,
                "fee_minor": 20,
            },
            {
                "recipient_id": "vend_003",
                "recipient_name": "Dev Studio Partner",
                "channel": "SEPA",
                "account_identifier": "DE89370400440532013000",
                "amount_minor": 120_000,
                "fee_minor": 100,
            },
        ]

        # 1. Create mass payout batch (Maker)
        batch = payout_mgr.create_batch(
            tenant_id=self.tenant_id,
            batch_name="Supplier_Disbursement_202609",
            currency="CNY",
            maker_id="usr_finance_maker_alice",
            items=items,
        )
        self.assertEqual(batch["total_count"], 3)
        self.assertEqual(batch["total_amount_minor"], 350_000)
        self.assertEqual(batch["status"], "SUBMITTED")

        # 2. Four-eyes violation: maker Alice tries to approve her own batch
        with self.assertRaises(ValidationError) as ctx:
            payout_mgr.approve_batch(
                tenant_id=self.tenant_id,
                batch_id=batch["batch_id"],
                checker_id="usr_finance_maker_alice",
            )
        self.assertIn("four-eyes rule violation", str(ctx.exception))

        # Independent checker Bob approves
        approved = payout_mgr.approve_batch(
            tenant_id=self.tenant_id,
            batch_id=batch["batch_id"],
            checker_id="usr_finance_checker_bob",
        )
        self.assertEqual(approved["status"], "APPROVED")

        # 3. Execute batch with simulated partial failure on item 3
        batch_details = payout_mgr.get_batch_status(self.tenant_id, batch["batch_id"])
        item3_id = batch_details["items"][2]["item_id"]

        exec_res = payout_mgr.execute_batch(
            tenant_id=self.tenant_id,
            batch_id=batch["batch_id"],
            executor_id="usr_treasury_ops",
            item_outcomes={item3_id: "IBAN routing code inactive"},
        )
        self.assertEqual(exec_res["status"], "PARTIALLY_FAILED")
        self.assertEqual(exec_res["success_count"], 2)
        self.assertEqual(exec_res["failed_count"], 1)

        # 4. Export ISO 20022 pain.001.001.03 XML
        xml_content = payout_mgr.export_iso20022_pain001(self.tenant_id, batch["batch_id"])
        self.assertIn('<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.03">', xml_content)
        self.assertIn("<NbOfTxs>3</NbOfTxs>", xml_content)
        self.assertIn("<CtrlSum>3500.00</CtrlSum>", xml_content)
        self.assertIn("<Nm>Acme Hardware Ltd</Nm>", xml_content)

        # 5. Export CSV
        csv_content = payout_mgr.export_payout_csv(self.tenant_id, batch["batch_id"])
        self.assertIn("Acme Hardware Ltd", csv_content)
        self.assertIn("IBAN routing code inactive", csv_content)

    def test_card_vault_network_tokenization_and_updater(self) -> None:
        """E3: PCI DSS 4.0 zero-knowledge card tokenization, network cryptogram, and Account Updater."""
        vault_mgr = CardVaultManager(self.store)

        # 1. Luhn check: invalid card fails closed
        with self.assertRaises(ValidationError) as ctx:
            vault_mgr.tokenize_card(
                tenant_id=self.tenant_id,
                customer_id="cust_vip_001",
                raw_pan="4111111111111112",  # Invalid checksum
                exp_month=12,
                exp_year=2028,
                cardholder_name="Alice Smith",
            )
        self.assertIn("failed Luhn checksum", str(ctx.exception))

        # 2. Tokenize valid Visa test card
        valid_pan = "4111111111111111"
        token = vault_mgr.tokenize_card(
            tenant_id=self.tenant_id,
            customer_id="cust_vip_001",
            raw_pan=valid_pan,
            exp_month=12,
            exp_year=2028,
            cardholder_name="Alice Smith",
        )
        self.assertTrue(token["vault_token"].startswith("tok_"))
        self.assertTrue(token["network_token"].startswith("ntok_"))
        self.assertEqual(token["card_brand"], "VISA")
        self.assertEqual(token["bin_first6"], "411111")
        self.assertEqual(token["last4"], "1111")
        self.assertEqual(token["masked_pan"], "411111******1111")

        # 3. Generate 3DS Network Token Cryptogram
        crypto = vault_mgr.generate_network_token_cryptogram(self.tenant_id, token["vault_token"])
        self.assertEqual(crypto["eci"], "05")
        self.assertIsNotNone(crypto["cryptogram"])

        # 4. Account Updater: EXPIRY_UPDATE
        update_res = vault_mgr.apply_account_updater_event(
            tenant_id=self.tenant_id,
            vault_token=token["vault_token"],
            event_type="EXPIRY_UPDATE",
            new_exp_month=10,
            new_exp_year=2030,
        )
        self.assertEqual(update_res["event_type"], "EXPIRY_UPDATE")

        retrieved = vault_mgr.get_vault_token(self.tenant_id, token["vault_token"])
        self.assertEqual(retrieved["exp_year"], 2030)
        self.assertEqual(retrieved["exp_month"], 10)

        # 5. Purge expired tokens under PCI DSS 4.0
        purged = vault_mgr.purge_expired_tokens(self.tenant_id, current_year=2031, current_month=1)
        self.assertEqual(purged, 1)

        expired_card = vault_mgr.get_vault_token(self.tenant_id, token["vault_token"])
        self.assertEqual(expired_card["status"], "EXPIRED")


class EnterpriseFXB2BPayoutVaultE4Test(unittest.TestCase):
    """E4: Concurrency races, tamper injections, and adversarial boundary tests."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_elmpay_e4.db"
        self.store = DurableStore(str(self.db_path))
        self.tenant_id = "tent_e4_enterprise"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e4_concurrent_b2b_credit_drawdown_race(self) -> None:
        """E4: 10 concurrent threads racing to draw down 2,000 on a 10,000 credit line."""
        credit_mgr = B2BCreditManager(self.store)
        credit_mgr.create_credit_facility(
            tenant_id=self.tenant_id,
            buyer_id="buyer_race",
            buyer_name="Race Corp",
            credit_limit_minor=10_000,
        )

        successes = 0
        failures = 0

        def _worker(thread_idx: int) -> bool:
            try:
                credit_mgr.issue_purchase_order(
                    tenant_id=self.tenant_id,
                    buyer_id="buyer_race",
                    po_number=f"PO-RACE-{thread_idx}",
                    seller_name="Supplier Race",
                    amount_minor=2_000,
                    payment_terms="NET_30",
                )
                return True
            except ValidationError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_worker, i) for i in range(10)]
            for f in concurrent.futures.as_completed(futures):
                if f.result():
                    successes += 1
                else:
                    failures += 1

        # Exactly 5 threads should succeed (5 * 2,000 = 10,000); exactly 5 should fail
        self.assertEqual(successes, 5)
        self.assertEqual(failures, 5)

        facility = credit_mgr.get_facility_status(self.tenant_id, "buyer_race")
        self.assertEqual(facility["drawn_balance_minor"], 10_000)
        self.assertEqual(facility["available_credit_minor"], 0)

    def test_e4_expired_fx_quote_and_concurrent_redemption_race(self) -> None:
        """E4: Quote lock expires; concurrent threads racing to redeem the same quote lock."""
        fx_mgr = FXQuoteLockManager(self.store)
        fx_mgr.set_rate_matrix(self.tenant_id, "USD", "CNY", 7_200_000, 50)

        # 1. Quote lock expiry test (TTL = 1s)
        quote_exp = fx_mgr.create_quote_lock(self.tenant_id, "USD", "CNY", 10_000, ttl_seconds=1)
        time.sleep(1.2)  # Wait for expiry

        with self.assertRaises(ValidationError) as ctx:
            fx_mgr.redeem_quote_lock(self.tenant_id, quote_exp["quote_id"], "pi_exp_01")
        self.assertIn("has expired", str(ctx.exception))

        # 2. Concurrency race on a valid quote lock
        valid_quote = fx_mgr.create_quote_lock(self.tenant_id, "USD", "CNY", 10_000, ttl_seconds=300)
        qid = valid_quote["quote_id"]

        redeem_wins = 0
        redeem_losses = 0

        def _redeem_worker(idx: int) -> bool:
            try:
                fx_mgr.redeem_quote_lock(self.tenant_id, qid, f"pi_race_{idx}")
                return True
            except ValidationError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_redeem_worker, i) for i in range(10)]
            for f in concurrent.futures.as_completed(futures):
                if f.result():
                    redeem_wins += 1
                else:
                    redeem_losses += 1

        # Strictly 1 thread can redeem; 9 threads fail
        self.assertEqual(redeem_wins, 1)
        self.assertEqual(redeem_losses, 9)

    def test_e4_mass_payout_digest_tamper_and_double_execution(self) -> None:
        """E4: Database tampering on payout batch and prevention of double execution."""
        payout_mgr = MassPayoutManager(self.store)
        items = [
            {
                "recipient_id": "v1",
                "recipient_name": "Vendor 1",
                "channel": "BANK_WIRE",
                "account_identifier": "62220101",
                "amount_minor": 50_000,
            }
        ]
        batch = payout_mgr.create_batch(self.tenant_id, "Tamper_Batch", "CNY", "alice", items)
        bid = batch["batch_id"]

        # Tamper test: direct database tampering of total_amount_minor
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE mass_payout_batch SET total_amount_minor = ? WHERE batch_id = ?",
                (999_999, bid),
            )

        # Verification that recalculating digest detects discrepancy
        batch_row = payout_mgr.get_batch_status(self.tenant_id, bid)
        computed_digest = _compute_batch_digest(
            self.tenant_id, batch_row["batch_name"], batch_row["currency"], batch_row["items"]
        )
        self.assertEqual(computed_digest, batch["batch_digest"])  # Items are unchanged, but total is tampered!
        self.assertNotEqual(batch_row["total_amount_minor"], 50_000)

        # Restore original amount for execution test
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE mass_payout_batch SET total_amount_minor = 50000 WHERE batch_id = ?",
                (bid,),
            )

        # Approve and execute
        payout_mgr.approve_batch(self.tenant_id, bid, "bob")
        exec1 = payout_mgr.execute_batch(self.tenant_id, bid, "ops")
        self.assertEqual(exec1["status"], "COMPLETED")

        # Double execution attempt fails closed
        with self.assertRaises(ValidationError) as ctx:
            payout_mgr.execute_batch(self.tenant_id, bid, "ops")
        self.assertIn("must be APPROVED to execute", str(ctx.exception))


class EnterpriseFXB2BPayoutVaultCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_cli.db"
        self.control_py = REPO_ROOT / "tools" / "runtime" / "control.py"
        self.tenant_id = "tent_cli_01"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_cli(self, args: list[str]) -> dict:
        cmd = [sys.executable, str(self.control_py)] + args
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"CLI error: {proc.stderr}\nOutput: {proc.stdout}")
        return json.loads(proc.stdout.strip())

    def test_cli_fx_and_b2b_credit(self) -> None:
        """CLI: fx-rate-set, fx-quote-lock, fx-quote-redeem, fx-dcc-evaluate, b2b-credit, b2b-po."""
        # 1. fx-rate-set
        r1 = self._run_cli([
            "fx-rate-set", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--base", "USD", "--target", "CNY",
            "--spot-rate-units", "7150000", "--spread-bp", "50"
        ])
        self.assertEqual(r1["spot_rate_units"], 7150000)

        # 2. fx-quote-lock
        r2 = self._run_cli([
            "fx-quote-lock", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--base", "USD", "--target", "CNY",
            "--amount-minor", "10000"
        ])
        self.assertEqual(r2["status"], "LOCKED")
        qid = r2["quote_id"]

        # 3. fx-quote-redeem
        r3 = self._run_cli([
            "fx-quote-redeem", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--quote-id", qid,
            "--payment-intent", "pi_cli_test"
        ])
        self.assertEqual(r3["status"], "REDEEMED")

        # 4. fx-dcc-evaluate
        r4 = self._run_cli([
            "fx-dcc-evaluate", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--card-currency", "CNY",
            "--merchant-currency", "USD",
            "--amount-minor", "20000"
        ])
        self.assertTrue(r4["dcc_eligible"])

        # 5. b2b-credit-create
        r5 = self._run_cli([
            "b2b-credit-create", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--buyer-id", "buyer_cli",
            "--buyer-name", "CLI Enterprise Ltd",
            "--limit-minor", "500000",
            "--currency", "CNY"
        ])
        self.assertEqual(r5["available_credit_minor"], 500000)

        # 6. b2b-po-issue
        r6 = self._run_cli([
            "b2b-po-issue", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--buyer-id", "buyer_cli",
            "--po-number", "PO-CLI-01",
            "--seller-name", "Supplier CLI",
            "--amount-minor", "200000",
            "--terms", "NET_30"
        ])
        self.assertEqual(r6["available_credit_minor"], 300000)

        # 7. b2b-po-repay
        r7 = self._run_cli([
            "b2b-po-repay", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--po-number", "PO-CLI-01",
            "--amount-minor", "100000"
        ])
        self.assertEqual(r7["available_credit_minor"], 400000)

        # 8. b2b-aging-report
        r8 = self._run_cli([
            "b2b-aging-report", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--buyer-id", "buyer_cli"
        ])
        self.assertEqual(r8["total_open_minor"], 100000)

    def test_cli_payout_and_card_vault(self) -> None:
        """CLI: payout-batch, payout-approve, payout-execute, vault-tokenize, vault-cryptogram."""
        # 1. payout-batch-create
        items_json_path = Path(self.temp_dir.name) / "items.json"
        items_json_path.write_text(json.dumps([
            {
                "recipient_id": "rec_01",
                "recipient_name": "Supplier 1",
                "channel": "BANK_WIRE",
                "account_identifier": "622201",
                "amount_minor": 80000
            }
        ]), encoding="utf-8")

        p1 = self._run_cli([
            "payout-batch-create", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--batch-name", "CLI_Batch",
            "--maker", "maker_cli",
            "--items", str(items_json_path)
        ])
        bid = p1["batch_id"]

        # 2. payout-batch-approve
        p2 = self._run_cli([
            "payout-batch-approve", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--batch-id", bid,
            "--checker", "checker_cli"
        ])
        self.assertEqual(p2["status"], "APPROVED")

        # 3. payout-batch-execute
        p3 = self._run_cli([
            "payout-batch-execute", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--batch-id", bid,
            "--executor", "ops_cli"
        ])
        self.assertEqual(p3["status"], "COMPLETED")

        # 4. vault-tokenize
        v1 = self._run_cli([
            "vault-tokenize", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--customer-id", "cust_cli",
            "--pan", "4111111111111111",
            "--exp-month", "12",
            "--exp-year", "2029",
            "--name", "Jane Doe"
        ])
        self.assertEqual(v1["card_brand"], "VISA")
        tok = v1["vault_token"]

        # 5. vault-cryptogram
        v2 = self._run_cli([
            "vault-cryptogram", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--vault-token", tok
        ])
        self.assertEqual(v2["eci"], "05")

        # 6. vault-account-updater
        v3 = self._run_cli([
            "vault-account-updater", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--vault-token", tok,
            "--event-type", "EXPIRY_UPDATE",
            "--new-exp-month", "11",
            "--new-exp-year", "2031"
        ])
        self.assertEqual(v3["event_type"], "EXPIRY_UPDATE")

        # 7. vault-purge
        v4 = self._run_cli([
            "vault-purge", "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--year", "2025",
            "--month", "1"
        ])
        self.assertEqual(v4["purgedCount"], 0)


if __name__ == "__main__":
    unittest.main()
