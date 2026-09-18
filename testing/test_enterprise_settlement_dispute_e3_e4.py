"""E3/E4 tests for enterprise batch invoicing, refund red-noting, merchant settlement, and disputes."""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.runtime.elmpay_runtime.common import ValidationError
from tools.runtime.elmpay_runtime.durable import DurableStore
from tools.runtime.elmpay_runtime.invoice import (
    CustomerInvoiceLedger,
    render_invoice_batch_html,
)
from tools.runtime.elmpay_runtime.settlement import (
    SettlementLedger,
    render_settlement_html,
)
from tools.runtime.elmpay_runtime.dispute import DisputeLedger


class TestEnterpriseBatchInvoicingAndRefundsE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_invoice_enterprise.db"
        self.store = DurableStore(self.db_path)
        self.ledger = CustomerInvoiceLedger(self.store)
        self.tenant_id = "tenant_enterprise_99"
        self.project_id = "project_saas_global"

        # Create default buyer title
        self.title = self.ledger.create_buyer_title(
            tenant_id=self.tenant_id,
            buyer_type="enterprise",
            buyer_name="上海极客云网络科技有限公司",
            buyer_tax_number="91310115MA1K4ABCD1",
            buyer_address_phone="上海市浦东新区高科西路 021-88889999",
            buyer_bank_account="招商银行上海分行 6225888812345678",
            recipient_email="finance@geekcloud.example.com",
            is_default=True,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_batch_auto_invoicing_manifest(self) -> None:
        """E3: Verify batch auto-invoicing from transaction manifest with error tolerance."""
        manifest = [
            {
                "paymentIntentId": f"pi_batch_{i}",
                "capturedAmountMinor": 10000 * i,
                "refundedAmountMinor": 0,
                "itemName": f"企业软件订阅服务 级别{i}",
                "taxRateBasisPoints": 1300,
                "idempotencyKey": f"idem_batch_{i}",
            }
            for i in range(1, 6)
        ]
        # Add duplicate and invalid entries
        manifest.append({
            "paymentIntentId": "pi_batch_1",  # duplicate
            "capturedAmountMinor": 10000,
            "idempotencyKey": "idem_batch_1",
        })
        manifest.append({
            "paymentIntentId": "",  # missing ID
            "capturedAmountMinor": 5000,
        })

        result = self.ledger.batch_auto_invoice(
            tenant_id=self.tenant_id,
            manifest=manifest,
            seller_name="云支付技术服务有限公司",
            seller_tax_number="91110108MA00AAAAAA",
        )

        self.assertEqual(result["tenantId"], self.tenant_id)
        self.assertEqual(result["totalProcessed"], 7)
        self.assertEqual(result["successCount"], 5)
        self.assertEqual(result["skippedDuplicateCount"], 1)
        self.assertEqual(result["failedCount"], 1)
        # Total: (1+2+3+4+5)*10000 = 150,000 minor
        self.assertEqual(result["totalInvoicedAmountMinor"], 150000)
        self.assertEqual(len(result["invoices"]), 5)

        # Idempotent replay: all should be skipped duplicates
        replay_result = self.ledger.batch_auto_invoice(
            tenant_id=self.tenant_id,
            manifest=manifest[:5],
            seller_name="云支付技术服务有限公司",
            seller_tax_number="91110108MA00AAAAAA",
        )
        self.assertEqual(replay_result["successCount"], 0)
        self.assertEqual(replay_result["skippedDuplicateCount"], 5)

    def test_e3_refund_linked_auto_red_noting(self) -> None:
        """E3: When payment is refunded, automatically issue pro-rata / full red notes."""
        pi_id = "pi_refund_test_01"
        # 1. Issue initial blue invoice for 100,000 minor ($1000)
        blue_inv = self.ledger.auto_invoice_payment_intent(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=100000,
            refunded_amount_minor=0,
            seller_name="云支付技术服务有限公司",
            seller_tax_number="91110108MA00AAAAAA",
            buyer_title_id=self.title["titleId"],
            idempotency_key="key_initial_blue",
        )
        self.assertEqual(blue_inv["status"], "ISSUED")
        self.assertEqual(blue_inv["totalAmountMinor"], 100000)

        # 2. Customer gets partial refund of 35,000 minor ($350)
        red_res1 = self.ledger.auto_red_note_on_refund(
            tenant_id=self.tenant_id,
            payment_intent_id=pi_id,
            refund_amount_minor=35000,
            operator="财务退款审核员",
        )
        self.assertEqual(red_res1["requestedRefundMinor"], 35000)
        self.assertEqual(red_res1["creditedAmountMinor"], 35000)
        self.assertEqual(red_res1["uncreditedAmountMinor"], 0)
        self.assertEqual(red_res1["redNotesCount"], 1)
        self.assertEqual(red_res1["redNotes"][0]["totalAmountMinor"], -35000)

        # 3. Verify invoicable balance is now 65,000
        bal = self.ledger.calculate_invoicable_balance(
            tenant_id=self.tenant_id,
            payment_intent_id=pi_id,
            captured_amount_minor=100000,
            refunded_amount_minor=35000,
        )
        self.assertEqual(bal, 0)  # captured (100k) - refunded (35k) = 65k net; invoiced net is 100k - 35k = 65k. Balance = 0!

        # 4. Customer gets second refund of 65,000 minor (full refund)
        red_res2 = self.ledger.auto_red_note_on_refund(
            tenant_id=self.tenant_id,
            payment_intent_id=pi_id,
            refund_amount_minor=65000,
            operator="财务退款审核员",
        )
        self.assertEqual(red_res2["creditedAmountMinor"], 65000)
        self.assertEqual(red_res2["redNotes"][0]["totalAmountMinor"], -65000)

        # 5. Further refund attempt should fail closed
        with self.assertRaises(ValidationError) as ctx:
            self.ledger.auto_red_note_on_refund(
                tenant_id=self.tenant_id,
                payment_intent_id=pi_id,
                refund_amount_minor=1000,
                operator="财务退款审核员",
            )
        self.assertIn("already fully red-noted", str(ctx.exception))

    def test_e3_render_invoice_batch_html(self) -> None:
        """E3: Verify multi-invoice printable booklet rendering."""
        invoices = []
        for i in range(1, 4):
            inv = self.ledger.auto_invoice_payment_intent(
                tenant_id=self.tenant_id,
                project_id=self.project_id,
                payment_intent_id=f"pi_booklet_{i}",
                captured_amount_minor=20000 * i,
                seller_name="云支付技术服务有限公司",
                seller_tax_number="91110108MA00AAAAAA",
                buyer_title_id=self.title["titleId"],
                idempotency_key=f"idem_booklet_{i}",
            )
            invoices.append(inv)

        html = render_invoice_batch_html(invoices, title="2026年9月企业服务费发票汇总册")
        self.assertIn("2026年9月企业服务费发票汇总册", html)
        self.assertIn("发票总张数", html)
        self.assertIn("3", html)
        self.assertIn("¥1200.00", html)  # (200 + 400 + 600 = 1200 Yuan)
        self.assertIn("page-break-after: always", html)
        self.assertIn("invoice-sheet", html)

    def test_e4_concurrent_batch_invoicing_race_condition(self) -> None:
        """E4: High concurrency test with 10 threads competing on batch auto-invoicing."""
        manifest = [
            {
                "paymentIntentId": f"pi_race_{i}",
                "capturedAmountMinor": 5000,
                "itemName": "高并发测试服务",
                "idempotencyKey": f"race_idem_{i}",
            }
            for i in range(1, 6)
        ]

        def worker() -> dict[str, Any]:
            worker_ledger = CustomerInvoiceLedger(self.store)
            return worker_ledger.batch_auto_invoice(
                tenant_id=self.tenant_id,
                manifest=manifest,
                seller_name="云支付技术服务有限公司",
                seller_tax_number="91110108MA00AAAAAA",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        total_new_success = sum(r["successCount"] for r in results)
        total_skipped = sum(r["skippedDuplicateCount"] for r in results)

        # Exactly 5 new invoices across all threads
        self.assertEqual(total_new_success, 5)
        self.assertEqual(total_skipped, 45)

        with self.store.connect() as conn:
            cnt = conn.execute(
                "SELECT count(*) as c FROM customer_invoice WHERE tenant_id=?",
                (self.tenant_id,),
            ).fetchone()["c"]
        self.assertEqual(cnt, 5)


class TestMerchantSettlementE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_settlement.db"
        self.store = DurableStore(self.db_path)
        self.ledger = SettlementLedger(self.store)
        self.tenant_id = "tenant_merchant_01"
        self.project_id = "project_ecommerce"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_settlement_full_lifecycle_and_four_eyes_approval(self) -> None:
        """E3: Test complete merchant settlement lifecycle: config -> batch -> four-eyes -> export -> execute."""
        # 1. Configure settlement
        config = self.ledger.configure_merchant_settlement(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            currency="CNY",
            settlement_cycle="T_PLUS_1",
            minimum_payout_minor=5000,  # 50.00 CNY
            commission_basis_points=30,  # 0.30%
            channel_fee_basis_points=38,  # 0.38%
            reserve_holdback_basis_points=500,  # 5.00%
            bank_name="中国工商银行上海自贸试验区分行",
            bank_account_number="6222021001009999888",
            bank_account_name="上海优品电子商务有限公司",
        )
        self.assertEqual(config["status"], "ACTIVE")
        self.assertEqual(config["reserveHoldbackBasisPoints"], 500)

        # 2. Simulate 10 captured transactions (total 200,000 minor = 2000 Yuan)
        #    and 2 refunds (total 20,000 minor = 200 Yuan)
        txs = [{"capturedAmountMinor": 20000, "refundedAmountMinor": 0} for _ in range(9)]
        txs.append({"capturedAmountMinor": 20000, "refundedAmountMinor": 20000})  # 1 full refund

        batch = self.ledger.calculate_settlement_batch(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            period_start="2026-09-01T00:00:00Z",
            period_end="2026-09-07T23:59:59Z",
            transactions=txs,
            operator="settlement_cron_operator",
        )

        self.assertEqual(batch["grossCapturedMinor"], 200000)
        self.assertEqual(batch["grossRefundedMinor"], 20000)
        self.assertEqual(batch["netCapturedMinor"], 180000)
        # Channel fee: 200000 * 38 // 10000 = 760 minor
        self.assertEqual(batch["channelFeeMinor"], 760)
        # Commission: 180000 * 30 // 10000 = 540 minor
        self.assertEqual(batch["platformCommissionMinor"], 540)
        # Reserve holdback: 180000 * 500 // 10000 = 9000 minor
        self.assertEqual(batch["reserveHoldbackMinor"], 9000)
        # Net payout: 180000 - 760 - 540 - 9000 = 169700 minor ($1697.00)
        self.assertEqual(batch["netPayoutMinor"], 169700)
        self.assertEqual(batch["status"], "CALCULATED")

        # 3. Four-eyes enforcement: Creator cannot approve own batch
        with self.assertRaises(ValidationError) as ctx:
            self.ledger.approve_settlement_payout(
                tenant_id=self.tenant_id,
                batch_id=batch["batchId"],
                approver="settlement_cron_operator",
            )
        self.assertIn("four-eyes principle violation", str(ctx.exception))

        # 4. Independent approval succeeds
        appr_batch = self.ledger.approve_settlement_payout(
            tenant_id=self.tenant_id,
            batch_id=batch["batchId"],
            approver="finance_director_zhang",
        )
        self.assertEqual(appr_batch["status"], "APPROVED")
        self.assertEqual(appr_batch["approvedBy"], "finance_director_zhang")

        # 5. Export banking payout instructions (both CSV and JSON)
        csv_out = self.ledger.export_payout_instructions(self.tenant_id, batch["batchId"], format_type="csv")
        self.assertIn("1697.00", csv_out)
        self.assertIn("6222021001009999888", csv_out)

        json_out = self.ledger.export_payout_instructions(self.tenant_id, batch["batchId"], format_type="json")
        json_data = json.loads(json_out)
        self.assertEqual(json_data["payoutAmountMinor"], 169700)

        # 6. Execute payout with bank reference ID
        exec_batch = self.ledger.execute_settlement_payout(
            tenant_id=self.tenant_id,
            batch_id=batch["batchId"],
            executor="treasury_officer_li",
            bank_reference_id="BK-TRANSFER-20260918-8877",
        )
        self.assertEqual(exec_batch["status"], "EXECUTED")
        self.assertEqual(exec_batch["bankReferenceId"], "BK-TRANSFER-20260918-8877")

        # 7. Render printable settlement voucher HTML
        html_voucher = render_settlement_html(exec_batch, config=config)
        self.assertIn("商户结算与分账对账凭单", html_voucher)
        self.assertIn("1697.00", html_voucher)
        self.assertIn("BK-TRANSFER-20260918-8877", html_voucher)

        # 8. Verify audit chain
        self.assertTrue(self.ledger.verify_settlement_audit_chain(self.tenant_id, batch["batchId"]))

    def test_e3_settlement_minimum_payout_hold(self) -> None:
        """E3: Small payout under minimum threshold is held in ON_HOLD status."""
        self.ledger.configure_merchant_settlement(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            minimum_payout_minor=50000,  # 500 Yuan min
            bank_name="中国银行",
            bank_account_number="123456",
            bank_account_name="小微商户",
        )
        txs = [{"capturedAmountMinor": 1000, "refundedAmountMinor": 0}]  # 10 Yuan
        batch = self.ledger.calculate_settlement_batch(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            period_start="2026-09-01T00:00:00Z",
            period_end="2026-09-02T00:00:00Z",
            transactions=txs,
            operator="op",
        )
        self.assertEqual(batch["status"], "ON_HOLD")
        with self.assertRaises(ValidationError):
            self.ledger.approve_settlement_payout(self.tenant_id, batch["batchId"], approver="other_approver")

    def test_e4_settlement_audit_tamper_detection(self) -> None:
        """E4: Fault injection into SQLite audit records fails closed immediately."""
        self.ledger.configure_merchant_settlement(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            bank_name="招商银行",
            bank_account_number="998877",
            bank_account_name="测试商户",
        )
        batch = self.ledger.calculate_settlement_batch(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            period_start="2026-09-01T00:00:00Z",
            period_end="2026-09-02T00:00:00Z",
            transactions=[{"capturedAmountMinor": 10000}],
            operator="op",
        )
        # Verify initially valid
        self.assertTrue(self.ledger.verify_settlement_audit_chain(self.tenant_id, batch["batchId"]))

        # Inject fraudulent edit into SQLite audit table
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE merchant_settlement_audit SET payload_json=? WHERE batch_id=?",
                ('{"fraudulent": true}', batch["batchId"]),
            )

        # Assert tamper detected
        self.assertFalse(self.ledger.verify_settlement_audit_chain(self.tenant_id, batch["batchId"]))

    def test_e4_concurrent_settlement_batch_calculation(self) -> None:
        """E4: 10 concurrent threads calculating settlement batches on independent date windows."""
        self.ledger.configure_merchant_settlement(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            bank_name="招商银行",
            bank_account_number="998877",
            bank_account_name="测试商户",
        )

        def worker(idx: int) -> str:
            w_ledger = SettlementLedger(self.store)
            b = w_ledger.calculate_settlement_batch(
                tenant_id=self.tenant_id,
                project_id=self.project_id,
                period_start=f"2026-09-0{idx}T00:00:00Z",
                period_end=f"2026-09-0{idx}T23:59:59Z",
                transactions=[{"capturedAmountMinor": 10000 * idx}],
                operator=f"op_{idx}",
            )
            return b["batchId"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(1, 10)]
            batch_ids = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(len(batch_ids), 9)
        self.assertEqual(len(set(batch_ids)), 9)


class TestMerchantDisputeE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_dispute.db"
        self.store = DurableStore(self.db_path)
        self.ledger = DisputeLedger(self.store)
        self.tenant_id = "tenant_dispute_01"
        self.project_id = "project_crossborder"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_dispute_full_lifecycle_won_and_lost(self) -> None:
        """E3: Test incoming dispute -> evidence submission -> win/loss resolution."""
        due_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        # 1. Ingest dispute event from card network
        disp = self.ledger.record_dispute(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id="pi_dispute_target_01",
            dispute_amount_minor=50000,  # $500
            evidence_due_at=due_at,
            currency="USD",
            reason_code="PRODUCT_NOT_RECEIVED",
        )
        self.assertEqual(disp["status"], "NEEDS_RESPONSE")
        self.assertEqual(disp["disputeAmountMinor"], 50000)

        # Duplicate dispute for same payment intent should fail closed
        with self.assertRaises(ValidationError):
            self.ledger.record_dispute(
                tenant_id=self.tenant_id,
                project_id=self.project_id,
                payment_intent_id="pi_dispute_target_01",
                dispute_amount_minor=50000,
                evidence_due_at=due_at,
            )

        # 2. Submit merchant rebuttal evidence
        evidence = {
            "carrier": "DHL Express",
            "trackingNumber": "DHL9988776655",
            "deliveryConfirmationSignature": "John Doe",
            "customerCorrespondence": "Customer confirmed receipt via email on 2026-09-10",
        }
        sub_disp = self.ledger.submit_dispute_evidence(
            tenant_id=self.tenant_id,
            dispute_id=disp["disputeId"],
            evidence=evidence,
            actor_id="dispute_operations_agent",
        )
        self.assertEqual(sub_disp["status"], "UNDER_REVIEW")
        self.assertEqual(sub_disp["evidence"]["carrier"], "DHL Express")

        # 3. Resolve dispute as WON
        won_disp = self.ledger.resolve_dispute(
            tenant_id=self.tenant_id,
            dispute_id=disp["disputeId"],
            outcome="WON",
            actor_id="arbitration_webhook",
        )
        self.assertEqual(won_disp["status"], "WON")
        self.assertIsNotNone(won_disp["resolvedAt"])

        # 4. Verify audit chain
        self.assertTrue(self.ledger.verify_dispute_audit_chain(self.tenant_id, disp["disputeId"]))

        # 5. Second dispute resolving as LOST
        disp2 = self.ledger.record_dispute(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id="pi_dispute_target_02",
            dispute_amount_minor=15000,
            evidence_due_at=due_at,
            reason_code="FRAUDULENT",
        )
        lost_disp = self.ledger.resolve_dispute(
            tenant_id=self.tenant_id,
            dispute_id=disp2["disputeId"],
            outcome="LOST",
            lost_fee_minor=1500,  # $15 chargeback processing fee
            actor_id="visa_network_gateway",
        )
        self.assertEqual(lost_disp["status"], "LOST")
        self.assertEqual(lost_disp["lostFeeMinor"], 1500)
        self.assertTrue(self.ledger.verify_dispute_audit_chain(self.tenant_id, disp2["disputeId"]))

    def test_e3_dispute_expired_evidence_deadline_fails_closed(self) -> None:
        """E3: Submitting rebuttal evidence past the network deadline must fail closed."""
        past_due = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        disp = self.ledger.record_dispute(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id="pi_expired_test",
            dispute_amount_minor=10000,
            evidence_due_at=past_due,
        )
        with self.assertRaises(ValidationError) as ctx:
            self.ledger.submit_dispute_evidence(
                tenant_id=self.tenant_id,
                dispute_id=disp["disputeId"],
                evidence={"info": "late submission"},
                actor_id="agent",
            )
        self.assertIn("expired", str(ctx.exception))

    def test_e4_dispute_audit_tamper_detection(self) -> None:
        """E4: Tampering with dispute audit table must be detected by cryptographic verify."""
        due_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        disp = self.ledger.record_dispute(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id="pi_tamper_disp",
            dispute_amount_minor=30000,
            evidence_due_at=due_at,
        )
        self.assertTrue(self.ledger.verify_dispute_audit_chain(self.tenant_id, disp["disputeId"]))

        with self.store.connect() as conn:
            conn.execute(
                "UPDATE merchant_dispute_audit SET payload_json=? WHERE dispute_id=?",
                ('{"fraudulent": true}', disp["disputeId"]),
            )

        self.assertFalse(self.ledger.verify_dispute_audit_chain(self.tenant_id, disp["disputeId"]))


class TestCliEnterpriseProductivitySuite(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_cli.db"
        self.tenant_id = "tenant_cli_corp"
        self.project_id = "project_cli"

        # Pre-populate title
        store = DurableStore(self.db_path)
        inv_ledger = CustomerInvoiceLedger(store)
        self.title = inv_ledger.save_buyer_title(
            tenant_id=self.tenant_id,
            buyer_type="enterprise",
            buyer_name="CLI自动化企业",
            buyer_tax_number="91310115MA1K4ABCD1",
            is_default=True,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_cli(self, *args: str) -> tuple[int, str]:
        cmd = [sys.executable, "tools/runtime/control.py", *args]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.returncode, res.stdout.strip()

    def test_cli_invoice_batch_and_refund_red_note(self) -> None:
        """CLI: Verify batch-auto, refund-red-note, and batch-render subcommands."""
        manifest_file = Path(self.temp_dir.name) / "manifest.json"
        manifest_file.write_text(json.dumps([
            {"paymentIntentId": "pi_cli_1", "capturedAmountMinor": 10000, "refundedAmountMinor": 0},
            {"paymentIntentId": "pi_cli_2", "capturedAmountMinor": 20000, "refundedAmountMinor": 0},
        ]), encoding="utf-8")

        code, out = self._run_cli(
            "invoice-batch-auto",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--manifest", str(manifest_file),
            "--seller-name", "企业技术服务方",
            "--seller-tax-number", "91110108MA00AAAAAA",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        data = json.loads(out)
        self.assertEqual(data["successCount"], 2)

        # Refund-red-note CLI
        code, out = self._run_cli(
            "invoice-refund-red-note",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--payment-intent", "pi_cli_1",
            "--refund-minor", "4000",
            "--operator", "cli_tester",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        ref_data = json.loads(out)
        self.assertEqual(ref_data["creditedAmountMinor"], 4000)

        # Batch render CLI
        booklet_file = Path(self.temp_dir.name) / "booklet.html"
        code, out = self._run_cli(
            "invoice-batch-render",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--out", str(booklet_file),
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        self.assertTrue(booklet_file.exists())
        self.assertIn("企业电子发票批量装订归档册", booklet_file.read_text(encoding="utf-8"))

    def test_cli_settlement_and_dispute_suite(self) -> None:
        """CLI: Verify settlement config/batch/approve/execute and dispute record/resolve."""
        # 1. settlement-config
        code, out = self._run_cli(
            "settlement-config",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--project", self.project_id,
            "--bank-name", "浦发银行上海张江支行",
            "--bank-acc", "987654321",
            "--bank-acc-name", "测试结算户名",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")

        # 2. settlement-batch
        tx_file = Path(self.temp_dir.name) / "transactions.json"
        tx_file.write_text(json.dumps([
            {"capturedAmountMinor": 50000, "refundedAmountMinor": 0}
        ]), encoding="utf-8")
        code, out = self._run_cli(
            "settlement-batch",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--project", self.project_id,
            "--period-start", "2026-09-01T00:00:00Z",
            "--period-end", "2026-09-07T23:59:59Z",
            "--transactions", str(tx_file),
            "--operator", "cli_operator",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        batch = json.loads(out)
        batch_id = batch["batchId"]

        # 3. settlement-approve (four-eyes: different approver)
        code, out = self._run_cli(
            "settlement-approve",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--batch-id", batch_id,
            "--approver", "cli_finance_manager",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")

        # 4. settlement-execute
        code, out = self._run_cli(
            "settlement-execute",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--batch-id", batch_id,
            "--executor", "cli_treasury_lead",
            "--bank-ref", "CLI-BANK-REF-9988",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")

        # 5. settlement-audit-verify
        code, out = self._run_cli(
            "settlement-audit-verify",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--batch-id", batch_id,
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        self.assertTrue(json.loads(out)["auditChainValid"])

        # 6. dispute-record
        code, out = self._run_cli(
            "dispute-record",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--project", self.project_id,
            "--payment-intent", "pi_cli_disp",
            "--amount-minor", "12000",
            "--due-at", "2026-10-01T00:00:00Z",
            "--reason", "FRAUDULENT",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        disp_id = json.loads(out)["disputeId"]

        # 7. dispute-resolve
        code, out = self._run_cli(
            "dispute-resolve",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--dispute-id", disp_id,
            "--outcome", "WON",
            "--actor", "network_judge",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")

        # 8. dispute-audit-verify
        code, out = self._run_cli(
            "dispute-audit-verify",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--dispute-id", disp_id,
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        self.assertTrue(json.loads(out)["auditChainValid"])


if __name__ == "__main__":
    unittest.main()
