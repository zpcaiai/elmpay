"""Enterprise Customer Invoice Lifecycle E3 & E4 test suite.

Covers:
- E3: Multi-payment consolidated invoicing with strict anti-double-invoicing
- E3: China National Standard GB/T 33190-2016 OFD manifest rendering & cryptographic digest verification
- E3: Golden Tax 4-element invoice verification (code, number, date, check code/untaxed amount)
- E3: Expense reimbursement claim registration & anti-duplication prevention
- E3: Multi-channel delivery (Email, SMS, Webhook) & dispatch logging
- E3: Accounts receivable invoice-to-cash settlement & write-off lifecycle
- E4: 20-thread concurrent reimbursement claim race condition (strictly 1 winner, 19 blocked)
- E4: 10-thread concurrent settlement write-off race condition (strictly prevents balance over-settlement)
- CLI: End-to-end subprocess integration across all 9 new control commands
"""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any
import unittest
import uuid

from tools.runtime.elmpay_runtime.common import ValidationError
from tools.runtime.elmpay_runtime.durable import DurableStore
from tools.runtime.elmpay_runtime.invoice import (
    CustomerInvoiceLedger,
    render_invoice_ofd_manifest,
    verify_invoice_ofd_manifest,
)


class EnterpriseInvoiceLifecycleE3Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "lifecycle_test.db"
        self.store = DurableStore(self.db_path)
        self.ledger = CustomerInvoiceLedger(self.store)
        self.tenant_id = "tenant_enterprise_life"
        self.project_id = "proj_fintech"
        self.now = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)

        self.seller_info = {
            "sellerName": "云支付科技有限公司",
            "sellerTaxNumber": "91110108MA00ABC012",
            "sellerAddressPhone": "北京市海淀区科技园路8号 010-88888888",
            "sellerBankAccount": "中国工商银行北京分行 110200300400500",
        }
        self.buyer_info = {
            "buyerType": "enterprise",
            "buyerName": "北京智航物流技术有限公司",
            "buyerTaxNumber": "91110105MA00XYZ987",
            "buyerAddressPhone": "北京市朝阳区物流港A座 010-66666666",
            "buyerBankAccount": "招商银行北京建国门支行 010123456789012",
            "recipientEmail": "finance@zhihang-logistics.com",
            "recipientPhone": "13800138000",
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_multi_payment_consolidated_invoicing(self) -> None:
        """E3: Consolidate multiple small payment intents into a single compliant invoice."""
        pi_ids = [f"pi_micro_{uuid.uuid4().hex[:8]}" for _ in range(3)]
        amounts = {pi_ids[0]: 5000, pi_ids[1]: 8000, pi_ids[2]: 12000}

        inv = self.ledger.consolidate_and_apply_invoice(
            self.tenant_id,
            pi_ids,
            project_id=self.project_id,
            buyer_info=self.buyer_info,
            seller_info=self.seller_info,
            invoice_title="企业物流SaaS云服务费",
            payment_amounts_minor=amounts,
            operator="fin_operator_amy",
            now=self.now,
        )

        self.assertEqual(inv["status"], "ISSUED")
        self.assertEqual(inv["totalAmountMinor"], 25000)
        self.assertEqual(len(inv["items"]), 3)
        self.assertEqual(sorted(inv["consolidatedPaymentIntentIds"]), sorted(pi_ids))

        # Re-invoicing any of the payment intents must fail closed
        with self.assertRaises(ValidationError) as ctx:
            self.ledger.consolidate_and_apply_invoice(
                self.tenant_id,
                [pi_ids[1], f"pi_new_{uuid.uuid4().hex[:6]}"],
                project_id=self.project_id,
                buyer_info=self.buyer_info,
                seller_info=self.seller_info,
                operator="fin_operator_bob",
                now=self.now,
            )
        self.assertIn("has already been invoiced", str(ctx.exception))

    def test_china_national_standard_ofd_manifest_and_verification(self) -> None:
        """E3: Render China National Standard GB/T 33190-2016 OFD manifest and verify digital digest."""
        pi_id = f"pi_ofd_{uuid.uuid4().hex[:8]}"
        applied = self.ledger.apply_invoice(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=10600,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="enterprise",
            buyer_name=self.buyer_info["buyerName"],
            buyer_tax_number=self.buyer_info["buyerTaxNumber"],
            seller_name=self.seller_info["sellerName"],
            seller_tax_number=self.seller_info["sellerTaxNumber"],
            operator="op_ofd",
            items=[{
                "itemName": "软件技术开发与支持服务",
                "specification": "v2.0",
                "unit": "套",
                "quantity": 1,
                "unitPriceMinor": 10000,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "1070101010000000000",
            }],
            now=self.now,
        )
        issued = self.ledger.issue_invoice(
            self.tenant_id,
            applied["invoiceId"],
            actor="actor_ofd",
            checker="王复核",
            payee="张收款",
            now=self.now,
        )

        ofd_xml = render_invoice_ofd_manifest(issued)
        self.assertIn("<OFDInvoicePackage", ofd_xml)
        self.assertIn('standard="GB/T 33190-2016"', ofd_xml)
        self.assertIn("<DigestValue>", ofd_xml)
        self.assertIn("<SignatureMethod>1.2.156.10197.1.501</SignatureMethod>", ofd_xml)
        self.assertIn(issued["invoiceNumber"], ofd_xml)

        # Verification passes on untampered manifest
        v_res = verify_invoice_ofd_manifest(ofd_xml, issued)
        self.assertTrue(v_res["valid"])
        self.assertTrue(v_res["digestMatched"])
        self.assertEqual(v_res["invoiceNumber"], issued["invoiceNumber"])

        # Tampering with manifest content triggers cryptographic digest mismatch
        tampered_xml = ofd_xml.replace("<TotalAmountMinor>10600</TotalAmountMinor>", "<TotalAmountMinor>99999</TotalAmountMinor>")
        t_res = verify_invoice_ofd_manifest(tampered_xml, issued)
        self.assertFalse(t_res["valid"])
        self.assertEqual(t_res["reason"], "digest_mismatch_tamper_detected")

    def test_four_element_invoice_verification_and_anti_fraud(self) -> None:
        """E3: Golden Tax 4-element verification for normal and special VAT invoices."""
        pi_id = f"pi_v4_{uuid.uuid4().hex[:8]}"
        applied = self.ledger.apply_invoice(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=21200,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="enterprise",
            buyer_name=self.buyer_info["buyerName"],
            buyer_tax_number=self.buyer_info["buyerTaxNumber"],
            seller_name=self.seller_info["sellerName"],
            seller_tax_number=self.seller_info["sellerTaxNumber"],
            operator="op_v4",
            items=[{
                "itemName": "云计算基础资源租赁",
                "specification": "Standard-8C16G",
                "unit": "月",
                "quantity": 2,
                "unitPriceMinor": 10000,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "3040201010000000000",
            }],
            now=self.now,
        )
        issued = self.ledger.issue_invoice(
            self.tenant_id,
            applied["invoiceId"],
            actor="actor_v4",
            now=self.now,
        )

        code = issued["invoiceCode"]
        num = issued["invoiceNumber"]
        date_str = issued["issuedAt"][:10]
        vcode = issued["verificationCode"]
        last6 = vcode[-6:]

        # Normal invoice 4-element matching with last 6 digits
        res = self.ledger.verify_invoice_four_elements(
            self.tenant_id,
            invoice_code=code,
            invoice_number=num,
            issued_date=date_str,
            check_code_or_amount=last6,
            invoice_type="vat_electronic_normal",
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["status"], "VERIFIED_AUTHENTIC")

        # Wrong date mismatch
        res_wrong_date = self.ledger.verify_invoice_four_elements(
            self.tenant_id,
            invoice_code=code,
            invoice_number=num,
            issued_date="2025-01-01",
            check_code_or_amount=last6,
        )
        self.assertFalse(res_wrong_date["verified"])
        self.assertEqual(res_wrong_date["status"], "DATE_MISMATCH")

        # Wrong check code mismatch
        res_wrong_code = self.ledger.verify_invoice_four_elements(
            self.tenant_id,
            invoice_code=code,
            invoice_number=num,
            issued_date=date_str,
            check_code_or_amount="000000",
        )
        self.assertFalse(res_wrong_code["verified"])
        self.assertEqual(res_wrong_code["status"], "CHECK_CODE_MISMATCH")

    def test_invoice_reimbursement_claim_and_anti_duplication(self) -> None:
        """E3: Expense reimbursement claim registration & strict anti-duplication prevention."""
        pi_id = f"pi_reimb_{uuid.uuid4().hex[:8]}"
        applied = self.ledger.apply_invoice(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=5300,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="enterprise",
            buyer_name=self.buyer_info["buyerName"],
            buyer_tax_number=self.buyer_info["buyerTaxNumber"],
            seller_name=self.seller_info["sellerName"],
            seller_tax_number=self.seller_info["sellerTaxNumber"],
            operator="op_reimb",
            items=[{
                "itemName": "出差差旅费-云端办公席位",
                "specification": "P1",
                "unit": "人月",
                "quantity": 1,
                "unitPriceMinor": 5000,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "304020101",
            }],
            now=self.now,
        )
        issued = self.ledger.issue_invoice(self.tenant_id, applied["invoiceId"], actor="actor_reimb", now=self.now)
        inv_id = issued["invoiceId"]

        # Initially un-reimbursed
        status_before = self.ledger.get_reimbursement_status(self.tenant_id, inv_id)
        self.assertFalse(status_before["reimbursed"])

        # Register reimbursement claim
        claim = self.ledger.register_invoice_reimbursement(
            self.tenant_id,
            invoice_id=inv_id,
            claim_id="EXP_CLAIM_2026_09_001",
            claimant="李研发",
            department="云计算架构部",
            expense_category="差旅办公",
            now=self.now,
        )
        self.assertEqual(claim["status"], "APPROVED")
        self.assertEqual(claim["claimant"], "李研发")

        status_after = self.ledger.get_reimbursement_status(self.tenant_id, inv_id)
        self.assertTrue(status_after["reimbursed"])
        self.assertEqual(status_after["claimId"], "EXP_CLAIM_2026_09_001")

        # Second attempt to claim the exact same invoice must fail closed
        with self.assertRaises(ValidationError) as ctx:
            self.ledger.register_invoice_reimbursement(
                self.tenant_id,
                invoice_id=inv_id,
                claim_id="EXP_CLAIM_2026_09_999",
                claimant="张财务",
                department="财务部",
                expense_category="重复入账测试",
                now=self.now,
            )
        self.assertIn("has already been reimbursed in claim", str(ctx.exception))

    def test_multi_channel_invoice_delivery_and_retry(self) -> None:
        """E3: Multi-channel delivery across Email, SMS, Webhook with dispatch audit."""
        pi_id = f"pi_dlv_{uuid.uuid4().hex[:8]}"
        applied = self.ledger.apply_invoice(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=10000,
            refunded_amount_minor=0,
            invoice_type="commercial_receipt",
            buyer_type="individual",
            buyer_name="王用户",
            seller_name=self.seller_info["sellerName"],
            seller_tax_number=self.seller_info["sellerTaxNumber"],
            operator="op_dlv",
            items=[{
                "itemName": "会员增值订阅服务",
                "specification": "VIP",
                "unit": "年",
                "quantity": 1,
                "unitPriceMinor": 10000,
                "taxRateBasisPoints": 0,
            }],
            now=self.now,
        )
        issued = self.ledger.issue_invoice(self.tenant_id, applied["invoiceId"], actor="actor_dlv", now=self.now)
        inv_id = issued["invoiceId"]

        deliveries = self.ledger.deliver_invoice(
            self.tenant_id,
            inv_id,
            channels=["EMAIL", "SMS", "WEBHOOK"],
            destinations={
                "EMAIL": "wang@example.com",
                "SMS": "13912345678",
                "WEBHOOK": "https://erp.example.com/webhooks/invoice",
            },
            actor="notif_service",
            now=self.now,
        )
        self.assertEqual(len(deliveries), 3)

        history = self.ledger.get_invoice_delivery_history(self.tenant_id, inv_id)
        self.assertEqual(len(history), 3)
        self.assertEqual({h["channel"] for h in history}, {"EMAIL", "SMS", "WEBHOOK"})

        # Retry the email delivery
        first_id = history[0]["deliveryId"]
        retry_res = self.ledger.retry_invoice_delivery(self.tenant_id, first_id, now=self.now)
        self.assertEqual(retry_res["attempts"], 2)

    def test_accounts_receivable_invoice_to_cash_settlement(self) -> None:
        """E3: Invoice-to-cash settlement write-off lifecycle (UNSETTLED -> PARTIALLY -> FULLY)."""
        pi_id = f"pi_recon_{uuid.uuid4().hex[:8]}"
        applied = self.ledger.apply_invoice(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=50000,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="enterprise",
            buyer_name=self.buyer_info["buyerName"],
            buyer_tax_number=self.buyer_info["buyerTaxNumber"],
            seller_name=self.seller_info["sellerName"],
            seller_tax_number=self.seller_info["sellerTaxNumber"],
            operator="op_recon",
            items=[{
                "itemName": "企业年度技术维保与支持协议",
                "specification": "Standard",
                "unit": "年",
                "quantity": 1,
                "unitPriceMinor": 47170,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "3040201020000000000",
            }],
            now=self.now,
        )
        issued = self.ledger.issue_invoice(self.tenant_id, applied["invoiceId"], actor="actor_recon", now=self.now)
        inv_id = issued["invoiceId"]

        # Initial status
        st0 = self.ledger.get_invoice_settlement_status(self.tenant_id, inv_id)
        self.assertEqual(st0["settlementStatus"], "UNSETTLED")
        self.assertEqual(st0["settledAmountMinor"], 0)
        self.assertEqual(st0["unsettledAmountMinor"], issued["totalAmountMinor"])

        total = issued["totalAmountMinor"]
        first_settle = total // 2

        # Step 1: Partial settlement write-off
        r1 = self.ledger.reconcile_invoice_settlement(
            self.tenant_id,
            inv_id,
            settlement_ref="BANK_WIRE_20260901_001",
            amount_minor=first_settle,
            operator="cfo_claire",
            notes="收到北京智航物流首期对公电汇款",
            now=self.now,
        )
        self.assertEqual(r1["settlementStatus"], "PARTIALLY_SETTLED")
        self.assertEqual(r1["settledAmountMinor"], first_settle)
        self.assertEqual(r1["unsettledAmountMinor"], total - first_settle)

        # Step 2: Attempting to settle more than the remaining balance must fail closed
        with self.assertRaises(ValidationError) as ctx:
            self.ledger.reconcile_invoice_settlement(
                self.tenant_id,
                inv_id,
                settlement_ref="BANK_WIRE_OVER",
                amount_minor=total,
                operator="cfo_claire",
                now=self.now,
            )
        self.assertIn("exceeds remaining unsettled balance", str(ctx.exception))

        # Step 3: Settle the remaining balance in full
        r2 = self.ledger.reconcile_invoice_settlement(
            self.tenant_id,
            inv_id,
            settlement_ref="BANK_WIRE_20260902_002",
            amount_minor=total - first_settle,
            operator="cfo_claire",
            notes="收到北京智航物流尾期对公电汇款",
            now=self.now,
        )
        self.assertEqual(r2["settlementStatus"], "FULLY_SETTLED")
        self.assertEqual(r2["settledAmountMinor"], total)
        self.assertEqual(r2["unsettledAmountMinor"], 0)

        st_final = self.ledger.get_invoice_settlement_status(self.tenant_id, inv_id)
        self.assertEqual(st_final["settlementStatus"], "FULLY_SETTLED")
        self.assertEqual(len(st_final["reconciliations"]), 2)


class EnterpriseInvoiceLifecycleE4Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "lifecycle_e4.db"
        self.store = DurableStore(self.db_path)
        self.ledger = CustomerInvoiceLedger(self.store)
        self.tenant_id = "tenant_e4_concurrency"
        self.project_id = "proj_e4"
        self.now = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e4_concurrent_reimbursement_claim_race(self) -> None:
        """E4: 20 concurrent threads race to claim the same invoice for reimbursement."""
        pi_id = f"pi_e4_rmb_{uuid.uuid4().hex[:8]}"
        applied = self.ledger.apply_invoice(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=8000,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="individual",
            buyer_name="竞态测试用户",
            seller_name="云支付科技",
            seller_tax_number="91110108MA00ABC012",
            operator="op_e4",
            items=[{"itemName": "项目测试支出", "quantity": 1, "unitPriceMinor": 8000, "taxRateBasisPoints": 0}],
            now=self.now,
        )
        issued = self.ledger.issue_invoice(self.tenant_id, applied["invoiceId"], actor="op_e4", now=self.now)
        inv_id = issued["invoiceId"]

        thread_count = 20
        results: list[dict[str, Any]] = []
        errors: list[str] = []

        def worker(worker_id: int) -> None:
            ledger = CustomerInvoiceLedger(self.store)
            try:
                res = ledger.register_invoice_reimbursement(
                    self.tenant_id,
                    invoice_id=inv_id,
                    claim_id=f"CLAIM_RACE_{worker_id}",
                    claimant=f"员工_{worker_id}",
                    department="技术部",
                    expense_category="差旅",
                    now=self.now,
                )
                results.append(res)
            except ValidationError as err:
                errors.append(str(err))

        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(worker, i) for i in range(thread_count)]
            concurrent.futures.wait(futures)

        # Invariant: Exactly 1 thread successfully claims the invoice, and exactly 19 fail with duplication error
        self.assertEqual(len(results), 1, f"Expected exactly 1 claim winner, got {len(results)}")
        self.assertEqual(len(errors), thread_count - 1)
        for err in errors:
            self.assertIn("has already been reimbursed in claim", err)

        # Verify database has strictly 1 record
        with self.store.connect() as conn:
            cnt = conn.execute(
                "SELECT COUNT(*) as c FROM customer_invoice_reimbursement WHERE tenant_id=? AND invoice_id=?",
                (self.tenant_id, inv_id),
            ).fetchone()["c"]
            self.assertEqual(cnt, 1)

    def test_e4_concurrent_settlement_reconciliation_race(self) -> None:
        """E4: 10 concurrent threads attempt write-offs on the same invoice; cannot over-settle balance."""
        total_minor = 10000
        pi_id = f"pi_e4_recon_{uuid.uuid4().hex[:8]}"
        applied = self.ledger.apply_invoice(
            tenant_id=self.tenant_id,
            project_id=self.project_id,
            payment_intent_id=pi_id,
            captured_amount_minor=total_minor,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="enterprise",
            buyer_name="高并发客户",
            buyer_tax_number="91110105MA00XYZ987",
            seller_name="云支付科技",
            seller_tax_number="91110108MA00ABC012",
            operator="op_e4",
            items=[{"itemName": "服务费", "quantity": 1, "unitPriceMinor": total_minor, "taxRateBasisPoints": 0}],
            now=self.now,
        )
        issued = self.ledger.issue_invoice(self.tenant_id, applied["invoiceId"], actor="op_e4", now=self.now)
        inv_id = issued["invoiceId"]

        thread_count = 10
        chunk_size = 2000  # Total capacity: 10000 / 2000 = exactly 5 can succeed

        successes: list[dict[str, Any]] = []
        blocked: list[str] = []

        def worker(worker_id: int) -> None:
            ledger = CustomerInvoiceLedger(self.store)
            try:
                res = ledger.reconcile_invoice_settlement(
                    self.tenant_id,
                    inv_id,
                    settlement_ref=f"WIRE_CONCUR_{worker_id}",
                    amount_minor=chunk_size,
                    operator=f"accountant_{worker_id}",
                    now=self.now,
                )
                successes.append(res)
            except ValidationError as err:
                blocked.append(str(err))

        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(worker, i) for i in range(thread_count)]
            concurrent.futures.wait(futures)

        # Invariant: At most 5 threads can succeed, exactly 5 threads blocked
        self.assertEqual(len(successes), 5)
        self.assertEqual(len(blocked), 5)
        for b in blocked:
            self.assertIn("exceeds remaining unsettled balance", b)

        final_st = self.ledger.get_invoice_settlement_status(self.tenant_id, inv_id)
        self.assertEqual(final_st["settledAmountMinor"], total_minor)
        self.assertEqual(final_st["unsettledAmountMinor"], 0)
        self.assertEqual(final_st["settlementStatus"], "FULLY_SETTLED")


class EnterpriseInvoiceLifecycleCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "cli_test.db"
        self.store = DurableStore(self.db_path)
        self.ledger = CustomerInvoiceLedger(self.store)
        self.tenant = "tenant_cli_enterprise"
        self.script_path = str(Path(__file__).resolve().parents[1] / "tools/runtime/control.py")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, self.script_path, *args]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_consolidate_and_verify(self) -> None:
        """CLI: invoice-consolidate and invoice-verify-four-elements."""
        res = self._run_cli(
            "invoice-consolidate",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--payment-intents", "pi_batch_001,pi_batch_002",
            "--buyer-name", "深圳前海智能科技有限公司",
            "--buyer-tax-id", "91440300MA5EXXXX11",
            "--seller-name", "云支付科技有限公司",
            "--seller-tax-number", "91110108MA00ABC012",
            "--operator", "cli_tester",
            "--title", "企业多订单合并技术费",
        )
        self.assertEqual(res.returncode, 0, f"CLI error: {res.stderr}")
        data = json.loads(res.stdout)
        self.assertEqual(data["status"], "ISSUED")
        self.assertEqual(len(data["consolidatedPaymentIntentIds"]), 2)

        code = data["invoiceCode"]
        num = data["invoiceNumber"]
        date_str = data["issuedAt"][:10]
        vcode = data["verificationCode"]

        # Verify 4 elements via CLI
        v_res = self._run_cli(
            "invoice-verify-four-elements",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--invoice-code", code,
            "--invoice-number", num,
            "--issued-date", date_str,
            "--check-code-or-amount", vcode[-6:],
        )
        self.assertEqual(v_res.returncode, 0)
        v_data = json.loads(v_res.stdout)
        self.assertTrue(v_data["verified"])

    def test_cli_reimburse_deliver_reconcile_ofd(self) -> None:
        """CLI: reimbursement, delivery, settlement reconciliation, and OFD manifest rendering."""
        # 1. First consolidate/apply an invoice
        res = self._run_cli(
            "invoice-consolidate",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--payment-intents", "pi_flow_001",
            "--buyer-name", "上海鼎盛供应链管理有限公司",
            "--buyer-tax-id", "91110105MA00XYZ987",
            "--seller-name", "云支付科技有限公司",
            "--seller-tax-number", "91110108MA00ABC012",
            "--operator", "cli_flow",
        )
        self.assertEqual(res.returncode, 0)
        inv = json.loads(res.stdout)
        inv_id = inv["invoiceId"]

        # 2. Test invoice-deliver and invoice-deliver-status
        del_res = self._run_cli(
            "invoice-deliver",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--invoice-id", inv_id,
            "--channels", "EMAIL,SMS",
            "--email", "finance@dingsheng.com",
            "--sms", "13800001111",
        )
        self.assertEqual(del_res.returncode, 0)
        del_data = json.loads(del_res.stdout)
        self.assertEqual(len(del_data["deliveries"]), 2)

        del_st = self._run_cli(
            "invoice-deliver-status",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--invoice-id", inv_id,
        )
        self.assertEqual(del_st.returncode, 0)
        st_data = json.loads(del_st.stdout)
        self.assertEqual(len(st_data["history"]), 2)

        # 3. Test invoice-reimburse-claim and invoice-reimburse-status
        rmb_res = self._run_cli(
            "invoice-reimburse-claim",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--invoice-id", inv_id,
            "--claim-id", "EXP_20260918_CLI",
            "--claimant", "赵工程",
            "--department", "平台部",
            "--expense-category", "技术开发",
        )
        self.assertEqual(rmb_res.returncode, 0)

        rmb_st = self._run_cli(
            "invoice-reimburse-status",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--invoice-id", inv_id,
        )
        self.assertEqual(rmb_st.returncode, 0)
        self.assertTrue(json.loads(rmb_st.stdout)["reimbursed"])

        # 4. Test invoice-reconcile-settlement and invoice-settlement-status
        total = inv["totalAmountMinor"]
        rec_res = self._run_cli(
            "invoice-reconcile-settlement",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--invoice-id", inv_id,
            "--settlement-ref", "WIRE_CLI_001",
            "--amount-minor", str(total),
            "--operator", "cli_treasurer",
        )
        self.assertEqual(rec_res.returncode, 0)
        self.assertEqual(json.loads(rec_res.stdout)["settlementStatus"], "FULLY_SETTLED")

        rec_st = self._run_cli(
            "invoice-settlement-status",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--invoice-id", inv_id,
        )
        self.assertEqual(rec_st.returncode, 0)
        self.assertEqual(json.loads(rec_st.stdout)["settlementStatus"], "FULLY_SETTLED")

        # 5. Test invoice-ofd-render
        ofd_file = Path(self.temp_dir.name) / "invoice.ofd.xml"
        ofd_res = self._run_cli(
            "invoice-ofd-render",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--invoice-id", inv_id,
            "--out", str(ofd_file),
        )
        self.assertEqual(ofd_res.returncode, 0)
        self.assertTrue(ofd_file.exists())
        self.assertIn("<OFDInvoicePackage", ofd_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
