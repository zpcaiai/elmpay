from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError, sha256_json
from elmpay_runtime.durable import DurableStore
from elmpay_runtime.invoice import (
    CustomerInvoiceLedger,
    calculate_vat_breakdown,
    generate_verification_code,
    validate_buyer_info,
)

NOW = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)


class CustomerInvoiceE1E2Test(unittest.TestCase):
    """Level E1 Unit and Level E2 Component/Persistence Integration Tests."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = str(Path(self.temporary.name) / "test_invoice.db")
        self.ledger = CustomerInvoiceLedger(self.db_path)

    def test_e1_vat_breakdown_precision_and_rounding(self) -> None:
        items = [
            {
                "itemName": "云服务技术咨询费",
                "specification": "标准企业版",
                "unit": "月",
                "quantity": 3,
                "unitPriceMinor": 33333,  # 333.33 CNY each -> total 999.99 CNY (99999 minor)
                "taxRateBasisPoints": 600,  # 6%
            },
            {
                "itemName": "服务器硬件代维",
                "quantity": 1,
                "unitPriceMinor": 100000,  # 1000.00 CNY
                "taxRateBasisPoints": 1300,  # 13%
            },
        ]
        breakdown = calculate_vat_breakdown(items)
        # Line 1: 99999 * 600 / 10000 = 5999.94 -> 6000 minor
        # Line 2: 100000 * 1300 / 10000 = 13000 minor
        self.assertEqual(2, len(breakdown.lines))
        self.assertEqual(99999, breakdown.lines[0].amount_minor)
        self.assertEqual(6000, breakdown.lines[0].tax_amount_minor)
        self.assertEqual(100000, breakdown.lines[1].amount_minor)
        self.assertEqual(13000, breakdown.lines[1].tax_amount_minor)
        self.assertEqual(199999, breakdown.untaxed_amount_minor)
        self.assertEqual(19000, breakdown.tax_amount_minor)
        self.assertEqual(218999, breakdown.total_amount_minor)

    def test_e1_buyer_info_validation(self) -> None:
        # Valid cases
        validate_buyer_info("enterprise", "北京测试科技有限公司", "91110000000000001X")
        validate_buyer_info("enterprise", "上海某外资企业", "123456789012345")
        validate_buyer_info("individual", "张三", None)
        validate_buyer_info("government", "某省财政厅", None)

        # Invalid cases
        with self.assertRaises(ValidationError):
            validate_buyer_info("alien", "张三", None)
        with self.assertRaises(ValidationError):
            validate_buyer_info("enterprise", "短", "91110000000000001X")
        with self.assertRaises(ValidationError):
            validate_buyer_info("enterprise", "缺少税号企业", None)
        with self.assertRaises(ValidationError):
            validate_buyer_info("enterprise", "非法税号企业", "12345")  # Too short

    def test_e2_buyer_title_management_and_default_toggle(self) -> None:
        t1 = self.ledger.save_buyer_title(
            "tenant-1",
            "enterprise",
            "第一企业抬头",
            buyer_tax_number="91110000000000001X",
            is_default=True,
            now=NOW,
        )
        t2 = self.ledger.save_buyer_title(
            "tenant-1",
            "enterprise",
            "第二企业抬头",
            buyer_tax_number="91110000000000002Y",
            is_default=True,  # Should demote t1 from default
            now=NOW + timedelta(seconds=1),
        )

        titles = self.ledger.list_buyer_titles("tenant-1")
        self.assertEqual(2, len(titles))
        # Second title must be the sole default
        self.assertEqual(t2["titleId"], titles[0]["titleId"])
        self.assertTrue(titles[0]["isDefault"])
        self.assertEqual(t1["titleId"], titles[1]["titleId"])
        self.assertFalse(titles[1]["isDefault"])


class CustomerInvoiceE3SystemLifecycleTest(unittest.TestCase):
    """Level E3 System and End-to-End Enterprise Invoicing Workflows."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = str(Path(self.temporary.name) / "test_invoice_e3.db")
        self.ledger = CustomerInvoiceLedger(self.db_path)

    def test_e3_full_invoice_positive_lifecycle_and_verification(self) -> None:
        # Step 1: Apply for an invoice
        applied = self.ledger.apply_invoice(
            tenant_id="tenant-alpha",
            project_id="proj-1",
            payment_intent_id="pi_1001",
            captured_amount_minor=100000,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="enterprise",
            buyer_name="腾讯科技（深圳）有限公司",
            buyer_tax_number="91440300708461136T",
            seller_name="榆钱儿支付科技有限公司",
            seller_tax_number="91110108MA01XXXXXX",
            operator="billing-agent-01",
            items=[
                {
                    "itemName": "企业版软件服务年费",
                    "quantity": 1,
                    "unitPriceMinor": 88496,  # 884.96 CNY untaxed + 115.04 CNY tax = 1000.00 CNY total
                    "taxRateBasisPoints": 1300,  # 13%
                }
            ],
            now=NOW,
        )
        self.assertEqual("APPLIED", applied["status"])
        self.assertEqual(100000, applied["totalAmountMinor"])
        self.assertEqual("blue", applied["invoiceCategory"])
        self.assertIsNone(applied["verificationCode"])

        # Invoicable balance should now be 0
        bal = self.ledger.calculate_invoicable_balance("tenant-alpha", "pi_1001", 100000, 0)
        self.assertEqual(0, bal)

        # Step 2: Issue invoice by finance checker
        issued = self.ledger.issue_invoice(
            "tenant-alpha",
            applied["invoiceId"],
            actor="finance-checker-01",
            checker="finance-lead",
            payee="榆钱儿出纳",
            now=NOW + timedelta(minutes=5),
        )
        self.assertEqual("ISSUED", issued["status"])
        self.assertIsNotNone(issued["verificationCode"])
        self.assertEqual(20, len(issued["verificationCode"]))
        self.assertIn(f"/v1/invoices/{applied['invoiceId']}/download", issued["downloadUrl"])

        # Step 3: Verify invoice externally using deterministic verification code
        v_result = self.ledger.verify_invoice(
            "tenant-alpha",
            applied["invoiceId"],
            issued["verificationCode"],
        )
        self.assertTrue(v_result["valid"])
        self.assertEqual(100000, v_result["totalAmountMinor"])
        self.assertEqual("腾讯科技（深圳）有限公司", v_result["buyerName"])

        # Fraudulent code fails verification
        fake_result = self.ledger.verify_invoice(
            "tenant-alpha",
            applied["invoiceId"],
            "00000000000000000000",
        )
        self.assertFalse(fake_result["valid"])
        self.assertEqual("verification_code_mismatch", fake_result["reason"])

    def test_e3_anti_over_invoicing_with_refund_boundary(self) -> None:
        captured = 100000
        refunded = 30000
        bal = self.ledger.calculate_invoicable_balance("tenant-beta", "pi_2002", captured, refunded)
        self.assertEqual(70000, bal)

        # Attempting to invoice 70001 minor must fail closed
        with self.assertRaises(ValidationError) as cm:
            self.ledger.apply_invoice(
                tenant_id="tenant-beta",
                project_id="proj-1",
                payment_intent_id="pi_2002",
                captured_amount_minor=captured,
                refunded_amount_minor=refunded,
                invoice_type="vat_electronic_normal",
                buyer_type="individual",
                buyer_name="李四",
                seller_name="榆钱儿科技",
                seller_tax_number="91110108MA01XXXXXX",
                operator="op",
                items=[{"itemName": "咨询服务", "quantity": 1, "unitPriceMinor": 70001, "taxRateBasisPoints": 0}],
                now=NOW,
            )
        self.assertIn("exceeds invoicable balance", str(cm.exception))

        # Invoicing 40000 minor succeeds
        inv1 = self.ledger.apply_invoice(
            tenant_id="tenant-beta",
            project_id="proj-1",
            payment_intent_id="pi_2002",
            captured_amount_minor=captured,
            refunded_amount_minor=refunded,
            invoice_type="vat_electronic_normal",
            buyer_type="individual",
            buyer_name="李四",
            seller_name="榆钱儿科技",
            seller_tax_number="91110108MA01XXXXXX",
            operator="op",
            items=[{"itemName": "咨询服务第1期", "quantity": 1, "unitPriceMinor": 40000, "taxRateBasisPoints": 0}],
            now=NOW,
        )
        self.assertEqual(40000, inv1["totalAmountMinor"])

        # Remaining invoicable balance is now 30000
        bal2 = self.ledger.calculate_invoicable_balance("tenant-beta", "pi_2002", captured, refunded)
        self.assertEqual(30000, bal2)

        # A further refund of 25000 occurs -> total refunded becomes 55000.
        # Net paid = 100000 - 55000 = 45000.
        # Active invoice = 40000.
        # Remaining invoicable = max(0, 45000 - 40000) = 5000.
        refunded = 55000
        bal3 = self.ledger.calculate_invoicable_balance("tenant-beta", "pi_2002", captured, refunded)
        self.assertEqual(5000, bal3)

        # Attempting to invoice 10000 fails closed
        with self.assertRaises(ValidationError):
            self.ledger.apply_invoice(
                tenant_id="tenant-beta",
                project_id="proj-1",
                payment_intent_id="pi_2002",
                captured_amount_minor=captured,
                refunded_amount_minor=refunded,
                invoice_type="vat_electronic_normal",
                buyer_type="individual",
                buyer_name="李四",
                seller_name="榆钱儿科技",
                seller_tax_number="91110108MA01XXXXXX",
                operator="op",
                items=[{"itemName": "咨询服务第2期", "quantity": 1, "unitPriceMinor": 10000, "taxRateBasisPoints": 0}],
                now=NOW,
            )

        # Invoicing exactly 5000 succeeds
        inv2 = self.ledger.apply_invoice(
            tenant_id="tenant-beta",
            project_id="proj-1",
            payment_intent_id="pi_2002",
            captured_amount_minor=captured,
            refunded_amount_minor=refunded,
            invoice_type="vat_electronic_normal",
            buyer_type="individual",
            buyer_name="李四",
            seller_name="榆钱儿科技",
            seller_tax_number="91110108MA01XXXXXX",
            operator="op",
            items=[{"itemName": "咨询服务第2期", "quantity": 1, "unitPriceMinor": 5000, "taxRateBasisPoints": 0}],
            now=NOW,
        )
        self.assertEqual(5000, inv2["totalAmountMinor"])
        self.assertEqual(0, self.ledger.calculate_invoicable_balance("tenant-beta", "pi_2002", captured, refunded))

    def test_e3_red_note_lifecycle_and_balance_restoration(self) -> None:
        """Verify that partial and full red-noting correctly reverses invoiced amounts and restores invoicable balance."""
        captured = 106000
        refunded = 0
        # 1. Apply and issue a 1060.00 CNY invoice (1000.00 untaxed + 60.00 tax)
        blue = self.ledger.apply_invoice(
            tenant_id="tenant-gamma",
            project_id="proj-1",
            payment_intent_id="pi_3003",
            captured_amount_minor=captured,
            refunded_amount_minor=refunded,
            invoice_type="vat_electronic_special",
            buyer_type="enterprise",
            buyer_name="阿里云计算有限公司",
            buyer_tax_number="91330106662323232X",
            seller_name="榆钱儿科技",
            seller_tax_number="91110108MA01XXXXXX",
            operator="op",
            items=[{"itemName": "云基础设施资源", "quantity": 1, "unitPriceMinor": 100000, "taxRateBasisPoints": 600}],
            now=NOW,
        )
        self.ledger.issue_invoice("tenant-gamma", blue["invoiceId"], actor="checker-1", now=NOW + timedelta(minutes=1))
        self.assertEqual(0, self.ledger.calculate_invoicable_balance("tenant-gamma", "pi_3003", captured, refunded))

        # 2. Issue a partial red note for 400.00 CNY (40000 minor)
        red1 = self.ledger.issue_red_note(
            "tenant-gamma",
            blue["invoiceId"],
            reason="客户业务缩容退订部分资源",
            operator="finance-op",
            red_amount_minor=40000,
            now=NOW + timedelta(minutes=2),
        )
        self.assertEqual("ISSUED", red1["status"])
        self.assertEqual("red", red1["invoiceCategory"])
        self.assertEqual(-40000, red1["totalAmountMinor"])

        # Original blue invoice remains ISSUED since it is partially reversed
        original_reloaded = self.ledger.get_invoice("tenant-gamma", blue["invoiceId"])
        self.assertIsNotNone(original_reloaded)
        self.assertEqual("ISSUED", original_reloaded["status"])

        # Balance restored by 40000 minor
        bal_after_red1 = self.ledger.calculate_invoicable_balance("tenant-gamma", "pi_3003", captured, refunded)
        self.assertEqual(40000, bal_after_red1)

        # 3. Issue the remaining red note for 660.00 CNY (66000 minor)
        red2 = self.ledger.issue_red_note(
            "tenant-gamma",
            blue["invoiceId"],
            reason="全额退订结清",
            operator="finance-op",
            red_amount_minor=66000,
            now=NOW + timedelta(minutes=3),
        )
        self.assertEqual(-66000, red2["totalAmountMinor"])

        # Original blue invoice should now be marked RED_NOTED (fully reversed)
        original_fully_reversed = self.ledger.get_invoice("tenant-gamma", blue["invoiceId"])
        self.assertEqual("RED_NOTED", original_fully_reversed["status"])

        # CRITICAL BUG CHECK (GAP-01): Balance must NOT double to 212000! It must be exactly 106000!
        bal_after_full_red = self.ledger.calculate_invoicable_balance("tenant-gamma", "pi_3003", captured, refunded)
        self.assertEqual(106000, bal_after_full_red)

        # Further red-noting on fully reversed invoice fails closed
        with self.assertRaises(ValidationError) as cm:
            self.ledger.issue_red_note(
                "tenant-gamma",
                blue["invoiceId"],
                reason="非法再次冲红",
                operator="finance-op",
                red_amount_minor=1000,
                now=NOW + timedelta(minutes=4),
            )
        self.assertIn("cannot red-note invoice in status: RED_NOTED", str(cm.exception))

    def test_e3_rejection_and_voiding_workflows(self) -> None:
        inv = self.ledger.apply_invoice(
            tenant_id="tenant-delta",
            project_id="proj-1",
            payment_intent_id="pi_4004",
            captured_amount_minor=50000,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="individual",
            buyer_name="王五",
            seller_name="榆钱儿科技",
            seller_tax_number="91110108MA01XXXXXX",
            operator="op",
            items=[{"itemName": "咨询费", "quantity": 1, "unitPriceMinor": 50000, "taxRateBasisPoints": 0}],
            now=NOW,
        )

        # Reject the invoice
        rejected = self.ledger.reject_invoice(
            "tenant-delta",
            inv["invoiceId"],
            reason="抬头信息有误，客户要求重开",
            checker="finance-audit",
            now=NOW + timedelta(minutes=1),
        )
        self.assertEqual("REJECTED", rejected["status"])
        self.assertIsNotNone(rejected["voidedAt"])

        # Balance is immediately released upon rejection
        bal = self.ledger.calculate_invoicable_balance("tenant-delta", "pi_4004", 50000, 0)
        self.assertEqual(50000, bal)

        # Re-apply with corrected title
        inv2 = self.ledger.apply_invoice(
            tenant_id="tenant-delta",
            project_id="proj-1",
            payment_intent_id="pi_4004",
            captured_amount_minor=50000,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="individual",
            buyer_name="王五（正确）",
            seller_name="榆钱儿科技",
            seller_tax_number="91110108MA01XXXXXX",
            operator="op",
            items=[{"itemName": "咨询费", "quantity": 1, "unitPriceMinor": 50000, "taxRateBasisPoints": 0}],
            now=NOW + timedelta(minutes=2),
        )

        # Void invoice directly while still in APPLIED
        voided = self.ledger.void_invoice(
            "tenant-delta",
            inv2["invoiceId"],
            reason="用户撤销开票申请",
            operator="op",
            now=NOW + timedelta(minutes=3),
        )
        self.assertEqual("VOIDED", voided["status"])
        self.assertEqual(50000, self.ledger.calculate_invoicable_balance("tenant-delta", "pi_4004", 50000, 0))

    def test_e3_multi_tenant_isolation_and_export_ledger(self) -> None:
        # Create invoices for tenant A and tenant B
        for tenant in ["tenant-corp-A", "tenant-corp-B"]:
            inv = self.ledger.apply_invoice(
                tenant_id=tenant,
                project_id="proj-common",
                payment_intent_id=f"pi_{tenant}",
                captured_amount_minor=10600,
                refunded_amount_minor=0,
                invoice_type="vat_electronic_normal",
                buyer_type="individual",
                buyer_name=f"买方-{tenant}",
                seller_name="榆钱儿科技",
                seller_tax_number="91110108MA01XXXXXX",
                operator="op",
                items=[{"itemName": "服务项", "quantity": 1, "unitPriceMinor": 10000, "taxRateBasisPoints": 600}],
                now=NOW,
            )
            self.ledger.issue_invoice(tenant, inv["invoiceId"], actor="checker")

        # Tenant A export must only contain Tenant A invoices
        export_a = self.ledger.export_invoice_ledger("tenant-corp-A")
        self.assertEqual(1, export_a["invoiceCount"])
        self.assertEqual(10600, export_a["totalAmountMinor"])
        self.assertEqual(600, export_a["totalTaxAmountMinor"])
        self.assertIsNotNone(export_a["manifestDigest"])

        # Cross-tenant manipulation must fail closed
        inv_a = export_a["invoices"][0]
        self.assertIsNone(self.ledger.get_invoice("tenant-corp-B", inv_a["invoiceId"]))
        with self.assertRaises(ValidationError):
            self.ledger.issue_red_note(
                "tenant-corp-B",
                inv_a["invoiceId"],
                reason="越权冲红",
                operator="attacker",
            )


class CustomerInvoiceE4AdvancedTesting(unittest.TestCase):
    """Level E4 High-Concurrency, Fault-Tolerance, and Adversarial Security Tests."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = str(Path(self.temporary.name) / "test_invoice_e4.db")
        self.ledger = CustomerInvoiceLedger(self.db_path)

    def test_e4_high_concurrency_anti_over_invoicing_race_condition(self) -> None:
        """Spawn 20 concurrent threads trying to invoice against a 100,000 minor payment.

        Total requested across threads is 400,000 minor (4x the available balance).
        Zero race conditions: exactly 5 succeed (5 * 20,000 = 100,000) and 15 fail closed.
        """
        tenant_id = "tenant-stress"
        payment_intent_id = "pi_stress_concurrency"
        captured = 100000  # 1000.00 CNY
        thread_count = 20
        request_minor = 20000  # 200.00 CNY each (188.68 + 11.32 tax = 200.00)

        results: list[dict[str, Any] | str] = []

        def worker(idx: int) -> dict[str, Any] | str:
            try:
                inv = self.ledger.apply_invoice(
                    tenant_id=tenant_id,
                    project_id="proj-stress",
                    payment_intent_id=payment_intent_id,
                    captured_amount_minor=captured,
                    refunded_amount_minor=0,
                    invoice_type="vat_electronic_normal",
                    buyer_type="individual",
                    buyer_name=f"并发用户-{idx}",
                    seller_name="榆钱儿科技",
                    seller_tax_number="91110108MA01XXXXXX",
                    operator=f"thread-{idx}",
                    items=[
                        {
                            "itemName": "并发高频商品",
                            "quantity": 1,
                            "unitPriceMinor": request_minor,
                            "taxRateBasisPoints": 0,
                        }
                    ],
                    idempotency_key=f"concurrent-key-{idx}",
                )
                return inv
            except ValidationError as exc:
                return f"rejected:{exc}"

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(worker, i) for i in range(thread_count)]
            for f in as_completed(futures):
                results.append(f.result())

        succeeded = [r for r in results if isinstance(r, dict)]
        rejected = [r for r in results if isinstance(r, str) and r.startswith("rejected:")]

        self.assertEqual(5, len(succeeded), f"Expected exactly 5 succeeded, got {len(succeeded)}")
        self.assertEqual(15, len(rejected), f"Expected exactly 15 rejected, got {len(rejected)}")

        # Verify database totals
        all_invoices = self.ledger.list_invoices(tenant_id, payment_intent_id=payment_intent_id)
        total_minor = sum(inv["totalAmountMinor"] for inv in all_invoices)
        self.assertEqual(100000, total_minor)

        # Remaining invoicable balance must be exactly 0
        rem_bal = self.ledger.calculate_invoicable_balance(tenant_id, payment_intent_id, captured, 0)
        self.assertEqual(0, rem_bal)

    def test_e4_concurrent_red_notes_race_condition(self) -> None:
        """Spawn 10 concurrent threads attempting to partially red-note the same invoice.

        Cumulative reversed amount must never exceed the original blue invoice amount.
        """
        tenant_id = "tenant-red-stress"
        blue = self.ledger.apply_invoice(
            tenant_id=tenant_id,
            project_id="proj-1",
            payment_intent_id="pi_red_stress",
            captured_amount_minor=50000,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="individual",
            buyer_name="并发冲红买方",
            seller_name="榆钱儿科技",
            seller_tax_number="91110108MA01XXXXXX",
            operator="op",
            items=[{"itemName": "项目", "quantity": 1, "unitPriceMinor": 50000, "taxRateBasisPoints": 0}],
            now=NOW,
        )
        self.ledger.issue_invoice(tenant_id, blue["invoiceId"], actor="checker", now=NOW)

        # 10 threads attempting 20000 minor each (total requested 200,000 vs 50,000 original)
        thread_count = 10
        results: list[dict[str, Any] | str] = []

        def red_worker(idx: int) -> dict[str, Any] | str:
            try:
                return self.ledger.issue_red_note(
                    tenant_id,
                    blue["invoiceId"],
                    reason=f"并发冲红-{idx}",
                    operator=f"op-{idx}",
                    red_amount_minor=20000,
                    idempotency_key=f"red-idem-{idx}",
                )
            except ValidationError as exc:
                return f"rejected:{exc}"

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(red_worker, i) for i in range(thread_count)]
            for f in as_completed(futures):
                results.append(f.result())

        succeeded = [r for r in results if isinstance(r, dict)]
        # Maximum 2 partial red notes of 20000 can succeed (40000 total), 3rd would be 60000 > 50000 so rejected
        self.assertEqual(2, len(succeeded))

        # Check total reversed amount in database
        all_invoices = self.ledger.list_invoices(tenant_id)
        red_sum = sum(inv["totalAmountMinor"] for inv in all_invoices if inv["invoiceCategory"] == "red")
        self.assertEqual(-40000, red_sum)

    def test_e4_cryptographic_audit_tamper_detection_and_fault_injection(self) -> None:
        """Inject fraudulent modifications into SQLite and assert that audit chain verification fails closed."""
        tenant_id = "tenant-tamper"
        inv = self.ledger.apply_invoice(
            tenant_id=tenant_id,
            project_id="proj-1",
            payment_intent_id="pi_tamper",
            captured_amount_minor=10000,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="individual",
            buyer_name="审计测试",
            seller_name="榆钱儿科技",
            seller_tax_number="91110108MA01XXXXXX",
            operator="op",
            items=[{"itemName": "审计项目", "quantity": 1, "unitPriceMinor": 10000, "taxRateBasisPoints": 0}],
            now=NOW,
        )
        self.ledger.issue_invoice(tenant_id, inv["invoiceId"], actor="checker", now=NOW + timedelta(minutes=1))

        # Before tampering, audit chain must be valid
        self.assertTrue(self.ledger.verify_invoice_audit_chain(tenant_id))

        # Fault Injection: Tamper with an audit event's payload in SQLite directly
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE customer_invoice_audit SET payload_json='{\"tampered\": true}' WHERE tenant_id=?",
                (tenant_id,),
            )
            conn.commit()

        # After tampering, verification must fail closed
        self.assertFalse(self.ledger.verify_invoice_audit_chain(tenant_id))

    def test_e4_strict_idempotency_conflict_detection(self) -> None:
        """Verify that identical request returns idempotent response, while modified payload fails with conflict."""
        tenant_id = "tenant-idem"
        key = "IDEM-STRICT-001"

        def make_req(unit_price: int, buyer: str) -> dict[str, Any]:
            return self.ledger.apply_invoice(
                tenant_id=tenant_id,
                project_id="proj-1",
                payment_intent_id="pi_idem",
                captured_amount_minor=100000,
                refunded_amount_minor=0,
                invoice_type="vat_electronic_normal",
                buyer_type="individual",
                buyer_name=buyer,
                seller_name="榆钱儿科技",
                seller_tax_number="91110108MA01XXXXXX",
                operator="op",
                items=[{"itemName": "幂等商品", "quantity": 1, "unitPriceMinor": unit_price, "taxRateBasisPoints": 0}],
                idempotency_key=key,
                now=NOW,
            )

        # First request succeeds
        first = make_req(20000, "张三")
        self.assertEqual(20000, first["totalAmountMinor"])

        # Replay identical request -> returns same invoice
        replay = make_req(20000, "张三")
        self.assertEqual(first["invoiceId"], replay["invoiceId"])
        self.assertEqual(first["totalAmountMinor"], replay["totalAmountMinor"])

        # Replay with altered amount -> must fail closed with conflict
        with self.assertRaises(ValidationError) as cm1:
            make_req(30000, "张三")
        self.assertIn("idempotency_key_reuse: request payload conflict", str(cm1.exception))

        # Replay with altered buyer -> must fail closed with conflict
        with self.assertRaises(ValidationError) as cm2:
            make_req(20000, "李四")
        self.assertIn("idempotency_key_reuse: request payload conflict", str(cm2.exception))

    def test_e4_boundary_fuzzing_and_sqli_xss_injection(self) -> None:
        """Verify handling of extreme numbers, SQL injection patterns, and XSS strings."""
        tenant_id = "tenant-fuzz"
        # 1. SQL injection in buyer name
        sqli_buyer = "攻击企业' OR '1'='1' --"
        xss_item = "<script>alert('pwned')</script>"

        inv = self.ledger.apply_invoice(
            tenant_id=tenant_id,
            project_id="proj-1",
            payment_intent_id="pi_fuzz",
            captured_amount_minor=120000000000,  # 1.2 billion CNY (120 billion minor)
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="individual",
            buyer_name=sqli_buyer,
            seller_name="榆钱儿科技",
            seller_tax_number="91110108MA01XXXXXX",
            operator="sec-test",
            items=[{"itemName": xss_item, "quantity": 1, "unitPriceMinor": 99999999900, "taxRateBasisPoints": 1300}],
            now=NOW,
        )
        self.assertEqual(sqli_buyer, inv["buyerName"])
        self.assertEqual(xss_item, inv["items"][0]["itemName"])

        # Ensure safe parameterized retrieval
        retrieved = self.ledger.get_invoice(tenant_id, inv["invoiceId"])
        self.assertIsNotNone(retrieved)
        self.assertEqual(sqli_buyer, retrieved["buyerName"])

        # 2. Negative and illegal boundaries must fail closed
        with self.assertRaises(ValidationError):
            calculate_vat_breakdown([])  # empty
        with self.assertRaises(ValidationError):
            calculate_vat_breakdown([{"itemName": "a", "quantity": 0, "unitPriceMinor": 100, "taxRateBasisPoints": 600}])
        with self.assertRaises(ValidationError):
            calculate_vat_breakdown([{"itemName": "a", "quantity": 1, "unitPriceMinor": -100, "taxRateBasisPoints": 600}])
        with self.assertRaises(ValidationError):
            calculate_vat_breakdown([{"itemName": "a", "quantity": 1, "unitPriceMinor": 100, "taxRateBasisPoints": 10001}])


class CustomerInvoiceCliIntegrationTest(unittest.TestCase):
    """Level E3/E4 CLI Integration Testing for control.py entrypoints."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = Path(self.temporary.name) / "cli_invoice.db"

    def run_cli(self, *args: str) -> tuple[int, dict[str, Any]]:
        cmd = [sys.executable, str(ROOT / "tools/runtime/control.py"), *args]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        stdout = res.stdout.strip()
        data = json.loads(stdout) if stdout else {}
        return res.returncode, data

    def test_cli_invoice_full_lifecycle(self) -> None:
        tenant = "cli-corp"
        pi = "pi_cli_100"

        # 1. Check initial balance
        code, data = self.run_cli(
            "invoice-balance",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--payment-intent", pi,
            "--captured-minor", "50000",
            "--refunded-minor", "10000",
        )
        self.assertEqual(0, code)
        self.assertEqual(40000, data["invoicableBalanceMinor"])

        # 2. Apply for invoice via request JSON
        req_path = Path(self.temporary.name) / "apply_req.json"
        req_path.write_text(
            json.dumps({
                "tenantId": tenant,
                "projectId": "proj-cli",
                "paymentIntentId": pi,
                "capturedAmountMinor": 50000,
                "refundedAmountMinor": 10000,
                "invoiceType": "vat_electronic_normal",
                "buyerType": "enterprise",
                "buyerName": "字节跳动科技有限公司",
                "buyerTaxNumber": "91110108592366553N",
                "sellerName": "榆钱儿科技有限公司",
                "sellerTaxNumber": "91110108MA01XXXXXX",
                "operator": "cli-operator",
                "items": [
                    {
                        "itemName": "API调用服务费",
                        "quantity": 2,
                        "unitPriceMinor": 10000,
                        "taxRateBasisPoints": 600,
                    }
                ],
                "idempotencyKey": "cli-idem-001",
            }),
            encoding="utf-8",
        )
        code, inv = self.run_cli("invoice-apply", "--database", str(self.db_path), "--request", str(req_path))
        self.assertEqual(0, code)
        invoice_id = inv["invoiceId"]
        self.assertEqual("APPLIED", inv["status"])
        self.assertEqual(21200, inv["totalAmountMinor"])

        # 3. Issue invoice
        code, issued = self.run_cli(
            "invoice-issue",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--invoice-id", invoice_id,
            "--actor", "cli-checker",
        )
        self.assertEqual(0, code)
        self.assertEqual("ISSUED", issued["status"])
        v_code = issued["verificationCode"]
        self.assertIsNotNone(v_code)

        # 4. Verify invoice
        code, verified = self.run_cli(
            "invoice-verify",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--invoice-id", invoice_id,
            "--verification-code", v_code,
        )
        self.assertEqual(0, code)
        self.assertTrue(verified["valid"])

        # 5. Export ledger
        code, ledger_export = self.run_cli(
            "invoice-export",
            "--database", str(self.db_path),
            "--tenant", tenant,
        )
        self.assertEqual(0, code)
        self.assertEqual(1, ledger_export["invoiceCount"])
        self.assertEqual(21200, ledger_export["totalAmountMinor"])

        # 6. Verify audit chain
        code, audit_res = self.run_cli(
            "invoice-audit-verify",
            "--database", str(self.db_path),
            "--tenant", tenant,
        )
        self.assertEqual(0, code)
        self.assertTrue(audit_res["auditChainValid"])


if __name__ == "__main__":
    unittest.main()
