from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError
from elmpay_runtime.invoice import (
    COMMON_TAX_CLASSIFICATIONS,
    CustomerInvoiceLedger,
    calculate_vat_breakdown,
    export_tax_declaration_csv,
    render_golden_tax_xml,
    validate_tax_classification_code,
)

NOW = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)


class EnterpriseInvoiceProductivityE3Test(unittest.TestCase):
    """Level E3 System & Enterprise Workflow Tests for Invoice Management."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = str(Path(self.temporary.name) / "test_invoice_productivity.db")
        self.ledger = CustomerInvoiceLedger(self.db_path)

    def test_tax_classification_code_validation_and_golden_tax_xml(self) -> None:
        # Valid 9-digit and 19-digit codes
        self.assertEqual("304020101", validate_tax_classification_code("304020101"))
        self.assertEqual("3040201010000000000", validate_tax_classification_code("3040201010000000000"))
        self.assertEqual("1010101010000000000", validate_tax_classification_code("1010101010000000000"))

        # Invalid codes: non-numeric, too short, too long
        with self.assertRaises(ValidationError):
            validate_tax_classification_code("30402ABCD")
        with self.assertRaises(ValidationError):
            validate_tax_classification_code("12345")
        with self.assertRaises(ValidationError):
            validate_tax_classification_code("123456789012345678901")

        # Verify default catalog lookup
        self.assertIn("3040201010000000000", COMMON_TAX_CLASSIFICATIONS)
        self.assertEqual("信息技术服务*软件服务", COMMON_TAX_CLASSIFICATIONS["3040201010000000000"])

        # Verify inclusion in calculate_vat_breakdown and Golden Tax XML
        items = [
            {
                "itemName": "SaaS云平台年度订阅费",
                "specification": "企业标准版",
                "unit": "年",
                "quantity": 1,
                "unitPriceMinor": 100000,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "3040201010000000000",
            }
        ]
        breakdown = calculate_vat_breakdown(items)
        self.assertEqual("3040201010000000000", breakdown.lines[0].tax_classification_code)

        xml_str = render_golden_tax_xml({
            "invoiceId": "inv_tax_code_test",
            "invoiceCode": "1100261130",
            "invoiceNumber": "88880001",
            "invoiceType": "vat_electronic_normal",
            "buyerName": "北京智航科技有限公司",
            "buyerTaxNumber": "91110108MA01XXXXXX",
            "sellerName": "榆钱儿企业服务（北京）有限公司",
            "sellerTaxNumber": "91110105MA02YYYYYY",
            "totalAmountMinor": breakdown.total_amount_minor,
            "untaxedAmountMinor": breakdown.untaxed_amount_minor,
            "taxAmountMinor": breakdown.tax_amount_minor,
            "items": [
                {
                    "itemId": "item_1",
                    "itemName": breakdown.lines[0].item_name,
                    "specification": breakdown.lines[0].specification,
                    "unit": breakdown.lines[0].unit,
                    "quantity": breakdown.lines[0].quantity,
                    "unitPriceMinor": breakdown.lines[0].unit_price_minor,
                    "amountMinor": breakdown.lines[0].amount_minor,
                    "taxRateBasisPoints": breakdown.lines[0].tax_rate_basis_points,
                    "taxAmountMinor": breakdown.lines[0].tax_amount_minor,
                    "taxClassificationCode": breakdown.lines[0].tax_classification_code,
                }
            ],
            "issuedAt": "2026-09-18T10:00:00Z",
            "verificationCode": "12345678901234567890",
        })
        root = ET.fromstring(xml_str)
        ns = {"ns": "http://tax.chinatax.gov.cn/schema/einvoice/v3"}
        item_node = root.find(".//ns:Item", ns)
        self.assertIsNotNone(item_node)
        tax_code_node = item_node.find("ns:TaxClassificationCode", ns)
        self.assertIsNotNone(tax_code_node)
        self.assertEqual("3040201010000000000", tax_code_node.text)

    def test_tax_quota_configuration_and_fail_closed_enforcement(self) -> None:
        tenant = "tenant-quota-corp"
        operator = "finance-admin-01"

        # 1. Configure quota: monthly 1,000,000 minor (10,000 CNY), single limit 100,000 minor (1,000 CNY), alarm at 80%
        cfg = self.ledger.configure_tax_quota(
            tenant_id=tenant,
            monthly_tax_quota_minor=1000000,
            single_invoice_limit_minor=100000,
            alarm_threshold_pct=80,
            operator=operator,
            now=NOW,
        )
        self.assertEqual(1000000, cfg["monthlyTaxQuotaMinor"])
        self.assertEqual(100000, cfg["singleInvoiceLimitMinor"])
        self.assertEqual(80, cfg["alarmThresholdPct"])

        # 2. Check initial quota status
        status = self.ledger.get_tax_quota_status(tenant, tax_period="2026-09")
        self.assertEqual(1000000, status["monthlyTaxQuotaMinor"])
        self.assertEqual(0, status["usedTaxQuotaMinor"])
        self.assertEqual(1000000, status["remainingTaxQuotaMinor"])
        self.assertFalse(status["isAlarm"])
        self.assertFalse(status["isExhausted"])

        # 3. Apply invoice exceeding single invoice limit (120,000 minor > 100,000 minor)
        items_large = [
            {
                "itemName": "高阶咨询服务",
                "quantity": 1,
                "unitPriceMinor": 120000,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "3040201010000000000",
            }
        ]
        with self.assertRaises(ValidationError) as ctx:
            self.ledger.apply_invoice(
                tenant_id=tenant,
                project_id="proj_tax",
                payment_intent_id="pi_quota_large",
                captured_amount_minor=127200,
                refunded_amount_minor=0,
                invoice_type="vat_electronic_normal",
                buyer_type="enterprise",
                buyer_name="大客户企业",
                buyer_tax_number="91110108MA00000001",
                seller_name="榆钱儿科技",
                seller_tax_number="91110105MA02YYYYYY",
                operator=operator,
                items=items_large,
                now=NOW,
            )
        self.assertIn("exceeds tenant single invoice limit", str(ctx.exception))
        self.assertIn("split_and_apply_invoice", str(ctx.exception))

        # 4. Issue a valid invoice of 85,000 minor total (unit 80,188 + tax 4,812 = 85,000)
        items_ok = [
            {
                "itemName": "基础咨询服务",
                "quantity": 1,
                "unitPriceMinor": 80188,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "3040201010000000000",
            }
        ]
        inv1 = self.ledger.apply_invoice(
            tenant_id=tenant,
            project_id="proj_tax",
            payment_intent_id="pi_quota_ok1",
            captured_amount_minor=85000,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="enterprise",
            buyer_name="普通客户企业",
            buyer_tax_number="91110108MA00000002",
            seller_name="榆钱儿科技",
            seller_tax_number="91110105MA02YYYYYY",
            operator=operator,
            items=items_ok,
            now=NOW,
        )
        self.ledger.issue_invoice(tenant, inv1["invoiceId"], actor="actor1", now=NOW)

        # 5. Check status after inv1
        status1 = self.ledger.get_tax_quota_status(tenant, tax_period="2026-09")
        self.assertEqual(84999, status1["usedTaxQuotaMinor"])
        self.assertEqual(915001, status1["remainingTaxQuotaMinor"])
        self.assertFalse(status1["isAlarm"])

        # 6. Issue another invoice to trigger alarm threshold (> 80%)
        # Add 750,000 minor invoice
        items_alarm = [
            {
                "itemName": "软件授权费",
                "quantity": 1,
                "unitPriceMinor": 70000,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "3040201010000000000",
            }
        ]
        # We can configure a smaller quota to easily test exhaustion and alarm
        self.ledger.configure_tax_quota(
            tenant_id=tenant,
            monthly_tax_quota_minor=100000,
            single_invoice_limit_minor=100000,
            alarm_threshold_pct=80,
            operator=operator,
            now=NOW,
        )
        status_alarm = self.ledger.get_tax_quota_status(tenant, tax_period="2026-09")
        self.assertTrue(status_alarm["isAlarm"])  # 84999 / 100000 = 85.0% >= 80%
        self.assertFalse(status_alarm["isExhausted"])

        # 7. Attempt to apply another invoice that exceeds monthly quota (remaining is 15001 minor)
        items_exceed = [
            {
                "itemName": "额外模块费",
                "quantity": 1,
                "unitPriceMinor": 20000,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "3040201010000000000",
            }
        ]
        with self.assertRaises(ValidationError) as ctx_exceed:
            self.ledger.apply_invoice(
                tenant_id=tenant,
                project_id="proj_tax",
                payment_intent_id="pi_quota_exceed",
                captured_amount_minor=21200,
                refunded_amount_minor=0,
                invoice_type="vat_electronic_normal",
                buyer_type="enterprise",
                buyer_name="普通客户企业",
                buyer_tax_number="91110108MA00000002",
                seller_name="榆钱儿科技",
                seller_tax_number="91110105MA02YYYYYY",
                operator=operator,
                items=items_exceed,
                now=NOW,
            )
        self.assertIn("exceeds tenant monthly invoice quota", str(ctx_exceed.exception))

    def test_oversized_invoice_auto_splitting(self) -> None:
        tenant = "tenant-split-corp"
        operator = "finance-admin-split"

        # Monthly quota 1,000,000 minor, single limit 50,000 minor (500 CNY)
        self.ledger.configure_tax_quota(
            tenant_id=tenant,
            monthly_tax_quota_minor=1000000,
            single_invoice_limit_minor=50000,
            alarm_threshold_pct=90,
            operator=operator,
            now=NOW,
        )

        # Single order of 120,000 minor (1,200 CNY)
        items = [
            {
                "itemName": "企业年度安全网关服务",
                "quantity": 1,
                "unitPriceMinor": 120000,
                "taxRateBasisPoints": 600,
                "taxClassificationCode": "3040201010000000000",
            }
        ]
        buyer_info = {
            "name": "北京科技大学",
            "taxNumber": "12100000400001402P",
            "buyerType": "enterprise",
        }
        seller_info = {
            "name": "榆钱儿企业服务（北京）有限公司",
            "taxNumber": "91110105MA02YYYYYY",
        }

        # Auto-split and apply: 120,000 untaxed + 7,200 tax = 127,200 total minor.
        # Single limit = 50,000 minor -> Ceiling(127,200 / 50,000) = 3 sub-invoices.
        sub_invoices = self.ledger.split_and_apply_invoice(
            tenant_id=tenant,
            payment_intent_id="pi_large_order_split_001",
            invoice_type="vat_electronic_normal",
            buyer_info=buyer_info,
            seller_info=seller_info,
            items=items,
            actor_id="actor_split_engine",
            idempotency_key="idem_split_001",
            now=NOW,
        )

        self.assertEqual(3, len(sub_invoices))
        split_batch_id = sub_invoices[0]["splitBatchId"]
        self.assertTrue(split_batch_id.startswith("split_"))

        total_split_amount = 0
        total_split_untaxed = 0
        total_split_tax = 0

        for idx, inv in enumerate(sub_invoices):
            self.assertEqual(split_batch_id, inv["splitBatchId"])
            self.assertEqual(idx + 1, inv["splitIndex"])
            self.assertEqual(3, inv["splitCount"])
            self.assertLessEqual(inv["totalAmountMinor"], 50000)
            total_split_amount += inv["totalAmountMinor"]
            total_split_untaxed += inv["untaxedAmountMinor"]
            total_split_tax += inv["taxAmountMinor"]

            # Verify tax classification code on sub-items
            detail = self.ledger.get_invoice(tenant, inv["invoiceId"])
            self.assertEqual(1, len(detail["items"]))
            self.assertEqual("3040201010000000000", detail["items"][0]["taxClassificationCode"])

        # Verify conservation invariant: split total == original total
        self.assertEqual(127200, total_split_amount)
        self.assertEqual(120000, total_split_untaxed)
        self.assertEqual(7200, total_split_tax)

        # Verify idempotency: calling with same idempotency_key returns identical sub-invoices
        sub_invoices_replayed = self.ledger.split_and_apply_invoice(
            tenant_id=tenant,
            payment_intent_id="pi_large_order_split_001",
            invoice_type="vat_electronic_normal",
            buyer_info=buyer_info,
            seller_info=seller_info,
            items=items,
            actor_id="actor_split_engine",
            idempotency_key="idem_split_001",
            now=NOW,
        )
        self.assertEqual(3, len(sub_invoices_replayed))
        self.assertEqual(sub_invoices[0]["invoiceId"], sub_invoices_replayed[0]["invoiceId"])

    def test_self_service_qr_session_lifecycle(self) -> None:
        tenant = "tenant-self-service"
        pi = "pi_self_qr_1001"
        amount_minor = 66800  # 668.00 CNY

        # 1. Create self-service session
        session = self.ledger.create_self_service_session(
            tenant_id=tenant,
            payment_intent_id=pi,
            invoicable_amount_minor=amount_minor,
            created_by="pos_cashier_01",
            ttl_hours=48,
            currency="CNY",
            now=NOW,
        )
        self.assertEqual("ACTIVE", session["status"])
        self.assertEqual(amount_minor, session["invoicableAmountMinor"])
        self.assertIn("sessionToken", session)
        self.assertIn("qrPayload", session)
        token = session["sessionToken"]

        # 2. Query session
        queried = self.ledger.get_self_service_session(token, now=NOW)
        self.assertIsNotNone(queried)
        self.assertEqual(session["sessionId"], queried["sessionId"])
        self.assertEqual("ACTIVE", queried["status"])

        # 3. Customer scans and redeems invoice
        buyer_info = {
            "name": "北京美团数字科技有限公司",
            "taxNumber": "91110108MA00223344",
            "email": "invoice@meituan.com",
            "phone": "13800001111",
        }
        issued_invoice = self.ledger.redeem_self_service_session(
            session_token=token,
            buyer_info=buyer_info,
            invoice_type="vat_electronic_normal",
            now=NOW,
        )
        self.assertEqual("ISSUED", issued_invoice["status"])
        self.assertEqual(amount_minor, issued_invoice["totalAmountMinor"])
        self.assertEqual("北京美团数字科技有限公司", issued_invoice["buyerName"])
        self.assertEqual("91110108MA00223344", issued_invoice["buyerTaxNumber"])

        # 4. Session status is now REDEEMED
        updated_session = self.ledger.get_self_service_session(token)
        self.assertEqual("REDEEMED", updated_session["status"])
        self.assertEqual(issued_invoice["invoiceId"], updated_session["redeemedInvoiceId"])

        # 5. Subsequent redemption attempt fails fail-closed
        with self.assertRaises(ValidationError) as ctx:
            self.ledger.redeem_self_service_session(
                session_token=token,
                buyer_info=buyer_info,
                now=NOW,
            )
        self.assertIn("already redeemed", str(ctx.exception))

    def test_vat_tax_declaration_summary_and_csv_export(self) -> None:
        tenant = "tenant-tax-summary"
        operator = "finance-tax-agent"

        # 1. Issue 13% blue invoice
        inv_13 = self.ledger.apply_invoice(
            tenant_id=tenant,
            project_id="proj_vat",
            payment_intent_id="pi_vat_13",
            captured_amount_minor=11300,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="enterprise",
            buyer_name="企业A",
            buyer_tax_number="91110108MA00000001",
            seller_name="榆钱儿科技",
            seller_tax_number="91110105MA02YYYYYY",
            operator=operator,
            items=[{"itemName": "网络硬件", "quantity": 1, "unitPriceMinor": 10000, "taxRateBasisPoints": 1300, "taxClassificationCode": "1090101010000000000"}],
            now=NOW,
        )
        self.ledger.issue_invoice(tenant, inv_13["invoiceId"], actor="act1", now=NOW)

        # 2. Issue 6% blue invoice
        inv_6 = self.ledger.apply_invoice(
            tenant_id=tenant,
            project_id="proj_vat",
            payment_intent_id="pi_vat_6",
            captured_amount_minor=21200,
            refunded_amount_minor=0,
            invoice_type="vat_electronic_normal",
            buyer_type="enterprise",
            buyer_name="企业B",
            buyer_tax_number="91110108MA00000002",
            seller_name="榆钱儿科技",
            seller_tax_number="91110105MA02YYYYYY",
            operator=operator,
            items=[{"itemName": "技术咨询", "quantity": 1, "unitPriceMinor": 20000, "taxRateBasisPoints": 600, "taxClassificationCode": "3040201010000000000"}],
            now=NOW,
        )
        self.ledger.issue_invoice(tenant, inv_6["invoiceId"], actor="act1", now=NOW)

        # 3. Issue red note to partially reverse inv_6 (refund 5,300 minor = 5000 untaxed + 300 tax)
        self.ledger.issue_red_note(
            tenant_id=tenant,
            original_invoice_id=inv_6["invoiceId"],
            operator=operator,
            reason="部分退款",
            red_items=[{"itemName": "技术咨询", "quantity": 1, "unitPriceMinor": 5000, "taxRateBasisPoints": 600, "taxClassificationCode": "3040201010000000000"}],
            actor="act1",
            checker="chk1",
            now=NOW,
        )

        # 4. Generate tax declaration summary for 2026-09
        summary = self.ledger.generate_tax_declaration_summary(tenant, tax_period="2026-09")
        self.assertEqual("2026-09", summary["taxPeriod"])
        self.assertEqual(2, len(summary["taxRateBrackets"]))

        b13 = next(b for b in summary["taxRateBrackets"] if b["taxRateBasisPoints"] == 1300)
        self.assertEqual(1, b13["blueInvoiceCount"])
        self.assertEqual(10000, b13["blueUntaxedMinor"])
        self.assertEqual(1300, b13["blueTaxMinor"])
        self.assertEqual(0, b13["redInvoiceCount"])
        self.assertEqual(10000, b13["netSalesUntaxedMinor"])
        self.assertEqual(1300, b13["netOutputTaxMinor"])
        self.assertEqual(11300, b13["netTotalMinor"])

        b6 = next(b for b in summary["taxRateBrackets"] if b["taxRateBasisPoints"] == 600)
        self.assertEqual(1, b6["blueInvoiceCount"])
        self.assertEqual(20000, b6["blueUntaxedMinor"])
        self.assertEqual(1200, b6["blueTaxMinor"])
        self.assertEqual(1, b6["redInvoiceCount"])
        self.assertEqual(5000, b6["redUntaxedMinor"])
        self.assertEqual(300, b6["redTaxMinor"])
        self.assertEqual(15000, b6["netSalesUntaxedMinor"])
        self.assertEqual(900, b6["netOutputTaxMinor"])
        self.assertEqual(15900, b6["netTotalMinor"])

        # Totals
        totals = summary["totals"]
        self.assertEqual(2, totals["totalBlueCount"])
        self.assertEqual(1, totals["totalRedCount"])
        self.assertEqual(25000, totals["totalNetSalesUntaxedMinor"])
        self.assertEqual(2200, totals["totalNetOutputTaxMinor"])
        self.assertEqual(27200, totals["totalNetMinor"])

        # 5. Export to CSV
        csv_text = export_tax_declaration_csv(summary)
        reader = list(csv.reader(io.StringIO(csv_text)))
        self.assertGreaterEqual(len(reader), 3)  # header + 2 brackets
        self.assertEqual("税率(%)", reader[0][0])
        self.assertIn("13.0%", [row[0] for row in reader[1:]])
        self.assertIn("6.0%", [row[0] for row in reader[1:]])

    def test_subscription_recurring_auto_invoicing(self) -> None:
        tenant = "tenant-subscription-billing"
        operator = "subscription-billing-bot"

        buyer_info = {
            "name": "北京字节跳动科技有限公司",
            "taxId": "91110108MA00333333",
            "email": "finance@bytedance.com",
        }

        # Auto invoice subscription for cycle 2026-09
        inv = self.ledger.auto_invoice_subscription_billing(
            tenant_id=tenant,
            subscription_id="sub_enterprise_saas_999",
            billing_cycle="2026-09",
            amount_minor=99900,  # 999.00 CNY
            plan_name="企业版旗舰年度订阅套餐",
            buyer_info=buyer_info,
            operator=operator,
            tax_rate_basis_points=600,
            now=NOW,
        )
        self.assertEqual("ISSUED", inv["status"])
        self.assertEqual(99900, inv["totalAmountMinor"])
        self.assertIn("2026-09", inv["items"][0]["itemName"])
        self.assertIn("企业版旗舰年度订阅套餐", inv["items"][0]["itemName"])

        # Idempotent replay: calling again for same subscription and billing cycle
        inv_replayed = self.ledger.auto_invoice_subscription_billing(
            tenant_id=tenant,
            subscription_id="sub_enterprise_saas_999",
            billing_cycle="2026-09",
            amount_minor=99900,
            plan_name="企业版旗舰年度订阅套餐",
            buyer_info=buyer_info,
            operator=operator,
            tax_rate_basis_points=600,
            now=NOW,
        )
        self.assertEqual(inv["invoiceId"], inv_replayed["invoiceId"])


class EnterpriseInvoiceProductivityE4Test(unittest.TestCase):
    """Level E4 High-Concurrency, Security, and Tamper Testing."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = str(Path(self.temporary.name) / "test_invoice_e4.db")
        self.ledger = CustomerInvoiceLedger(self.db_path)

    def test_e4_concurrent_self_service_token_redemption_race(self) -> None:
        """15 concurrent worker threads race to redeem the exact same self-service session token.
        Strictly 1 thread must succeed, and 14 threads must be blocked fail-closed."""
        tenant = "tenant-e4-race"
        pi = "pi_e4_race_001"
        amount_minor = 88800

        session = self.ledger.create_self_service_session(
            tenant_id=tenant,
            payment_intent_id=pi,
            invoicable_amount_minor=amount_minor,
            created_by="pos_e4",
            ttl_hours=24,
            now=NOW,
        )
        token = session["sessionToken"]

        results: list[tuple[bool, str]] = []

        def worker(worker_id: int) -> tuple[bool, str]:
            local_ledger = CustomerInvoiceLedger(self.db_path)
            buyer = {
                "name": f"竞速企业_{worker_id}",
                "taxNumber": f"91110108MA000000{worker_id:02d}",
            }
            try:
                inv = local_ledger.redeem_self_service_session(
                    session_token=token,
                    buyer_info=buyer,
                    now=NOW,
                )
                return True, inv["invoiceId"]
            except ValidationError as exc:
                return False, str(exc)

        concurrency = 15
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(worker, i) for i in range(concurrency)]
            for f in as_completed(futures):
                results.append(f.result())

        successes = [r for r in results if r[0]]
        failures = [r for r in results if not r[0]]

        self.assertEqual(1, len(successes), f"Expected strictly 1 success, got {len(successes)}")
        self.assertEqual(concurrency - 1, len(failures))
        for _, err in failures:
            self.assertIn("already redeemed", err)

        # Check DB state
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT status, redeemed_invoice_id FROM customer_invoice_self_service WHERE session_token=?", (token,))
            row = cur.fetchone()
            self.assertEqual("REDEEMED", row[0])
            self.assertEqual(successes[0][1], row[1])

    def test_e4_concurrent_quota_exhaustion_race(self) -> None:
        """10 concurrent threads each try to invoice 10,000 minor with a total quota of 40,000 minor.
        Strictly 4 must succeed, 6 must be rejected, and quota cannot be breached."""
        tenant = "tenant-e4-quota-race"
        operator = "admin-e4"

        # Quota: 40,000 minor monthly, single limit 50,000 minor
        self.ledger.configure_tax_quota(
            tenant_id=tenant,
            monthly_tax_quota_minor=40000,
            single_invoice_limit_minor=50000,
            alarm_threshold_pct=90,
            operator=operator,
            now=NOW,
        )

        results: list[tuple[bool, str]] = []

        def worker(worker_id: int) -> tuple[bool, str]:
            local_ledger = CustomerInvoiceLedger(self.db_path)
            items = [
                {
                    "itemName": f"测试服务_{worker_id}",
                    "quantity": 1,
                    "unitPriceMinor": 9434,
                    "taxRateBasisPoints": 600,  # untaxed 9434 + tax 566 = 10000 minor
                    "taxClassificationCode": "3040201010000000000",
                }
            ]
            try:
                applied = local_ledger.apply_invoice(
                    tenant_id=tenant,
                    project_id="proj_e4",
                    payment_intent_id=f"pi_e4_worker_{worker_id}",
                    captured_amount_minor=10000,
                    refunded_amount_minor=0,
                    invoice_type="vat_electronic_normal",
                    buyer_type="enterprise",
                    buyer_name="并发客户",
                    buyer_tax_number="91110108MA00000001",
                    seller_name="榆钱儿科技",
                    seller_tax_number="91110105MA02YYYYYY",
                    operator=operator,
                    items=items,
                    now=NOW,
                )
                local_ledger.issue_invoice(tenant, applied["invoiceId"], actor=f"actor_{worker_id}", now=NOW)
                return True, applied["invoiceId"]
            except ValidationError as exc:
                return False, str(exc)

        concurrency = 10
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(worker, i) for i in range(concurrency)]
            for f in as_completed(futures):
                results.append(f.result())

        successes = [r for r in results if r[0]]
        failures = [r for r in results if not r[0]]

        self.assertEqual(4, len(successes), f"Expected strictly 4 successes, got {len(successes)}")
        self.assertEqual(6, len(failures))
        for _, err in failures:
            self.assertIn("exceeds tenant monthly invoice quota", err)

        # Invariant: final used quota <= 40000 minor
        status = self.ledger.get_tax_quota_status(tenant, tax_period="2026-09")
        self.assertEqual(40000, status["usedTaxQuotaMinor"])
        self.assertEqual(0, status["remainingTaxQuotaMinor"])
        self.assertTrue(status["isExhausted"])


class EnterpriseInvoiceCliIntegrationTest(unittest.TestCase):
    """Level E3/E4 CLI Integration Testing for Enterprise Invoice Subcommands in control.py."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db_path = Path(self.temporary.name) / "cli_invoice_productivity.db"

    def run_cli(self, *args: str) -> tuple[int, dict[str, Any], str]:
        cmd = [sys.executable, str(ROOT / "tools/runtime/control.py"), *args]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        stdout = res.stdout.strip()
        data = {}
        if stdout:
            try:
                data = json.loads(stdout)
            except Exception:
                pass
        return res.returncode, data, stdout

    def test_cli_tax_quota_and_status(self) -> None:
        tenant = "cli-quota-tenant"

        # 1. invoice-quota-config
        code, cfg, _ = self.run_cli(
            "invoice-quota-config",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--monthly-quota-minor", "500000",
            "--single-limit-minor", "80000",
            "--alarm-threshold-pct", "85",
            "--operator", "cli-finance-op",
        )
        self.assertEqual(0, code)
        self.assertEqual(500000, cfg["monthlyTaxQuotaMinor"])
        self.assertEqual(80000, cfg["singleInvoiceLimitMinor"])

        # 2. invoice-quota-status
        code, status, _ = self.run_cli(
            "invoice-quota-status",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--tax-period", "2026-09",
        )
        self.assertEqual(0, code)
        self.assertEqual(500000, status["monthlyTaxQuotaMinor"])
        self.assertEqual(0, status["usedTaxQuotaMinor"])

    def test_cli_split_apply(self) -> None:
        tenant = "cli-split-tenant"

        # Configure quota
        self.run_cli(
            "invoice-quota-config",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--monthly-quota-minor", "1000000",
            "--single-limit-minor", "50000",
            "--alarm-threshold-pct", "85",
            "--operator", "cli-op",
        )

        req_path = Path(self.temporary.name) / "split_req.json"
        req_path.write_text(
            json.dumps({
                "tenantId": tenant,
                "paymentIntentId": "pi_cli_split_1",
                "invoiceType": "vat_electronic_normal",
                "buyerInfo": {"name": "中国移动通信集团", "taxNumber": "911100007109250000", "buyerType": "enterprise"},
                "sellerInfo": {"name": "榆钱儿支付", "taxNumber": "91110105MA02YYYYYY"},
                "items": [
                    {
                        "itemName": "短信网关企业套餐",
                        "quantity": 1,
                        "unitPriceMinor": 120000,
                        "taxRateBasisPoints": 600,
                        "taxClassificationCode": "3040201010000000000",
                    }
                ],
            }),
            encoding="utf-8",
        )

        code, split_res, _ = self.run_cli(
            "invoice-split-apply",
            "--database", str(self.db_path),
            "--request", str(req_path),
            "--actor", "cli-actor",
        )
        self.assertEqual(0, code)
        self.assertEqual(3, split_res["splitCount"])
        self.assertEqual(3, len(split_res["invoices"]))

    def test_cli_self_service_create_and_redeem(self) -> None:
        tenant = "cli-self-service"

        # 1. Create self service session
        code, session, _ = self.run_cli(
            "invoice-self-service-create",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--payment-intent", "pi_cli_self_1",
            "--amount-minor", "19900",
            "--created-by", "cashier-007",
            "--ttl-hours", "24",
        )
        self.assertEqual(0, code)
        token = session["sessionToken"]

        # 2. Redeem
        code, inv, _ = self.run_cli(
            "invoice-self-service-redeem",
            "--database", str(self.db_path),
            "--token", token,
            "--buyer-name", "阿里巴巴（中国）有限公司",
            "--buyer-tax-id", "91330100799655058B",
            "--buyer-email", "tax@alibaba-inc.com",
        )
        self.assertEqual(0, code)
        self.assertEqual("ISSUED", inv["status"])
        self.assertEqual(19900, inv["totalAmountMinor"])
        self.assertEqual("阿里巴巴（中国）有限公司", inv["buyerName"])

    def test_cli_tax_declaration_and_subscription_auto(self) -> None:
        tenant = "cli-tax-and-sub"

        # 1. invoice-subscription-auto
        code, inv, _ = self.run_cli(
            "invoice-subscription-auto",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--subscription-id", "sub_cli_cloud_101",
            "--billing-cycle", "2026-09",
            "--amount-minor", "50000",
            "--plan-name", "云原生专属集群包月服务",
            "--buyer-name", "腾讯科技（深圳）有限公司",
            "--buyer-tax-id", "91440300708461136T",
            "--buyer-email", "cloud-bill@tencent.com",
            "--operator", "cli-sub-bot",
        )
        self.assertEqual(0, code)
        self.assertEqual("ISSUED", inv["status"])

        # 2. invoice-tax-declaration JSON
        code, summary, _ = self.run_cli(
            "invoice-tax-declaration",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--tax-period", "2026-09",
            "--format", "json",
        )
        self.assertEqual(0, code)
        self.assertEqual("2026-09", summary["taxPeriod"])
        self.assertEqual(1, summary["totals"]["totalBlueCount"])

        # 3. invoice-tax-declaration CSV file export
        csv_out = Path(self.temporary.name) / "declaration.csv"
        code, res, _ = self.run_cli(
            "invoice-tax-declaration",
            "--database", str(self.db_path),
            "--tenant", tenant,
            "--tax-period", "2026-09",
            "--format", "csv",
            "--out", str(csv_out),
        )
        self.assertEqual(0, code)
        self.assertTrue(csv_out.exists())
        csv_text = csv_out.read_text(encoding="utf-8")
        self.assertIn("税率(%)", csv_text)
        self.assertIn("6.0%", csv_text)


if __name__ == "__main__":
    unittest.main()
