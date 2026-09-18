"""Enterprise E3 and E4 Test Suite for Financial Exceptions, 4-Eyes Resolution & Reporting (B78-B79)."""
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
from tools.runtime.elmpay_runtime.financial_ledger import FinancialDoubleEntryLedger
from tools.runtime.elmpay_runtime.financial_reporting import (
    FinancialExceptionManager,
    FinancialReportingEngine,
)


class TestEnterpriseExceptionsReportingE3E4(unittest.TestCase):
    """Rigorous E3 and E4 test suite for financial exception tickets, 4-eyes review, and audit reporting."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_exc_rep.db"
        self.store = DurableStore(self.db_path)
        self.exc_mgr = FinancialExceptionManager(self.store)
        self.rep_engine = FinancialReportingEngine(self.store)
        self.fin_ledger = FinancialDoubleEntryLedger(self.store)
        self.tenant_id = "TENANT_FIN_01"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_cli(self, *args: str) -> tuple[int, str]:
        cmd = [sys.executable, "tools/runtime/control.py", *args]
        env = dict(os.environ)
        env["PYTHONPATH"] = f"tools/runtime:{env.get('PYTHONPATH', '')}"
        res = subprocess.run(cmd, capture_output=True, text=True, env=env)
        return res.returncode, res.stdout.strip()

    # -------------------------------------------------------------------------
    # E3: Functional, State Transitions & Financial Math Invariants
    # -------------------------------------------------------------------------

    def test_e3_exception_ticket_creation_and_filtering(self) -> None:
        """Verify ticket creation across all categories and query filtering."""
        t1 = self.exc_mgr.create_ticket(
            self.tenant_id,
            category="SURPLUS",
            reference_id="CH_TXN_001",
            amount_minor=10000,
            currency="CNY",
            notes="Channel surplus on Alipay statement",
        )
        self.assertEqual(t1["category"], "SURPLUS")
        self.assertEqual(t1["status"], "OPEN")
        self.assertEqual(t1["amountMinor"], 10000)

        t2 = self.exc_mgr.create_ticket(
            self.tenant_id,
            category="DEFICIT",
            reference_id="CH_TXN_002",
            amount_minor=5000,
            currency="CNY",
        )
        self.assertEqual(t2["category"], "DEFICIT")

        # Invalid category fails
        with self.assertRaises(ValidationError):
            self.exc_mgr.create_ticket(
                self.tenant_id,
                category="UNKNOWN_CAT",
                reference_id="CH_TXN_003",
                amount_minor=1000,
                currency="CNY",
            )

        # Invalid amount fails
        with self.assertRaises(ValidationError):
            self.exc_mgr.create_ticket(
                self.tenant_id,
                category="SURPLUS",
                reference_id="CH_TXN_004",
                amount_minor=-500,
                currency="CNY",
            )

        # Query filtering
        all_tickets = self.exc_mgr.list_tickets(self.tenant_id)
        self.assertEqual(len(all_tickets), 2)

        surplus_tickets = self.exc_mgr.list_tickets(self.tenant_id, category="SURPLUS")
        self.assertEqual(len(surplus_tickets), 1)
        self.assertEqual(surplus_tickets[0]["ticketId"], t1["ticketId"])

    def test_e3_four_eyes_maker_checker_write_off(self) -> None:
        """Verify Maker proposal and Checker approval for bad-debt WRITE_OFF with automated general ledger entry."""
        t = self.exc_mgr.create_ticket(
            self.tenant_id,
            category="DEFICIT",
            reference_id="TX_MISSING_01",
            amount_minor=2000,
            currency="CNY",
            notes="Unrecoverable channel deduction",
        )

        # Maker step
        prop = self.exc_mgr.propose_resolution(
            self.tenant_id,
            ticket_id=t["ticketId"],
            action="WRITE_OFF",
            maker_id="OPERATOR_ALICE",
            notes="Channel confirmed unrecoverable loss, propose bad debt write-off",
        )
        self.assertEqual(prop["status"], "PENDING_CHECKER")
        self.assertEqual(prop["proposedAction"], "WRITE_OFF")

        # Checker step (different operator)
        appr = self.exc_mgr.approve_resolution(
            self.tenant_id,
            ticket_id=t["ticketId"],
            checker_id="FIN_MANAGER_BOB",
        )
        self.assertEqual(appr["status"], "APPROVED")
        self.assertIsNotNone(appr["journalEntryId"])

        # Check ledger balance
        tb = self.fin_ledger.generate_trial_balance(self.tenant_id)
        self.assertTrue(tb["isBalanced"])
        cny_rep = next(r for r in tb["reports"] if r["currency"] == "CNY")
        bad_debt = next(a for a in cny_rep["accounts"] if a["accountCode"] == "5002_BAD_DEBT_EXPENSE")
        self.assertEqual(bad_debt["debitMinor"], 2000)

    def test_e3_four_eyes_maker_checker_manual_posting(self) -> None:
        """Verify Maker-Checker manual posting for missing platform cash in transit."""
        t = self.exc_mgr.create_ticket(
            self.tenant_id,
            category="SURPLUS",
            reference_id="BANK_SURPLUS_99",
            amount_minor=50000,
            currency="CNY",
        )

        self.exc_mgr.propose_resolution(
            self.tenant_id,
            ticket_id=t["ticketId"],
            action="MANUAL_POSTING",
            maker_id="MAKER_MIKE",
            notes="Offline bank clearing confirmed received",
        )

        appr = self.exc_mgr.approve_resolution(
            self.tenant_id,
            ticket_id=t["ticketId"],
            checker_id="CHECKER_CAROL",
        )
        self.assertEqual(appr["status"], "APPROVED")

        # Verify ledger
        tb = self.fin_ledger.generate_trial_balance(self.tenant_id)
        self.assertTrue(tb["isBalanced"])
        cny_rep = next(r for r in tb["reports"] if r["currency"] == "CNY")
        cash_transit = next(a for a in cny_rep["accounts"] if a["accountCode"] == "1001_CASH_IN_TRANSIT")
        self.assertEqual(cash_transit["debitMinor"], 50000)

    def test_e3_four_eyes_maker_checker_rejection(self) -> None:
        """Checker rejects Maker's proposal; Maker re-proposes an amended action."""
        t = self.exc_mgr.create_ticket(
            self.tenant_id,
            category="AMOUNT_MISMATCH",
            reference_id="MISMATCH_01",
            amount_minor=300,
            currency="CNY",
        )

        # Propose
        self.exc_mgr.propose_resolution(
            self.tenant_id,
            ticket_id=t["ticketId"],
            action="WRITE_OFF",
            maker_id="MAKER_ALICE",
            notes="Small difference, write off",
        )

        # Reject
        rej = self.exc_mgr.reject_resolution(
            self.tenant_id,
            ticket_id=t["ticketId"],
            checker_id="CHECKER_BOB",
            reason="Channel agreement allows clawback, do not write off",
        )
        self.assertEqual(rej["status"], "REJECTED")

        # Maker re-proposes
        prop2 = self.exc_mgr.propose_resolution(
            self.tenant_id,
            ticket_id=t["ticketId"],
            action="CHARGE_BACK_RECOVERY",
            maker_id="MAKER_ALICE",
            notes="Revised to channel recovery",
        )
        self.assertEqual(prop2["status"], "PENDING_CHECKER")

    def test_e3_financial_period_report_aggregation(self) -> None:
        """Verify accurate integer financial reporting metrics: GMV, Fees, Interchange, Net Revenue, Take Rate."""
        t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 31, 23, 59, 59, tzinfo=timezone.utc)

        # 1. Sale 1: GMV 100,000 minor, Fee 3,000 minor, Merchant 97,000 minor
        self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="PAYMENT_CAPTURED",
            source_event_id="SALE_1",
            currency="CNY",
            legs=[
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 100000},
                {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 97000},
                {"accountCode": "4001_PROCESSING_FEE_REVENUE", "direction": "CREDIT", "amountMinor": 3000},
            ],
            now=t0 + timedelta(days=5),
        )

        # 2. Interchange expense: 1,200 minor paid to gateway
        self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="INTERCHANGE_FEE",
            source_event_id="INT_1",
            currency="CNY",
            legs=[
                {"accountCode": "5001_INTERCHANGE_EXPENSE", "direction": "DEBIT", "amountMinor": 1200},
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "CREDIT", "amountMinor": 1200},
            ],
            now=t0 + timedelta(days=6),
        )

        # 3. Sale 2: GMV 50,000 minor, Fee 1,500 minor, Merchant 48,500 minor
        self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="PAYMENT_CAPTURED",
            source_event_id="SALE_2",
            currency="CNY",
            legs=[
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 50000},
                {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 48500},
                {"accountCode": "4001_PROCESSING_FEE_REVENUE", "direction": "CREDIT", "amountMinor": 1500},
            ],
            now=t0 + timedelta(days=10),
        )

        # Generate report
        report = self.rep_engine.generate_period_report(
            self.tenant_id,
            period_start=t0,
            period_end=t1,
            currency="CNY",
        )

        self.assertEqual(report["gmvMinor"], 150000)
        self.assertEqual(report["feeRevenueMinor"], 4500)
        self.assertEqual(report["interchangeExpenseMinor"], 1200)
        self.assertEqual(report["netRevenueMinor"], 3300)  # 4500 - 1200 = 3300
        self.assertEqual(report["merchantPayableMinor"], 145500)
        self.assertEqual(report["transactionCount"], 3)
        # Take rate bps: (4500 * 10000) // 150000 = 300 bps (3.0%)
        self.assertEqual(report["takeRateBasisPoints"], 300)

    def test_e3_immutable_audit_manifest_export_and_verify(self) -> None:
        """Export signed financial audit manifest and verify cryptographic digest seal."""
        t0 = datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 2, 28, 23, 59, 59, tzinfo=timezone.utc)

        # Post a transaction
        self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="PAYMENT_CAPTURED",
            source_event_id="EVT_MAN_01",
            currency="USD",
            legs=[
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 80000},
                {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 80000},
            ],
            now=t0 + timedelta(days=2),
        )

        manifest = self.rep_engine.export_financial_audit_manifest(
            self.tenant_id,
            period_start=t0,
            period_end=t1,
            currency="USD",
        )

        self.assertIn("manifestDigest", manifest)
        self.assertEqual(len(manifest["manifestDigest"]), 64)
        self.assertEqual(manifest["metrics"]["gmvMinor"], 80000)

        # Independent verification
        ver = FinancialReportingEngine.verify_financial_audit_manifest(manifest)
        self.assertTrue(ver["valid"])
        self.assertEqual(ver["computedDigest"], manifest["manifestDigest"])

    # -------------------------------------------------------------------------
    # E4: Security, Fail-Closed, Concurrency & Tampering Boundaries
    # -------------------------------------------------------------------------

    def test_e4_maker_equals_checker_fail_closed(self) -> None:
        """Fail-closed: Operator cannot approve their own proposed resolution."""
        t = self.exc_mgr.create_ticket(
            self.tenant_id,
            category="DEFICIT",
            reference_id="SELF_APPROVE_01",
            amount_minor=1000,
            currency="CNY",
        )

        self.exc_mgr.propose_resolution(
            self.tenant_id,
            ticket_id=t["ticketId"],
            action="WRITE_OFF",
            maker_id="ROGUE_USER_DAVID",
            notes="Attempting self-approval",
        )

        # Same user as checker must raise ValidationError
        with self.assertRaises(ValidationError) as ctx:
            self.exc_mgr.approve_resolution(
                self.tenant_id,
                ticket_id=t["ticketId"],
                checker_id="ROGUE_USER_DAVID",
            )
        self.assertIn("four-eyes principle", str(ctx.exception))

        # Ticket status remains PENDING_CHECKER, no write-off entry posted
        t_check = self.exc_mgr.list_tickets(self.tenant_id)[0]
        self.assertEqual(t_check["status"], "PENDING_CHECKER")
        self.assertIsNone(t_check["journalEntryId"])

    def test_e4_audit_manifest_tamper_detection(self) -> None:
        """Security: Tampering with even 1 minor cent in an exported audit manifest causes verification failure."""
        t0 = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 3, 31, 23, 59, 59, tzinfo=timezone.utc)

        self.fin_ledger.post_journal_entry(
            self.tenant_id,
            transaction_type="PAYMENT_CAPTURED",
            source_event_id="EVT_TAMPER_01",
            currency="CNY",
            legs=[
                {"accountCode": "1001_CASH_IN_TRANSIT", "direction": "DEBIT", "amountMinor": 10000},
                {"accountCode": "2001_MERCHANT_PAYABLE", "direction": "CREDIT", "amountMinor": 10000},
            ],
            now=t0 + timedelta(days=1),
        )

        manifest = self.rep_engine.export_financial_audit_manifest(
            self.tenant_id,
            period_start=t0,
            period_end=t1,
            currency="CNY",
        )
        self.assertTrue(FinancialReportingEngine.verify_financial_audit_manifest(manifest)["valid"])

        # Tamper with GMV metric (+1 cent)
        tampered = json.loads(json.dumps(manifest))
        tampered["metrics"]["gmvMinor"] = 10001

        ver = FinancialReportingEngine.verify_financial_audit_manifest(tampered)
        self.assertFalse(ver["valid"])
        self.assertNotEqual(ver["computedDigest"], ver["expectedDigest"])

    def test_e4_concurrent_ticket_approval_race(self) -> None:
        """Concurrency stress: 10 concurrent threads attempting to approve the same ticket simultaneously."""
        t = self.exc_mgr.create_ticket(
            self.tenant_id,
            category="DEFICIT",
            reference_id="RACE_TKT_01",
            amount_minor=5000,
            currency="CNY",
        )
        self.exc_mgr.propose_resolution(
            self.tenant_id,
            ticket_id=t["ticketId"],
            action="WRITE_OFF",
            maker_id="MAKER_ALICE",
            notes="Concurrent test",
        )

        success_count = 0
        failure_count = 0

        def try_approve(checker_id: str) -> bool:
            try:
                self.exc_mgr.approve_resolution(
                    self.tenant_id,
                    ticket_id=t["ticketId"],
                    checker_id=checker_id,
                )
                return True
            except ValidationError:
                return False

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(try_approve, f"CHECKER_{i}") for i in range(10)]
            for f in futures:
                if f.result():
                    success_count += 1
                else:
                    failure_count += 1

        # Exactly 1 thread successfully approves; 9 fail
        self.assertEqual(success_count, 1)
        self.assertEqual(failure_count, 9)

        # Ledger contains exactly 1 write-off entry
        audit = self.fin_ledger.verify_chain_integrity(self.tenant_id)
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["entriesAudited"], 1)

    def test_e4_cli_exceptions_and_reporting_e2e(self) -> None:
        """CLI Control Plane: test end-to-end exception ticket workflow and financial audit export."""
        # 1. exception-ticket-create CLI
        ret, out = self._run_cli(
            "exception-ticket-create",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--category", "DEFICIT",
            "--reference-id", "CLI_REF_99",
            "--amount-minor", "12000",
            "--currency", "CNY",
            "--notes", "CLI created exception ticket",
        )
        self.assertEqual(ret, 0, f"Ticket create failed: {out}")
        t_data = json.loads(out)
        t_id = t_data["ticketId"]
        self.assertEqual(t_data["category"], "DEFICIT")

        # 2. exception-ticket-propose CLI
        ret, out = self._run_cli(
            "exception-ticket-propose",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--ticket-id", t_id,
            "--action", "WRITE_OFF",
            "--maker-id", "CLI_MAKER_1",
            "--notes", "CLI proposed write-off",
        )
        self.assertEqual(ret, 0, f"Ticket propose failed: {out}")
        p_data = json.loads(out)
        self.assertEqual(p_data["status"], "PENDING_CHECKER")

        # 3. exception-ticket-approve CLI
        ret, out = self._run_cli(
            "exception-ticket-approve",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--ticket-id", t_id,
            "--checker-id", "CLI_CHECKER_2",
        )
        self.assertEqual(ret, 0, f"Ticket approve failed: {out}")
        a_data = json.loads(out)
        self.assertEqual(a_data["status"], "APPROVED")

        # 4. exception-ticket-list CLI
        ret, out = self._run_cli(
            "exception-ticket-list",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--status", "APPROVED",
        )
        self.assertEqual(ret, 0, f"Ticket list failed: {out}")
        l_data = json.loads(out)
        self.assertEqual(l_data["count"], 1)

        # 5. financial-report-export CLI
        manifest_file = Path(self.temp_dir.name) / "cli_manifest.json"
        now = datetime.now(timezone.utc)
        t_start = now - timedelta(days=1)
        t_end = now + timedelta(days=1)
        ret, out = self._run_cli(
            "financial-report-export",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--start", t_start.isoformat(),
            "--end", t_end.isoformat(),
            "--currency", "CNY",
            "--out", str(manifest_file),
        )
        self.assertEqual(ret, 0, f"Report export failed: {out}")
        self.assertTrue(manifest_file.exists())

        # 6. financial-report-verify CLI
        ret, out = self._run_cli(
            "financial-report-verify",
            "--manifest", str(manifest_file),
        )
        self.assertEqual(ret, 0, f"Report verify failed: {out}")
        v_data = json.loads(out)
        self.assertTrue(v_data["valid"])


if __name__ == "__main__":
    unittest.main()
