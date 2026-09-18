"""Enterprise commercial contracts, tax withholding, customs declaration, and treasury cash pool E3 & E4 tests.

Covers:
- E3: Commercial contract registration, milestone breakdown, and phased billing ceiling validation
- E3: China IIT labor progressive & WHT calculation, certificate issuance, and Golden Tax IV CSV export
- E3: GACC Order 179 cross-border ecommerce payment declaration, XML generation, and customs receipt callbacks
- E3: Multi-entity corporate treasury cash pool, virtual sub-accounts, zero-balance and target-balance sweeping
- E4: 10-thread concurrent milestone invoicing race condition (strictly enforces milestone balance ceiling)
- E4: Concurrent treasury deposits and sweeps preserving double-entry mathematical conservation
- E4: Direct database tamper injection detecting cryptographic digest mismatches
- CLI: End-to-end subprocess integration across contract, tax withholding, customs, and treasury subcommands
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
from tools.runtime.elmpay_runtime.contract_billing import CommercialContractLedger
from tools.runtime.elmpay_runtime.tax_withholding import (
    TaxWithholdingLedger,
    calculate_tax_withholding,
)
from tools.runtime.elmpay_runtime.customs_declaration import (
    CustomsPaymentDeclarationManager,
    render_customs_179_xml,
)
from tools.runtime.elmpay_runtime.treasury_pool import TreasuryPoolManager


class EnterpriseTreasuryCustomsTaxE3Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "e3_enterprise.db"
        self.store = DurableStore(self.db_path)
        self.tenant_id = "tenant_e3_enterprise"
        self.now = datetime(2026, 9, 18, 14, 0, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_commercial_contract_milestone_invoicing_lifecycle(self) -> None:
        """E3: Contract creation, milestone breakdown conservation, and phased billing enforcement."""
        ledger = CommercialContractLedger(self.store)

        # 1. Create contract of 100,000 minor (1,000 CNY)
        total_minor = 100000
        contract = ledger.create_contract(
            self.tenant_id,
            title="企业级数据中台技术服务采购合同",
            buyer_name="北京天融信科技有限公司",
            buyer_tax_number="91110108MA00XYZ888",
            seller_name="云支付科技有限公司",
            seller_tax_number="91110108MA00ABC012",
            total_amount_minor=total_minor,
            now=self.now,
        )
        cid = contract["contractId"]
        self.assertEqual(contract["status"], "ACTIVE")
        self.assertEqual(contract["totalAmountMinor"], total_minor)

        # 2. Add milestones with sum validation
        # Non-matching sum must fail closed
        with self.assertRaises(ValidationError) as ctx:
            ledger.add_milestones(
                self.tenant_id,
                cid,
                [
                    {"name": "预付款", "amount_minor": 30000, "seq_order": 1},
                    {"name": "初验款", "amount_minor": 40000, "seq_order": 2},
                ],
                now=self.now,
            )
        self.assertIn("must exactly equal contract total", str(ctx.exception))

        # Valid milestone distribution: 30%, 50%, 20%
        ms_list = ledger.add_milestones(
            self.tenant_id,
            cid,
            [
                {"name": "预付款", "amount_minor": 30000, "seq_order": 1, "due_date": "2026-09-30"},
                {"name": "初验款", "amount_minor": 50000, "seq_order": 2, "due_date": "2026-10-31"},
                {"name": "质保尾款", "amount_minor": 20000, "seq_order": 3, "due_date": "2026-12-31"},
            ],
            now=self.now,
        )
        self.assertEqual(len(ms_list), 3)

        # 3. Invoice Milestone 1 in full (30,000 minor)
        st1 = ledger.invoice_contract_milestone(
            self.tenant_id,
            cid,
            milestone_id_or_seq=1,
            invoice_id="inv_contract_001",
            amount_minor=30000,
            actor_id="finance_operator",
            notes="预付款全额开票",
            now=self.now,
        )
        self.assertEqual(st1["billedAmountMinor"], 30000)
        self.assertEqual(st1["milestones"][0]["status"], "FULLY_INVOICED")
        self.assertEqual(st1["status"], "ACTIVE")

        # 4. Partial invoicing on Milestone 2 (20,000 of 50,000 minor)
        st2 = ledger.invoice_contract_milestone(
            self.tenant_id,
            cid,
            milestone_id_or_seq=2,
            invoice_id="inv_contract_002",
            amount_minor=20000,
            actor_id="finance_operator",
            notes="初验款部分开票",
            now=self.now,
        )
        self.assertEqual(st2["billedAmountMinor"], 50000)
        self.assertEqual(st2["milestones"][1]["status"], "PARTIALLY_INVOICED")

        # 5. Over-invoicing Milestone 2 balance (remaining 30,000; trying 40,000) must fail closed
        with self.assertRaises(ValidationError) as ctx:
            ledger.invoice_contract_milestone(
                self.tenant_id,
                cid,
                milestone_id_or_seq=2,
                invoice_id="inv_contract_excess",
                amount_minor=40000,
                now=self.now,
            )
        self.assertIn("exceeds remaining milestone balance", str(ctx.exception))

        # 6. Complete remaining milestone 2 and milestone 3 -> Contract completed
        ledger.invoice_contract_milestone(self.tenant_id, cid, 2, "inv_contract_003", amount_minor=30000, now=self.now)
        final_st = ledger.invoice_contract_milestone(self.tenant_id, cid, 3, "inv_contract_004", amount_minor=20000, now=self.now)
        self.assertEqual(final_st["billedAmountMinor"], total_minor)
        self.assertEqual(final_st["remainingUnbilledMinor"], 0)
        self.assertEqual(final_st["status"], "COMPLETED")
        self.assertEqual(len(final_st["ledger"]), 4)

    def test_tax_withholding_calculation_and_certificate_issuance(self) -> None:
        """E3: Progressive IIT withholding calculation, certificate issuance, and Golden Tax CSV export."""
        # 1. Test calculation engine
        # Below 4000 RMB (300,000 minor): deduction = 80,000 minor, taxable = 220,000, rate = 20%
        calc1 = calculate_tax_withholding(300000, "LABOR_SERVICE")
        self.assertEqual(calc1["statutoryDeductionMinor"], 80000)
        self.assertEqual(calc1["taxableIncomeMinor"], 220000)
        self.assertEqual(calc1["taxRateBasisPoints"], 2000)
        self.assertEqual(calc1["taxWithheldMinor"], 44000)
        self.assertEqual(calc1["netPayoutMinor"], 256000)

        # Above 4000 RMB (1,000,000 minor = 10,000 RMB): deduction = 20% (200,000 minor), taxable = 800,000, rate = 20%
        calc2 = calculate_tax_withholding(1000000, "LABOR_SERVICE")
        self.assertEqual(calc2["statutoryDeductionMinor"], 200000)
        self.assertEqual(calc2["taxableIncomeMinor"], 800000)
        self.assertEqual(calc2["taxWithheldMinor"], 160000)
        self.assertEqual(calc2["netPayoutMinor"], 840000)

        # High bracket (6,000,000 minor = 60,000 RMB):
        # deduction = 12,000 RMB (1,200,000 minor), taxable = 48,000 RMB (4,800,000 minor)
        # bracket 30% with quick deduction 2,000 RMB (200,000 minor):
        # tax = 48,000 * 0.3 - 2,000 = 12,400 RMB (1,240,000 minor)
        calc3 = calculate_tax_withholding(6000000, "LABOR_SERVICE")
        self.assertEqual(calc3["taxRateBasisPoints"], 3000)
        self.assertEqual(calc3["quickDeductionMinor"], 200000)
        self.assertEqual(calc3["taxWithheldMinor"], 1240000)
        self.assertEqual(calc3["netPayoutMinor"], 4760000)

        # Non-resident corporate WHT flat 10%
        calc_wht = calculate_tax_withholding(500000, "NON_RESIDENT_WHT")
        self.assertEqual(calc_wht["taxRateBasisPoints"], 1000)
        self.assertEqual(calc_wht["statutoryDeductionMinor"], 0)
        self.assertEqual(calc_wht["taxWithheldMinor"], 50000)
        self.assertEqual(calc_wht["netPayoutMinor"], 450000)

        # 2. Issue certificates and verify cryptographic digest
        tax_ledger = TaxWithholdingLedger(self.store)
        cert1 = tax_ledger.issue_certificate(
            self.tenant_id,
            payee_name="张三",
            payee_id_number="110101199001011234",
            gross_amount_minor=1000000,
            income_type="LABOR_SERVICE",
            now=self.now,
        )
        self.assertTrue(cert1["integrityValid"])
        self.assertEqual(cert1["taxWithheldMinor"], 160000)

        cert2 = tax_ledger.issue_certificate(
            self.tenant_id,
            payee_name="李四",
            payee_id_number="110101199202025678",
            gross_amount_minor=300000,
            income_type="LABOR_SERVICE",
            now=self.now,
        )
        self.assertTrue(cert2["integrityValid"])

        # 3. Create remittance filing batch
        batch = tax_ledger.create_remittance_batch(self.tenant_id, "2026-09", now=self.now)
        self.assertEqual(batch["itemCount"], 2)
        self.assertEqual(batch["totalGrossMinor"], 1300000)
        self.assertEqual(batch["totalTaxWithheldMinor"], 204000)

        # 4. Export Golden Tax IV CSV
        csv_content = tax_ledger.export_golden_tax_csv(self.tenant_id, "2026-09")
        self.assertIn("完税凭证号,所得项目,纳税人姓名", csv_content)
        self.assertIn("张三", csv_content)
        self.assertIn("李四", csv_content)

    def test_cross_border_customs_payment_declaration_lifecycle(self) -> None:
        """E3: GACC Order 179 cross-border payment declaration, XML rendering, and receipt callbacks."""
        mgr = CustomsPaymentDeclarationManager(self.store)

        order_no = f"ORD_CB_{uuid.uuid4().hex[:8]}"
        pi_id = f"pi_cb_{uuid.uuid4().hex[:8]}"

        # 1. Declare cross-border retail import payment
        decl = mgr.declare_payment(
            self.tenant_id,
            customs_code="5100",  # 广州海关
            ebp_code="4401960001",
            ebc_code="4401960002",
            order_no=order_no,
            payment_intent_id=pi_id,
            payer_name="王小明",
            payer_id_number="440101199505051234",
            payer_phone="13800138000",
            amount_minor=35000,  # 350.00 RMB
            currency="142",
            now=self.now,
        )
        self.assertEqual(decl["status"], "REPORTED")
        self.assertTrue(decl["integrityValid"])
        self.assertIn("<CEB311Message", decl["xmlPayload"])
        self.assertIn("<amountPaid>350.00</amountPaid>", decl["xmlPayload"])
        self.assertIn("<customsCode>5100</customsCode>", decl["xmlPayload"])
        self.assertEqual(len(decl["logs"]), 1)

        # 2. Duplicate declaration must fail closed
        with self.assertRaises(ValidationError) as ctx:
            mgr.declare_payment(
                self.tenant_id,
                customs_code="5100",
                ebp_code="4401960001",
                ebc_code="4401960002",
                order_no=order_no,
                payment_intent_id=pi_id,
                payer_name="王小明",
                payer_id_number="440101199505051234",
                payer_phone="13800138000",
                amount_minor=35000,
                now=self.now,
            )
        self.assertIn("already exists", str(ctx.exception))

        # 3. Simulate customs callback acceptance
        ack = mgr.acknowledge_receipt(
            self.tenant_id,
            decl["declarationId"],
            status="CUSTOMS_ACCEPTED",
            receipt_code="0",
            receipt_message="海关审核通过，三单比对成功",
            now=self.now,
        )
        self.assertEqual(ack["status"], "CUSTOMS_ACCEPTED")
        self.assertEqual(len(ack["logs"]), 2)

    def test_treasury_cash_pool_virtual_accounts_and_sweeping(self) -> None:
        """E3: Multi-entity corporate treasury cash pool, virtual accounts, and automated sweeping."""
        tmgr = TreasuryPoolManager(self.store)

        # 1. Initialize master treasury pool with 50,000 minor balance
        pool = tmgr.create_pool(
            self.tenant_id,
            pool_name="大中华区集团统一资金池",
            master_account_id="ACC_MASTER_HK_001",
            currency="CNY",
            initial_master_balance_minor=50000,
            now=self.now,
        )
        pid = pool["poolId"]
        self.assertEqual(pool["masterBalanceMinor"], 50000)

        # 2. Create sub-account A (Zero balance sweep) and sub-account B (Target balance sweep)
        va_a = tmgr.create_virtual_account(
            self.tenant_id,
            pid,
            account_number="VA_STORE_SH_01",
            account_name="上海静安旗舰店资金户",
            entity_type="STORE",
            sweep_policy="ZERO_BALANCE",
            now=self.now,
        )
        va_b = tmgr.create_virtual_account(
            self.tenant_id,
            pid,
            account_number="VA_DIST_GZ_02",
            account_name="华南区分销商虚拟户",
            entity_type="DISTRIBUTOR",
            sweep_policy="TARGET_BALANCE",
            target_balance_minor=5000,
            now=self.now,
        )

        # 3. Deposit revenue into sub-accounts
        tmgr.deposit_to_virtual_account(self.tenant_id, pid, va_a["vaId"], 20000, now=self.now)
        tmgr.deposit_to_virtual_account(self.tenant_id, pid, va_b["vaId"], 15000, now=self.now)

        st_before = tmgr.get_pool_status(self.tenant_id, pid)
        self.assertEqual(st_before["masterBalanceMinor"], 50000)
        self.assertEqual(st_before["subAccountsTotalMinor"], 35000)
        self.assertEqual(st_before["totalPooledFundsMinor"], 85000)

        # 4. Execute automated sweep
        sweep_res = tmgr.execute_sweep(self.tenant_id, pid, now=self.now)
        # Sub A swept 20000 -> balance 0
        # Sub B swept (15000 - 5000) = 10000 -> balance 5000
        # Master pool balance = 50000 + 20000 + 10000 = 80000
        self.assertEqual(sweep_res["masterBalanceMinor"], 80000)
        self.assertEqual(sweep_res["subAccountsTotalMinor"], 5000)
        # Invariant: Total pooled funds remains 85000 exactly
        self.assertEqual(sweep_res["totalPooledFundsMinor"], 85000)

        # 5. Allocate funds from master pool to Sub A
        tmgr.allocate_funds(self.tenant_id, pid, va_a["vaId"], 10000, now=self.now)
        st_after_alloc = tmgr.get_pool_status(self.tenant_id, pid)
        self.assertEqual(st_after_alloc["masterBalanceMinor"], 70000)
        self.assertEqual(st_after_alloc["subAccountsTotalMinor"], 15000)
        self.assertEqual(st_after_alloc["totalPooledFundsMinor"], 85000)


class EnterpriseTreasuryCustomsTaxE4Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "e4_enterprise.db"
        self.store = DurableStore(self.db_path)
        self.tenant_id = "tenant_e4_concurrency"
        self.now = datetime(2026, 9, 18, 15, 0, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e4_concurrent_milestone_invoicing_race_condition(self) -> None:
        """E4: 10 concurrent threads race to invoice on a milestone with 10,000 minor capacity."""
        ledger = CommercialContractLedger(self.store)
        contract = ledger.create_contract(
            self.tenant_id,
            title="高并发里程碑开票测试合同",
            buyer_name="并发采购方",
            seller_name="云支付科技",
            seller_tax_number="91110108MA00ABC012",
            total_amount_minor=10000,
            now=self.now,
        )
        cid = contract["contractId"]
        ledger.add_milestones(self.tenant_id, cid, [{"name": "一期款", "amount_minor": 10000, "seq_order": 1}], now=self.now)

        thread_count = 10
        chunk_size = 5000  # Only exactly 2 threads can succeed!
        successes: list[dict[str, Any]] = []
        failures: list[str] = []

        def worker(worker_id: int) -> None:
            l = CommercialContractLedger(self.store)
            try:
                res = l.invoice_contract_milestone(
                    self.tenant_id,
                    cid,
                    milestone_id_or_seq=1,
                    invoice_id=f"inv_race_{worker_id}",
                    amount_minor=chunk_size,
                    actor_id=f"worker_{worker_id}",
                    now=self.now,
                )
                successes.append(res)
            except ValidationError as err:
                failures.append(str(err))

        with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = [executor.submit(worker, i) for i in range(thread_count)]
            concurrent.futures.wait(futures)

        # Invariant: Strictly 2 succeed, strictly 8 fail
        self.assertEqual(len(successes), 2)
        self.assertEqual(len(failures), 8)
        for f in failures:
            self.assertTrue(
                "exceeds remaining milestone balance" in f or "cannot invoice against contract with status" in f,
                f"Unexpected failure error: {f}",
            )

        final_st = ledger.get_contract_fulfillment_status(self.tenant_id, cid)
        self.assertEqual(final_st["billedAmountMinor"], 10000)
        self.assertEqual(final_st["remainingUnbilledMinor"], 0)
        self.assertEqual(final_st["status"], "COMPLETED")

    def test_e4_concurrent_treasury_sweep_and_deposit_race_condition(self) -> None:
        """E4: Multi-threaded concurrent deposits and sweeping preserve double-entry invariant."""
        tmgr = TreasuryPoolManager(self.store)
        initial_master = 100000
        pool = tmgr.create_pool(
            self.tenant_id,
            pool_name="高并发资金池测试",
            master_account_id="ACC_CONCUR_001",
            initial_master_balance_minor=initial_master,
            now=self.now,
        )
        pid = pool["poolId"]

        # Create 5 virtual sub-accounts
        vas = []
        for i in range(5):
            v = tmgr.create_virtual_account(
                self.tenant_id,
                pid,
                account_number=f"VA_RACE_{i}",
                account_name=f"门店_{i}",
                sweep_policy="ZERO_BALANCE",
                now=self.now,
            )
            vas.append(v)

        deposit_chunk = 1000
        deposit_ops_per_thread = 4
        total_deposit_threads = 5
        # Total to be deposited: 5 * 4 * 1000 = 20,000 minor

        def depositor(sub_idx: int) -> None:
            mgr = TreasuryPoolManager(self.store)
            va_id = vas[sub_idx]["vaId"]
            for _ in range(deposit_ops_per_thread):
                mgr.deposit_to_virtual_account(self.tenant_id, pid, va_id, deposit_chunk, now=self.now)

        def sweeper() -> None:
            mgr = TreasuryPoolManager(self.store)
            for _ in range(3):
                mgr.execute_sweep(self.tenant_id, pid, now=self.now)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            dep_futures = [executor.submit(depositor, i) for i in range(total_deposit_threads)]
            swp_futures = [executor.submit(sweeper) for _ in range(3)]
            concurrent.futures.wait(dep_futures + swp_futures)

        # Final sweep to consolidate everything
        final_sweep = tmgr.execute_sweep(self.tenant_id, pid, now=self.now)
        expected_total = initial_master + (total_deposit_threads * deposit_ops_per_thread * deposit_chunk)

        self.assertEqual(final_sweep["totalPooledFundsMinor"], expected_total)
        self.assertEqual(final_sweep["masterBalanceMinor"], expected_total)
        self.assertEqual(final_sweep["subAccountsTotalMinor"], 0)

    def test_e4_certificate_and_customs_tamper_detection(self) -> None:
        """E4: Injecting unauthorized database modifications fails cryptographic verification closed."""
        # 1. Certificate tamper detection
        tax_ledger = TaxWithholdingLedger(self.store)
        cert = tax_ledger.issue_certificate(
            self.tenant_id,
            payee_name="王专家",
            payee_id_number="110101198501018888",
            gross_amount_minor=500000,
            now=self.now,
        )
        cert_id = cert["certificateId"]
        self.assertTrue(cert["integrityValid"])

        # Tamper gross_amount_minor directly in SQLite
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE tax_withholding_certificate SET gross_amount_minor=999999 WHERE certificate_id=?",
                (cert_id,),
            )

        tampered_cert = tax_ledger.get_certificate(self.tenant_id, cert_id)
        self.assertFalse(tampered_cert["integrityValid"], "Tampered certificate must fail integrity validation")

        # 2. Customs payment declaration tamper detection
        cus_mgr = CustomsPaymentDeclarationManager(self.store)
        decl = cus_mgr.declare_payment(
            self.tenant_id,
            customs_code="5100",
            ebp_code="4401960001",
            ebc_code="4401960002",
            order_no="ORD_TAMPER_001",
            payment_intent_id="pi_tamper_001",
            payer_name="李用户",
            payer_id_number="440101199001011234",
            payer_phone="13900001111",
            amount_minor=10000,
            now=self.now,
        )
        decl_id = decl["declarationId"]
        self.assertTrue(decl["integrityValid"])

        # Tamper payer_name in SQLite
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE customs_payment_declaration SET payer_name='黑客篡改' WHERE declaration_id=?",
                (decl_id,),
            )

        tampered_decl = cus_mgr.get_declaration(self.tenant_id, decl_id)
        self.assertFalse(tampered_decl["integrityValid"], "Tampered customs declaration must fail integrity validation")


class EnterpriseTreasuryCustomsTaxCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "cli_test.db"
        self.tenant = "tenant_cli_all"
        self.script_path = str(Path(__file__).resolve().parents[1] / "tools/runtime/control.py")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, self.script_path, *args]
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_contract_lifecycle(self) -> None:
        """CLI: contract-create, contract-milestone-add, contract-milestone-invoice, contract-status."""
        # 1. Create contract
        c_res = self._run_cli(
            "contract-create",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--title", "CLI企业采购项目合同",
            "--buyer-name", "深圳前海智能科技有限公司",
            "--seller-name", "云支付科技有限公司",
            "--seller-tax-number", "91110108MA00ABC012",
            "--total-amount-minor", "50000",
        )
        self.assertEqual(c_res.returncode, 0, f"Error: {c_res.stderr}")
        c_data = json.loads(c_res.stdout)
        cid = c_data["contractId"]

        # 2. Add milestones via JSON file
        ms_file = Path(self.temp_dir.name) / "milestones.json"
        ms_file.write_text(json.dumps([
            {"name": "预付款", "amount_minor": 20000, "seq_order": 1},
            {"name": "尾款", "amount_minor": 30000, "seq_order": 2},
        ]), encoding="utf-8")

        m_res = self._run_cli(
            "contract-milestone-add",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--contract-id", cid,
            "--milestones-json", str(ms_file),
        )
        self.assertEqual(m_res.returncode, 0, f"Error: {m_res.stderr}")

        # 3. Invoice milestone 1
        inv_res = self._run_cli(
            "contract-milestone-invoice",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--contract-id", cid,
            "--milestone-seq", "1",
            "--invoice-id", "inv_cli_001",
        )
        self.assertEqual(inv_res.returncode, 0)
        self.assertEqual(json.loads(inv_res.stdout)["billedAmountMinor"], 20000)

        # 4. Check status
        st_res = self._run_cli(
            "contract-status",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--contract-id", cid,
        )
        self.assertEqual(st_res.returncode, 0)
        self.assertEqual(json.loads(st_res.stdout)["remainingUnbilledMinor"], 30000)

    def test_cli_tax_withhold_and_customs(self) -> None:
        """CLI: tax withholding and customs declaration."""
        # Tax calculate
        calc_res = self._run_cli(
            "tax-withhold-calculate",
            "--gross-amount-minor", "800000",
            "--income-type", "LABOR_SERVICE",
        )
        self.assertEqual(calc_res.returncode, 0)
        self.assertEqual(json.loads(calc_res.stdout)["taxWithheldMinor"], 128000)

        # Tax certificate
        cert_res = self._run_cli(
            "tax-withhold-certificate",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--payee-name", "陈顾问",
            "--payee-id", "110101198808081234",
            "--gross-amount-minor", "800000",
        )
        self.assertEqual(cert_res.returncode, 0)
        self.assertTrue(json.loads(cert_res.stdout)["integrityValid"])

        # Customs declaration
        cus_res = self._run_cli(
            "customs-payment-declare",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--customs-code", "5100",
            "--ebp-code", "4401960001",
            "--ebc-code", "4401960002",
            "--order-no", "ORD_CLI_CUSTOMS_01",
            "--payment-intent-id", "pi_cli_customs_01",
            "--payer-name", "周用户",
            "--payer-id", "440101199606061234",
            "--payer-phone", "13900002222",
            "--amount-minor", "29900",
        )
        self.assertEqual(cus_res.returncode, 0)
        self.assertEqual(json.loads(cus_res.stdout)["status"], "REPORTED")

    def test_cli_treasury_pool(self) -> None:
        """CLI: treasury pool creation, virtual account creation, and sweeping."""
        pool_res = self._run_cli(
            "treasury-pool-create",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--pool-name", "CLI自动化资金池",
            "--master-acc-id", "ACC_CLI_MASTER",
            "--initial-balance-minor", "10000",
        )
        self.assertEqual(pool_res.returncode, 0)
        pid = json.loads(pool_res.stdout)["poolId"]

        # Create virtual account
        va_res = self._run_cli(
            "treasury-va-create",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--pool-id", pid,
            "--acc-no", "VA_CLI_SUB_01",
            "--acc-name", "CLI分公司虚拟户",
            "--initial-balance-minor", "5000",
        )
        self.assertEqual(va_res.returncode, 0)

        # Sweep
        swp_res = self._run_cli(
            "treasury-sweep",
            "--database", str(self.db_path),
            "--tenant", self.tenant,
            "--pool-id", pid,
        )
        self.assertEqual(swp_res.returncode, 0)
        self.assertEqual(json.loads(swp_res.stdout)["masterBalanceMinor"], 15000)


if __name__ == "__main__":
    unittest.main()
