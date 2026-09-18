"""E3/E4 tests for enterprise smart routing, tiered/IC++ pricing, webhooks DLQ, and marketplace escrow."""
from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from tools.runtime.elmpay_runtime.common import ValidationError
from tools.runtime.elmpay_runtime.durable import DurableStore
from tools.runtime.elmpay_runtime.smart_routing import SmartRoutingEngine
from tools.runtime.elmpay_runtime.tiered_pricing import TieredPricingEngine
from tools.runtime.elmpay_runtime.webhook_engine import (
    EnterpriseWebhookDispatcher,
    sign_webhook_payload,
    verify_webhook_signature,
)
from tools.runtime.elmpay_runtime.marketplace_escrow import MarketplaceEscrowManager


class TestSmartRoutingEngineE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_routing.db"
        self.store = DurableStore(self.db_path)
        self.engine = SmartRoutingEngine(self.store)
        self.tenant_id = "tenant_routing_corp"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_provider_registration_and_health_state(self) -> None:
        """E3: Validate registration limits, fees, and circuit breaker health transitions."""
        # Valid registration
        reg = self.engine.register_provider_profile(
            tenant_id=self.tenant_id,
            provider_id="acq_alipay_direct",
            provider_name="Alipay Direct Online",
            supported_methods=["ALIPAY", "ALIPAY_HK"],
            supported_currencies=["CNY", "HKD"],
            min_amount_minor=100,
            max_amount_minor=50_000_000,
            fee_basis_points=35,
            fixed_fee_minor=20,
            priority_rank=10,
        )
        self.assertEqual(reg["provider_id"], "acq_alipay_direct")
        self.assertEqual(reg["health_status"], "HEALTHY")
        self.assertEqual(reg["supported_methods"], ["ALIPAY", "ALIPAY_HK"])

        # Health transitions
        updated = self.engine.update_provider_health(self.tenant_id, "acq_alipay_direct", "DEGRADED")
        self.assertEqual(updated["health_status"], "DEGRADED")

        updated = self.engine.update_provider_health(self.tenant_id, "acq_alipay_direct", "CIRCUIT_BROKEN")
        self.assertEqual(updated["health_status"], "CIRCUIT_BROKEN")

        # Invalid health state fails closed
        with self.assertRaises(ValidationError):
            self.engine.update_provider_health(self.tenant_id, "acq_alipay_direct", "INVALID_STATUS")

        # Empty methods/currencies fails closed
        with self.assertRaises(ValidationError):
            self.engine.register_provider_profile(
                tenant_id=self.tenant_id,
                provider_id="acq_invalid",
                provider_name="Invalid Provider",
                supported_methods=[],
                supported_currencies=["CNY"],
            )

        # Negative fee fails closed
        with self.assertRaises(ValidationError):
            self.engine.register_provider_profile(
                tenant_id=self.tenant_id,
                provider_id="acq_invalid",
                provider_name="Invalid Provider",
                supported_methods=["CARD"],
                supported_currencies=["USD"],
                fee_basis_points=-5,
            )

    def test_e3_least_cost_routing_selection_and_fallback_cascade(self) -> None:
        """E3: Least-Cost Routing (LCR) picks the lowest fee candidate, penalizes degraded, and builds fallback cascade."""
        # Provider A: 30 bps + 30 minor fixed
        self.engine.register_provider_profile(
            tenant_id=self.tenant_id,
            provider_id="p_alpha",
            provider_name="Alpha Acquirer",
            supported_methods=["CARD"],
            supported_currencies=["USD"],
            fee_basis_points=30,
            fixed_fee_minor=30,
            priority_rank=10,
        )
        # Provider B: 20 bps + 20 minor fixed (cheaper!)
        self.engine.register_provider_profile(
            tenant_id=self.tenant_id,
            provider_id="p_beta",
            provider_name="Beta Acquirer",
            supported_methods=["CARD"],
            supported_currencies=["USD"],
            fee_basis_points=20,
            fixed_fee_minor=20,
            priority_rank=10,
        )
        # Provider C: 10 bps + 10 minor fixed, but DEGRADED!
        self.engine.register_provider_profile(
            tenant_id=self.tenant_id,
            provider_id="p_gamma",
            provider_name="Gamma Acquirer",
            supported_methods=["CARD"],
            supported_currencies=["USD"],
            fee_basis_points=10,
            fixed_fee_minor=10,
            priority_rank=5,
        )
        self.engine.update_provider_health(self.tenant_id, "p_gamma", "DEGRADED")

        # Amount = 10,000 minor USD ($100.00)
        # p_alpha fee = (10000 * 30)//10000 + 30 = 60
        # p_beta fee = (10000 * 20)//10000 + 20 = 40
        # p_gamma fee = (10000 * 10)//10000 + 10 = 20, but health penalty +100000
        decision = self.engine.route_transaction(
            tenant_id=self.tenant_id,
            payment_intent_id="pi_lcr_001",
            amount_minor=10_000,
            currency="USD",
            payment_method="CARD",
        )

        self.assertEqual(decision["selected_provider_id"], "p_beta")
        self.assertEqual(decision["estimated_fee_minor"], 40)
        self.assertEqual(decision["cascade_routes"], ["p_beta", "p_alpha", "p_gamma"])

    def test_e3_circuit_breaker_exclusion_and_unmatched_fails_closed(self) -> None:
        """E3: Circuit broken providers are immediately eliminated from candidate routing."""
        self.engine.register_provider_profile(
            tenant_id=self.tenant_id,
            provider_id="p_broken",
            provider_name="Broken Acquirer",
            supported_methods=["WECHAT"],
            supported_currencies=["CNY"],
            fee_basis_points=10,
            fixed_fee_minor=10,
        )
        self.engine.update_provider_health(self.tenant_id, "p_broken", "CIRCUIT_BROKEN")

        with self.assertRaises(ValidationError) as ctx:
            self.engine.route_transaction(
                tenant_id=self.tenant_id,
                payment_intent_id="pi_cb_001",
                amount_minor=5000,
                currency="CNY",
                payment_method="WECHAT",
            )
        self.assertIn("no eligible payment provider found", str(ctx.exception))

    def test_e4_concurrent_routing_decisions_durable(self) -> None:
        """E4: Concurrent multi-threaded routing decisions must be atomically and durably logged."""
        self.engine.register_provider_profile(
            tenant_id=self.tenant_id,
            provider_id="p_shared",
            provider_name="Shared Acquirer",
            supported_methods=["ALIPAY"],
            supported_currencies=["CNY"],
            fee_basis_points=25,
            fixed_fee_minor=15,
        )

        successes = 0
        def _route_worker(idx: int) -> bool:
            try:
                res = self.engine.route_transaction(
                    tenant_id=self.tenant_id,
                    payment_intent_id=f"pi_conc_route_{idx}",
                    amount_minor=1000 + idx * 100,
                    currency="CNY",
                    payment_method="ALIPAY",
                )
                return bool(res["decision_id"])
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_route_worker, i) for i in range(10)]
            for f in concurrent.futures.as_completed(futures):
                if f.result():
                    successes += 1

        self.assertEqual(successes, 10)
        with self.store.connect() as conn:
            cnt = conn.execute(
                "SELECT COUNT(*) FROM smart_routing_decision_log WHERE tenant_id = ?",
                (self.tenant_id,),
            ).fetchone()[0]
        self.assertEqual(cnt, 10)


class TestTieredPricingEngineE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_pricing.db"
        self.store = DurableStore(self.db_path)
        self.engine = TieredPricingEngine(self.store)
        self.tenant_id = "tenant_pricing_corp"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_default_blended_fee_calculation(self) -> None:
        """E3: Fallback to default blended contract (60 bps + 30 minor fixed) when unconfigured."""
        calc = self.engine.calculate_merchant_fee(
            tenant_id=self.tenant_id,
            transaction_id="txn_blended_01",
            amount_minor=100_000,  # 1000.00 CNY
            currency="CNY",
        )
        # Expected fee: (100,000 * 60) // 10000 + 30 = 600 + 30 = 630 minor
        self.assertEqual(calc["pricing_model"], "BLENDED")
        self.assertEqual(calc["gross_fee_minor"], 630)
        self.assertEqual(calc["net_margin_minor"], 630)
        self.assertEqual(calc["interchange_cost_minor"], 0)

    def test_e3_tiered_volume_discount_pricing(self) -> None:
        """E3: Volume tiers discount transaction fees according to monthly accumulated threshold."""
        tiers = [
            {"up_to_minor": 1_000_000, "fee_bps": 50},   # Up to 10k: 50 bps
            {"up_to_minor": 5_000_000, "fee_bps": 35},   # Up to 50k: 35 bps
            {"up_to_minor": None, "fee_bps": 20},        # Above 50k: 20 bps
        ]
        self.engine.configure_fee_schedule(
            tenant_id=self.tenant_id,
            pricing_model="TIERED_VOLUME",
            tiers=tiers,
            fixed_fee_minor=10,
        )

        # Monthly volume = 500,000 (Tier 1: 50 bps)
        # Txn amount = 20,000 -> (20,000 * 50)//10000 + 10 = 100 + 10 = 110 minor
        c1 = self.engine.calculate_merchant_fee(
            tenant_id=self.tenant_id,
            transaction_id="txn_t1",
            amount_minor=20_000,
            monthly_accumulated_volume_minor=500_000,
        )
        self.assertEqual(c1["gross_fee_minor"], 110)

        # Monthly volume = 3,000,000 (Tier 2: 35 bps)
        # Txn amount = 20,000 -> (20,000 * 35)//10000 + 10 = 70 + 10 = 80 minor
        c2 = self.engine.calculate_merchant_fee(
            tenant_id=self.tenant_id,
            transaction_id="txn_t2",
            amount_minor=20_000,
            monthly_accumulated_volume_minor=3_000_000,
        )
        self.assertEqual(c2["gross_fee_minor"], 80)

        # Monthly volume = 10,000,000 (Tier 3: 20 bps)
        # Txn amount = 20,000 -> (20,000 * 20)//10000 + 10 = 40 + 10 = 50 minor
        c3 = self.engine.calculate_merchant_fee(
            tenant_id=self.tenant_id,
            transaction_id="txn_t3",
            amount_minor=20_000,
            monthly_accumulated_volume_minor=10_000_000,
        )
        self.assertEqual(c3["gross_fee_minor"], 50)

    def test_e3_interchange_plus_plus_unbundled_pricing(self) -> None:
        """E3: IC++ unbundled model details Interchange (140 bps) + Scheme (15 bps) + Acquirer markup."""
        self.engine.configure_fee_schedule(
            tenant_id=self.tenant_id,
            pricing_model="INTERCHANGE_PLUS_PLUS",
            markup_basis_points=25,
            fixed_fee_minor=15,
        )

        # Txn amount = 100,000 minor ($1000.00)
        # IC: (100000 * 140) // 10000 = 1400 minor
        # Scheme: (100000 * 15) // 10000 = 150 minor
        # Acquirer Markup: (100000 * 25) // 10000 + 15 = 250 + 15 = 265 minor
        # Gross Fee: 1400 + 150 + 265 = 1815 minor
        # Net Margin: 265 minor
        c = self.engine.calculate_merchant_fee(
            tenant_id=self.tenant_id,
            transaction_id="txn_ic_001",
            amount_minor=100_000,
        )
        self.assertEqual(c["pricing_model"], "INTERCHANGE_PLUS_PLUS")
        self.assertEqual(c["interchange_cost_minor"], 1400)
        self.assertEqual(c["scheme_assessment_minor"], 150)
        self.assertEqual(c["net_margin_minor"], 265)
        self.assertEqual(c["gross_fee_minor"], 1815)

    def test_e4_concurrent_fee_journaling(self) -> None:
        """E4: Concurrent fee calculations must atomically journal fee entries."""
        self.engine.configure_fee_schedule(
            tenant_id=self.tenant_id,
            pricing_model="BLENDED",
            markup_basis_points=40,
            fixed_fee_minor=20,
        )

        def _calc_worker(idx: int) -> bool:
            try:
                res = self.engine.calculate_merchant_fee(
                    tenant_id=self.tenant_id,
                    transaction_id=f"txn_conc_fee_{idx}",
                    amount_minor=50_000,
                )
                return bool(res["journal_id"])
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_calc_worker, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(sum(1 for r in results if r), 10)
        with self.store.connect() as conn:
            cnt = conn.execute(
                "SELECT COUNT(*) FROM merchant_fee_journal WHERE tenant_id = ?",
                (self.tenant_id,),
            ).fetchone()[0]
        self.assertEqual(cnt, 10)


class TestEnterpriseWebhookDispatcherE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_webhook.db"
        self.store = DurableStore(self.db_path)
        self.dispatcher = EnterpriseWebhookDispatcher(self.store)
        self.tenant_id = "tenant_webhook_corp"
        self.secret = "super_secure_webhook_secret_key_12345"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_endpoint_registration_and_validation(self) -> None:
        """E3: Validate webhook endpoint URL, secret key length, and subscribed topics."""
        ep = self.dispatcher.register_endpoint(
            tenant_id=self.tenant_id,
            endpoint_id="ep_payments",
            url="https://api.merchant.com/webhook/v1",
            secret_key=self.secret,
            subscribed_events=["payment_intent.succeeded", "refund.created"],
        )
        self.assertEqual(ep["endpoint_id"], "ep_payments")
        self.assertEqual(ep["status"], "ACTIVE")

        # Short secret (<16 chars) fails closed
        with self.assertRaises(ValidationError):
            self.dispatcher.register_endpoint(
                tenant_id=self.tenant_id,
                endpoint_id="ep_bad",
                url="https://api.merchant.com/wh",
                secret_key="short",
                subscribed_events=["*"],
            )

        # Invalid URL schema fails closed
        with self.assertRaises(ValidationError):
            self.dispatcher.register_endpoint(
                tenant_id=self.tenant_id,
                endpoint_id="ep_bad2",
                url="ftp://api.merchant.com/wh",
                secret_key=self.secret,
                subscribed_events=["*"],
            )

    def test_e3_signed_webhook_dispatch_and_delivery(self) -> None:
        """E3: Signed webhook payload formatting, topic matching, and signature verification."""
        self.dispatcher.register_endpoint(
            tenant_id=self.tenant_id,
            endpoint_id="ep_card",
            url="https://api.merchant.com/card_events",
            secret_key=self.secret,
            subscribed_events=["payment_intent.succeeded"],
        )
        self.dispatcher.register_endpoint(
            tenant_id=self.tenant_id,
            endpoint_id="ep_other",
            url="https://api.merchant.com/other_events",
            secret_key=self.secret,
            subscribed_events=["dispute.created"],
        )

        payload = {"paymentIntentId": "pi_wh_100", "amountMinor": 25000, "status": "SUCCEEDED"}
        events = self.dispatcher.dispatch_event(
            tenant_id=self.tenant_id,
            event_type="payment_intent.succeeded",
            payload=payload,
            simulate_http_status=200,
        )

        # Only ep_card matches
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["endpoint_id"], "ep_card")
        self.assertEqual(events[0]["status"], "DELIVERED")

        # Signature header verification
        sig_header = events[0]["signature_header"]
        payload_canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.assertTrue(verify_webhook_signature(sig_header, self.secret, payload_canonical))

        # Tampered payload fails verification
        tampered = json.dumps({"paymentIntentId": "pi_wh_100", "amountMinor": 99999}, sort_keys=True, separators=(",", ":"))
        self.assertFalse(verify_webhook_signature(sig_header, self.secret, tampered))

    def test_e3_exponential_retry_and_dead_letter_replay(self) -> None:
        """E3: Failure retry progression, Dead-Letter Queue (DLQ) exhaustion, and manual replay."""
        self.dispatcher.register_endpoint(
            tenant_id=self.tenant_id,
            endpoint_id="ep_flake",
            url="https://api.flake.com/webhook",
            secret_key=self.secret,
            subscribed_events=["*"],
        )

        events = self.dispatcher.dispatch_event(
            tenant_id=self.tenant_id,
            event_type="order.settled",
            payload={"orderId": "ord_999"},
            simulate_http_status=500,  # Fails on dispatch
        )
        evt_id = events[0]["event_id"]
        self.assertEqual(events[0]["status"], "RETRYING")

        # Attempt 2, 3, 4 (still retrying with exponential backoff)
        r2 = self.dispatcher.process_retry_attempt(self.tenant_id, evt_id, simulate_http_status=500)
        self.assertEqual(r2["status"], "RETRYING")
        self.assertEqual(r2["attempts"], 2)

        r3 = self.dispatcher.process_retry_attempt(self.tenant_id, evt_id, simulate_http_status=500)
        self.assertEqual(r3["status"], "RETRYING")

        r4 = self.dispatcher.process_retry_attempt(self.tenant_id, evt_id, simulate_http_status=500)
        self.assertEqual(r4["status"], "RETRYING")

        # Attempt 5 (max attempts reached -> transitions to DEAD_LETTER and routes to DLQ)
        r5 = self.dispatcher.process_retry_attempt(self.tenant_id, evt_id, simulate_http_status=500)
        self.assertEqual(r5["status"], "DEAD_LETTER")
        dlq_id = r5["dead_letter_id"]
        self.assertTrue(dlq_id.startswith("dlq_"))

        # Replay failed: simulate 503
        f_rep = self.dispatcher.replay_dead_letter(self.tenant_id, dlq_id, simulate_http_status=503)
        self.assertEqual(f_rep["status"], "REPLAY_FAILED")

        # Replay succeeded: simulate 200
        s_rep = self.dispatcher.replay_dead_letter(self.tenant_id, dlq_id, simulate_http_status=200)
        self.assertEqual(s_rep["status"], "REPLAY_SUCCEEDED")

        # Check queue status updated to DELIVERED
        with self.store.connect() as conn:
            row = conn.execute("SELECT status FROM webhook_event_queue WHERE event_id = ?", (evt_id,)).fetchone()
            self.assertEqual(row["status"], "DELIVERED")

    def test_e4_signature_freshness_and_tampering_security(self) -> None:
        """E4: Replay attack prevention: signatures with expired timestamp (>300s) are rejected."""
        payload_json = '{"event":"test"}'
        now_ts = int(time.time())

        # Expired signature (400 seconds ago)
        old_header = sign_webhook_payload(self.secret, now_ts - 400, payload_json)
        self.assertFalse(verify_webhook_signature(old_header, self.secret, payload_json, tolerance_seconds=300))

        # Fresh signature (10 seconds ago)
        fresh_header = sign_webhook_payload(self.secret, now_ts - 10, payload_json)
        self.assertTrue(verify_webhook_signature(fresh_header, self.secret, payload_json, tolerance_seconds=300))

        # Invalid secret
        self.assertFalse(verify_webhook_signature(fresh_header, "wrong_secret_key_9999", payload_json))

    def test_e4_concurrent_webhook_dispatch_and_retry(self) -> None:
        """E4: High concurrency webhook dispatch maintains transactional isolation."""
        self.dispatcher.register_endpoint(
            tenant_id=self.tenant_id,
            endpoint_id="ep_conc",
            url="https://api.conc.com/wh",
            secret_key=self.secret,
            subscribed_events=["*"],
        )

        def _dispatch_worker(idx: int) -> bool:
            try:
                res = self.dispatcher.dispatch_event(
                    tenant_id=self.tenant_id,
                    event_type="test.event",
                    payload={"idx": idx},
                    simulate_http_status=200,
                )
                return len(res) == 1
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_dispatch_worker, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(sum(1 for r in results if r), 10)


class TestMarketplaceEscrowManagerE3E4(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_escrow.db"
        self.store = DurableStore(self.db_path)
        self.manager = MarketplaceEscrowManager(self.store)
        self.tenant_id = "tenant_marketplace_corp"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_e3_create_split_order_conservation_enforcement(self) -> None:
        """E3: Strict mathematical split conservation: sum(splits) + platform_fee == captured_amount."""
        recipients = [
            {"vendor_id": "vendor_camera_shop", "amount_minor": 6_000},
            {"vendor_id": "vendor_lens_store", "amount_minor": 3_500},
        ]
        # Platform fee: 500 minor. Total = 6,000 + 3,500 + 500 = 10,000 minor
        order = self.manager.create_split_order(
            tenant_id=self.tenant_id,
            order_id="ord_split_001",
            captured_amount_minor=10_000,
            currency="CNY",
            platform_fee_minor=500,
            recipients=recipients,
            hold_days=7,
        )
        self.assertEqual(order["order_id"], "ord_split_001")
        self.assertEqual(order["escrow_status"], "HELD")
        self.assertEqual(len(order["recipients"]), 2)

        # Conservation violation: sum = 9,999 (off by 1 cent) -> raises ValidationError
        with self.assertRaises(ValidationError) as ctx:
            self.manager.create_split_order(
                tenant_id=self.tenant_id,
                order_id="ord_split_bad",
                captured_amount_minor=10_000,
                currency="CNY",
                platform_fee_minor=499,
                recipients=recipients,
            )
        self.assertIn("mathematical split conservation violation", str(ctx.exception))

    def test_e3_escrow_hold_and_release(self) -> None:
        """E3: Releasing held escrow unlocks funds to vendor sub-accounts and disallows re-release."""
        recipients = [
            {"vendor_id": "v_1", "amount_minor": 7_000},
            {"vendor_id": "v_2", "amount_minor": 3_000},
        ]
        self.manager.create_split_order(
            tenant_id=self.tenant_id,
            order_id="ord_release_test",
            captured_amount_minor=10_000,
            currency="USD",
            platform_fee_minor=0,
            recipients=recipients,
        )

        # Release escrow
        rel = self.manager.release_escrow(self.tenant_id, "ord_release_test")
        self.assertEqual(rel["escrow_status"], "RELEASED")
        self.assertIsNotNone(rel["released_at"])

        # Check status
        st = self.manager.get_split_order_status(self.tenant_id, "ord_release_test")
        self.assertEqual(st["escrow_status"], "RELEASED")
        for r in st["recipients"]:
            self.assertEqual(r["status"], "RELEASED")
            self.assertEqual(r["settled_amount_minor"], r["allocated_amount_minor"])

        # Cannot release already released order
        with self.assertRaises(ValidationError):
            self.manager.release_escrow(self.tenant_id, "ord_release_test")

    def test_e3_proportional_refund_and_balance_bounds(self) -> None:
        """E3: Partial and full refunds proportionally debit vendor allocations."""
        recipients = [
            {"vendor_id": "v_hotel", "amount_minor": 8_000},
            {"vendor_id": "v_tour", "amount_minor": 2_000},
        ]
        self.manager.create_split_order(
            tenant_id=self.tenant_id,
            order_id="ord_refund_test",
            captured_amount_minor=10_000,
            currency="EUR",
            platform_fee_minor=0,
            recipients=recipients,
        )

        # Refund 4,000 minor (40%)
        # v_hotel portion: (4000 * 8000) // 10000 = 3200
        # v_tour portion: (4000 * 2000) // 10000 = 800
        ref1 = self.manager.refund_split_order(self.tenant_id, "ord_refund_test", 4_000)
        self.assertEqual(ref1["escrow_status"], "PARTIALLY_REFUNDED")
        self.assertEqual(ref1["total_refunded_minor"], 4_000)

        st1 = self.manager.get_split_order_status(self.tenant_id, "ord_refund_test")
        recip_map = {r["vendor_id"]: r for r in st1["recipients"]}
        self.assertEqual(recip_map["v_hotel"]["refunded_amount_minor"], 3200)
        self.assertEqual(recip_map["v_tour"]["refunded_amount_minor"], 800)

        # Refund remaining 6,000 minor
        ref2 = self.manager.refund_split_order(self.tenant_id, "ord_refund_test", 6_000)
        self.assertEqual(ref2["escrow_status"], "REFUNDED")
        self.assertEqual(ref2["total_refunded_minor"], 10_000)

        # Excess refund fails closed
        with self.assertRaises(ValidationError) as ctx:
            self.manager.refund_split_order(self.tenant_id, "ord_refund_test", 1)
        self.assertIn("exceeds remaining refundable balance", str(ctx.exception))

    def test_e4_concurrent_escrow_release_atomic_race(self) -> None:
        """E4: Exactly one concurrent thread can release an escrow order; remaining 9 fail atomically."""
        recipients = [{"vendor_id": "v_race", "amount_minor": 10_000}]
        self.manager.create_split_order(
            tenant_id=self.tenant_id,
            order_id="ord_race_release",
            captured_amount_minor=10_000,
            currency="CNY",
            platform_fee_minor=0,
            recipients=recipients,
        )

        wins = 0
        losses = 0

        def _release_worker() -> bool:
            try:
                self.manager.release_escrow(self.tenant_id, "ord_race_release")
                return True
            except ValidationError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_release_worker) for _ in range(10)]
            for f in concurrent.futures.as_completed(futures):
                if f.result():
                    wins += 1
                else:
                    losses += 1

        self.assertEqual(wins, 1)
        self.assertEqual(losses, 9)

    def test_e4_concurrent_refund_race_conservation(self) -> None:
        """E4: 10 concurrent threads attempt to refund 2,000 each on a 10,000 order; exactly 5 succeed."""
        recipients = [{"vendor_id": "v_race_ref", "amount_minor": 10_000}]
        self.manager.create_split_order(
            tenant_id=self.tenant_id,
            order_id="ord_race_refund",
            captured_amount_minor=10_000,
            currency="CNY",
            platform_fee_minor=0,
            recipients=recipients,
        )

        wins = 0
        losses = 0

        def _refund_worker() -> bool:
            try:
                self.manager.refund_split_order(self.tenant_id, "ord_race_refund", 2_000)
                return True
            except ValidationError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(_refund_worker) for _ in range(10)]
            for f in concurrent.futures.as_completed(futures):
                if f.result():
                    wins += 1
                else:
                    losses += 1

        self.assertEqual(wins, 5)
        self.assertEqual(losses, 5)

        st = self.manager.get_split_order_status(self.tenant_id, "ord_race_refund")
        self.assertEqual(st["refunded_amount_minor"], 10_000)
        self.assertEqual(st["escrow_status"], "REFUNDED")


class TestCliEnterpriseRoutingPricingWebhookEscrow(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_cli_runtime.db"
        self.tenant_id = "tenant_cli_enterprise"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _run_cli(self, *args: str) -> tuple[int, str]:
        cmd = [sys.executable, "tools/runtime/control.py", *args]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.returncode, res.stdout.strip()

    def test_cli_smart_routing_suite(self) -> None:
        """CLI: Verify routing-provider-reg, routing-health-update, and routing-evaluate."""
        # 1. Register provider
        code, out = self._run_cli(
            "routing-provider-reg",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--provider-id", "p_wechat_cli",
            "--provider-name", "WeChat CLI Pay",
            "--methods", "WECHAT,JSAPI",
            "--currencies", "CNY",
            "--fee-bp", "30",
            "--fixed-fee", "20",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        reg = json.loads(out)
        self.assertEqual(reg["provider_id"], "p_wechat_cli")

        # 2. Evaluate route
        code, out = self._run_cli(
            "routing-evaluate",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--payment-intent", "pi_cli_rt_01",
            "--amount-minor", "50000",
            "--currency", "CNY",
            "--method", "WECHAT",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        ev = json.loads(out)
        self.assertEqual(ev["selected_provider_id"], "p_wechat_cli")

        # 3. Update health to CIRCUIT_BROKEN
        code, out = self._run_cli(
            "routing-health-update",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--provider-id", "p_wechat_cli",
            "--status", "CIRCUIT_BROKEN",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        hu = json.loads(out)
        self.assertEqual(hu["health_status"], "CIRCUIT_BROKEN")

    def test_cli_tiered_pricing_suite(self) -> None:
        """CLI: Verify pricing-schedule-set and pricing-fee-calc."""
        tiers_file = Path(self.temp_dir.name) / "tiers.json"
        tiers_file.write_text(json.dumps([
            {"up_to_minor": 100000, "fee_bps": 40},
            {"up_to_minor": None, "fee_bps": 20},
        ]), encoding="utf-8")

        # 1. Set schedule
        code, out = self._run_cli(
            "pricing-schedule-set",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--model", "TIERED_VOLUME",
            "--tiers", str(tiers_file),
            "--fixed-fee", "15",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        sc = json.loads(out)
        self.assertEqual(sc["pricing_model"], "TIERED_VOLUME")

        # 2. Calculate fee
        code, out = self._run_cli(
            "pricing-fee-calc",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--txn-id", "txn_cli_fee_01",
            "--amount-minor", "20000",
            "--monthly-volume", "50000",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        fc = json.loads(out)
        # (20000 * 40)//10000 + 15 = 80 + 15 = 95 minor
        self.assertEqual(fc["gross_fee_minor"], 95)

    def test_cli_webhook_suite(self) -> None:
        """CLI: Verify webhook-endpoint-reg, webhook-dispatch, webhook-verify-sign, and webhook-replay."""
        # 1. Register endpoint
        secret = "very_long_and_secure_cli_secret_key"
        code, out = self._run_cli(
            "webhook-endpoint-reg",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--endpoint-id", "ep_cli_01",
            "--url", "https://api.example.com/hooks",
            "--secret", secret,
            "--events", "payment.captured",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")

        # 2. Dispatch event
        payload_file = Path(self.temp_dir.name) / "payload.json"
        payload_file.write_text(json.dumps({"intentId": "pi_cli_wh"}), encoding="utf-8")

        code, out = self._run_cli(
            "webhook-dispatch",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--event-type", "payment.captured",
            "--payload", str(payload_file),
            "--http-status", "200",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        disp = json.loads(out)
        self.assertEqual(disp["dispatchedCount"], 1)
        sig_header = disp["events"][0]["signature_header"]

        # 3. Verify signature via CLI
        code, out = self._run_cli(
            "webhook-verify-sign",
            "--header", sig_header,
            "--secret", secret,
            "--payload", str(payload_file),
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        self.assertTrue(json.loads(out)["signatureValid"])

    def test_cli_marketplace_escrow_suite(self) -> None:
        """CLI: Verify marketplace-split-create, marketplace-escrow-release, and marketplace-split-refund."""
        recip_file = Path(self.temp_dir.name) / "recipients.json"
        recip_file.write_text(json.dumps([
            {"vendor_id": "v_cli_1", "amount_minor": 8000},
            {"vendor_id": "v_cli_2", "amount_minor": 2000},
        ]), encoding="utf-8")

        # 1. Create split order
        code, out = self._run_cli(
            "marketplace-split-create",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--order-id", "ord_cli_mp_01",
            "--amount-minor", "10000",
            "--platform-fee", "0",
            "--recipients", str(recip_file),
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        sp = json.loads(out)
        self.assertEqual(sp["escrow_status"], "HELD")

        # 2. Release escrow
        code, out = self._run_cli(
            "marketplace-escrow-release",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--order-id", "ord_cli_mp_01",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        rel = json.loads(out)
        self.assertEqual(rel["escrow_status"], "RELEASED")

        # 3. Refund split order
        code, out = self._run_cli(
            "marketplace-split-refund",
            "--database", str(self.db_path),
            "--tenant", self.tenant_id,
            "--order-id", "ord_cli_mp_01",
            "--refund-amount-minor", "3000",
        )
        self.assertEqual(code, 0, f"CLI error: {out}")
        ref = json.loads(out)
        self.assertEqual(ref["escrow_status"], "PARTIALLY_REFUNDED")
        self.assertEqual(ref["total_refunded_minor"], 3000)


if __name__ == "__main__":
    unittest.main()
