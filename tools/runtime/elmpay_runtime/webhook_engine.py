# tools/runtime/elmpay_runtime/webhook_engine.py
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, List, Optional

from .common import ValidationError
from .durable import DurableStore


def sign_webhook_payload(secret: str, timestamp: int, payload_json: str) -> str:
    """Signs a webhook payload using standard HMAC-SHA256 timestamped signatures."""
    signed_payload = f"t={timestamp}.{payload_json}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={sig}"


def verify_webhook_signature(
    signature_header: str,
    secret: str,
    payload_json: str,
    tolerance_seconds: int = 300,
) -> bool:
    """Verifies HMAC-SHA256 signature header and enforces timestamp freshness."""
    try:
        parts = dict(kv.split("=", 1) for kv in signature_header.split(","))
        ts_str = parts.get("t")
        expected_sig = parts.get("v1")
        if not ts_str or not expected_sig:
            return False

        ts = int(ts_str)
        now = int(time.time())
        if abs(now - ts) > tolerance_seconds:
            return False

        computed_sig = sign_webhook_payload(secret, ts, payload_json).split(",")[1].split("=")[1]
        return hmac.compare_digest(expected_sig, computed_sig)
    except Exception:
        return False


class EnterpriseWebhookDispatcher:
    """Manages signed webhook event delivery, exponential backoff retries, and Dead-Letter Queue (DLQ) replays."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def register_endpoint(
        self,
        tenant_id: str,
        endpoint_id: str,
        url: str,
        secret_key: str,
        subscribed_events: List[str],
    ) -> Dict[str, Any]:
        """Subscribes an HTTPS webhook endpoint to specific event topics."""
        if not url.startswith("https://") and not url.startswith("http://"):
            raise ValidationError("url must be a valid HTTP or HTTPS endpoint")
        if not secret_key or len(secret_key) < 16:
            raise ValidationError("secret_key must be at least 16 characters")
        if not subscribed_events:
            raise ValidationError("subscribed_events cannot be empty")

        events_csv = ",".join(sorted(set(e.strip() for e in subscribed_events)))
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO webhook_endpoint_subscription (
                    endpoint_id, tenant_id, url, secret_key,
                    subscribed_events_csv, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
                ON CONFLICT(tenant_id, url) DO UPDATE SET
                    secret_key = excluded.secret_key,
                    subscribed_events_csv = excluded.subscribed_events_csv,
                    status = 'ACTIVE'
                """,
                (endpoint_id, tenant_id, url, secret_key, events_csv, now_iso),
            )

        return {
            "endpoint_id": endpoint_id,
            "tenant_id": tenant_id,
            "url": url,
            "subscribed_events": events_csv.split(","),
            "status": "ACTIVE",
        }

    def dispatch_event(
        self,
        tenant_id: str,
        event_type: str,
        payload: Dict[str, Any],
        simulate_http_status: int = 200,
    ) -> List[Dict[str, Any]]:
        """Constructs signed webhook events and dispatches across matching endpoint subscriptions."""
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        now_ts = int(time.time())
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            endpoints = conn.execute(
                "SELECT * FROM webhook_endpoint_subscription WHERE tenant_id = ? AND status = 'ACTIVE'",
                (tenant_id,),
            ).fetchall()

        dispatched: List[Dict[str, Any]] = []

        for ep in endpoints:
            sub_events = [e.strip() for e in ep["subscribed_events_csv"].split(",")]
            if "*" not in sub_events and event_type not in sub_events:
                continue

            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            sig_header = sign_webhook_payload(ep["secret_key"], now_ts, payload_json)

            is_success = (200 <= simulate_http_status < 300)
            status = "DELIVERED" if is_success else "RETRYING"
            attempts = 1
            delivered_at = now_iso if is_success else None
            last_err = None if is_success else f"HTTP {simulate_http_status} server error"
            next_delivery = (now_dt + datetime.timedelta(seconds=15)).isoformat()

            with self.store.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO webhook_event_queue (
                        event_id, tenant_id, endpoint_id, event_type,
                        payload_json, signature_header, status,
                        attempt_count, max_attempts, last_http_status,
                        last_error_message, next_delivery_at, created_at, delivered_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 5, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id, tenant_id, ep["endpoint_id"], event_type,
                        payload_json, sig_header, status,
                        attempts, simulate_http_status, last_err,
                        next_delivery, now_iso, delivered_at
                    ),
                )

            dispatched.append({
                "event_id": event_id,
                "endpoint_id": ep["endpoint_id"],
                "url": ep["url"],
                "event_type": event_type,
                "status": status,
                "signature_header": sig_header,
                "http_status": simulate_http_status,
            })

        return dispatched

    def process_retry_attempt(
        self,
        tenant_id: str,
        event_id: str,
        simulate_http_status: int = 200,
    ) -> Dict[str, Any]:
        """Advances an in-flight retrying webhook event or dead-letters upon exceeding max attempts."""
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_iso = now_dt.isoformat()

        with self.store.transaction() as conn:
            evt = conn.execute(
                "SELECT * FROM webhook_event_queue WHERE event_id = ? AND tenant_id = ?",
                (event_id, tenant_id),
            ).fetchone()

            if not evt:
                raise ValidationError(f"webhook event {event_id} not found")

            new_attempts = evt["attempt_count"] + 1
            is_success = (200 <= simulate_http_status < 300)

            if is_success:
                conn.execute(
                    """
                    UPDATE webhook_event_queue
                    SET status = 'DELIVERED', attempt_count = ?, last_http_status = ?,
                        last_error_message = NULL, delivered_at = ?
                    WHERE event_id = ?
                    """,
                    (new_attempts, simulate_http_status, now_iso, event_id),
                )
                return {"event_id": event_id, "status": "DELIVERED", "attempts": new_attempts}

            # If failed
            if new_attempts >= evt["max_attempts"]:
                conn.execute(
                    """
                    UPDATE webhook_event_queue
                    SET status = 'DEAD_LETTER', attempt_count = ?, last_http_status = ?,
                        last_error_message = ?
                    WHERE event_id = ?
                    """,
                    (new_attempts, simulate_http_status, f"HTTP {simulate_http_status} max attempts exhausted", event_id),
                )
                # Insert into DLQ
                dlq_id = f"dlq_{uuid.uuid4().hex[:12]}"
                conn.execute(
                    """
                    INSERT INTO webhook_dead_letter (
                        dead_letter_id, tenant_id, event_id, endpoint_id,
                        event_type, final_error, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        dlq_id, tenant_id, event_id, evt["endpoint_id"],
                        evt["event_type"], f"Exhausted {new_attempts} attempts (last HTTP {simulate_http_status})", now_iso
                    ),
                )
                return {"event_id": event_id, "status": "DEAD_LETTER", "dead_letter_id": dlq_id, "attempts": new_attempts}

            # Still retrying: schedule exponential backoff
            next_sec = (2 ** new_attempts) * 5
            next_iso = (now_dt + datetime.timedelta(seconds=next_sec)).isoformat()
            conn.execute(
                """
                UPDATE webhook_event_queue
                SET status = 'RETRYING', attempt_count = ?, last_http_status = ?,
                    last_error_message = ?, next_delivery_at = ?
                WHERE event_id = ?
                """,
                (new_attempts, simulate_http_status, f"HTTP {simulate_http_status}", next_iso, event_id),
            )
            return {"event_id": event_id, "status": "RETRYING", "attempts": new_attempts, "next_delivery_at": next_iso}

    def replay_dead_letter(
        self,
        tenant_id: str,
        dead_letter_id: str,
        simulate_http_status: int = 200,
    ) -> Dict[str, Any]:
        """Manually or programmatically redelivers an un-deliverable dead-letter webhook event."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            dlq = conn.execute(
                "SELECT * FROM webhook_dead_letter WHERE dead_letter_id = ? AND tenant_id = ?",
                (dead_letter_id, tenant_id),
            ).fetchone()

            if not dlq:
                raise ValidationError(f"dead-letter record {dead_letter_id} not found")

            if 200 <= simulate_http_status < 300:
                conn.execute(
                    "UPDATE webhook_dead_letter SET replayed_at = ? WHERE dead_letter_id = ?",
                    (now_iso, dead_letter_id),
                )
                conn.execute(
                    """
                    UPDATE webhook_event_queue
                    SET status = 'DELIVERED', last_http_status = ?, delivered_at = ?
                    WHERE event_id = ?
                    """,
                    (simulate_http_status, now_iso, dlq["event_id"]),
                )
                return {"dead_letter_id": dead_letter_id, "status": "REPLAY_SUCCEEDED", "replayed_at": now_iso}
            else:
                return {"dead_letter_id": dead_letter_id, "status": "REPLAY_FAILED", "http_status": simulate_http_status}
