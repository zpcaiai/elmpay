# tools/runtime/elmpay_runtime/aml_sanctions.py
from __future__ import annotations

import datetime
import json
import re
import uuid
from typing import Any, Dict, List, Optional

from .common import ValidationError
from .durable import DurableStore


class AmlSanctionsEngine:
    """Sanctions watchlist screening, PEP detection, AML large transaction reporting, and structuring anomaly detection."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def add_watchlist_entry(
        self,
        list_source: str,
        entity_name: str,
        entity_type: str = "ORGANIZATION",
        country_iso: str = "CN",
        aliases: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Adds or updates a designated entity on an official sanctions watchlist (OFAC, UN, EU, MOFCOM)."""
        list_source = list_source.strip().upper()
        entity_type = entity_type.strip().upper()
        if list_source not in ("OFAC_SDN", "UN_CONSOLIDATED", "EU_SANCTIONS", "MOFCOM_CHINA"):
            raise ValidationError(f"invalid list_source: {list_source}")
        if entity_type not in ("INDIVIDUAL", "ORGANIZATION", "VESSEL"):
            raise ValidationError(f"invalid entity_type: {entity_type}")
        if not entity_name or not entity_name.strip():
            raise ValidationError("entity_name cannot be empty")

        entry_id = f"wle_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        aliases_csv = ",".join(sorted(set(a.strip() for a in (aliases or []) if a.strip())))

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO aml_sanctions_watchlist (
                    entry_id, list_source, entity_name, entity_type,
                    country_iso, aliases_csv, added_at, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (entry_id, list_source, entity_name.strip(), entity_type, country_iso.strip().upper(), aliases_csv, now_iso),
            )

        return {
            "entry_id": entry_id,
            "list_source": list_source,
            "entity_name": entity_name.strip(),
            "entity_type": entity_type,
            "country_iso": country_iso.strip().upper(),
            "aliases": aliases_csv.split(",") if aliases_csv else [],
        }

    def screen_entity(
        self,
        tenant_id: str,
        entity_name: str,
        screening_type: str = "SANCTIONS",
    ) -> Dict[str, Any]:
        """Screens customer or counterparty against active global sanctions lists using tokenized matching."""
        if not entity_name or not entity_name.strip():
            raise ValidationError("entity_name cannot be empty")
        screening_type = screening_type.strip().upper()
        if screening_type not in ("SANCTIONS", "PEP", "ADVERSE_MEDIA"):
            raise ValidationError(f"invalid screening_type: {screening_type}")

        norm_query = re.sub(r"[^\w\s]", "", entity_name.strip().upper())
        query_tokens = set(norm_query.split())

        with self.store.transaction() as conn:
            entries = conn.execute(
                "SELECT * FROM aml_sanctions_watchlist WHERE is_active = 1",
            ).fetchall()

        best_confidence = 0
        matched_entry_id = None

        for e in entries:
            target_name = e["entity_name"].strip().upper()
            norm_target = re.sub(r"[^\w\s]", "", target_name)

            # Exact match
            if norm_query == norm_target:
                best_confidence = 100
                matched_entry_id = e["entry_id"]
                break

            # Alias match
            aliases = [a.strip().upper() for a in (e["aliases_csv"] or "").split(",") if a.strip()]
            if any(norm_query == re.sub(r"[^\w\s]", "", a) for a in aliases):
                best_confidence = 100
                matched_entry_id = e["entry_id"]
                break

            # Token overlap fuzzy confidence
            target_tokens = set(norm_target.split())
            if query_tokens and target_tokens:
                overlap = query_tokens.intersection(target_tokens)
                containment = len(overlap) / len(query_tokens)
                dice = (2 * len(overlap)) / (len(query_tokens) + len(target_tokens))
                confidence = int(max(containment, dice) * 100)
                if confidence > best_confidence:
                    best_confidence = confidence
                    matched_entry_id = e["entry_id"]

        if best_confidence >= 95:
            decision = "CONFIRMED_BLOCK"
        elif best_confidence >= 50:
            decision = "POTENTIAL_MATCH"
        else:
            decision = "CLEAR"
            matched_entry_id = None

        screening_id = f"scr_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO aml_screening_log (
                    screening_id, tenant_id, entity_name, screening_type,
                    match_confidence, matched_entry_id, decision, screened_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    screening_id, tenant_id, entity_name, screening_type,
                    best_confidence, matched_entry_id, decision, now_iso
                ),
            )

        return {
            "screening_id": screening_id,
            "tenant_id": tenant_id,
            "entity_name": entity_name,
            "screening_type": screening_type,
            "decision": decision,
            "match_confidence": best_confidence,
            "matched_entry_id": matched_entry_id,
            "screened_at": now_iso,
        }

    def evaluate_large_transaction(
        self,
        tenant_id: str,
        transaction_id: str,
        amount_minor: int,
        customer_name: str,
        currency: str = "CNY",
        threshold_minor: int = 5_000_000,  # 50,000.00 CNY / $50,000 equivalent
    ) -> Dict[str, Any]:
        """Evaluates transaction against AML large transaction reporting thresholds."""
        if amount_minor <= 0:
            raise ValidationError("amount_minor must be strictly positive")

        currency = currency.strip().upper()
        is_reportable = amount_minor >= threshold_minor
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        report_id = None
        if is_reportable:
            report_id = f"ltr_{uuid.uuid4().hex[:12]}"
            with self.store.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO aml_large_transaction_report (
                        report_id, tenant_id, transaction_id, amount_minor,
                        currency, customer_name, threshold_minor, report_status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'RECORDED', ?)
                    """,
                    (
                        report_id, tenant_id, transaction_id, amount_minor,
                        currency, customer_name, threshold_minor, now_iso
                    ),
                )

        return {
            "transaction_id": transaction_id,
            "tenant_id": tenant_id,
            "amount_minor": amount_minor,
            "threshold_minor": threshold_minor,
            "is_reportable": is_reportable,
            "report_id": report_id,
            "report_status": "RECORDED" if is_reportable else "EXEMPT",
        }

    def detect_structuring_activity(
        self,
        tenant_id: str,
        customer_id: str,
        transactions: List[Dict[str, Any]],
        threshold_minor: int = 5_000_000,
    ) -> Dict[str, Any]:
        """Detects structuring (smurfing) patterns designed to evade large transaction reporting limits."""
        if not customer_id or not customer_id.strip():
            raise ValidationError("customer_id cannot be empty")

        # Structuring criterion: multiple transactions within [0.80 * threshold, threshold)
        lower_bound = int(threshold_minor * 0.80)
        suspicious_txns = [
            t for t in transactions
            if lower_bound <= int(t.get("amount_minor", 0)) < threshold_minor
        ]

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        is_suspicious = len(suspicious_txns) >= 3

        sar_id = None
        if is_suspicious:
            sar_id = f"sar_{uuid.uuid4().hex[:12]}"
            details = {
                "flagged_tx_count": len(suspicious_txns),
                "threshold_minor": threshold_minor,
                "lower_bound_minor": lower_bound,
                "tx_ids": [t.get("transaction_id") for t in suspicious_txns],
            }
            with self.store.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO aml_suspicious_activity_log (
                        sar_id, tenant_id, customer_id, indicator,
                        details_json, flagged_at, status
                    ) VALUES (?, ?, ?, 'STRUCTURING_SMURFING', ?, ?, 'FLAGGED')
                    """,
                    (sar_id, tenant_id, customer_id, json.dumps(details), now_iso),
                )

        return {
            "customer_id": customer_id,
            "tenant_id": tenant_id,
            "is_suspicious": is_suspicious,
            "sar_id": sar_id,
            "indicator": "STRUCTURING_SMURFING" if is_suspicious else "NONE",
            "matching_transactions_count": len(suspicious_txns),
        }
