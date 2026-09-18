# tools/runtime/elmpay_runtime/card_vault.py
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import re
import uuid
from typing import Any, Dict, Optional

from .common import ValidationError
from .durable import DurableStore


def _validate_luhn(pan: str) -> bool:
    digits = [int(c) for c in pan if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


def _detect_card_brand(pan: str) -> str:
    if pan.startswith("4"):
        return "VISA"
    elif pan.startswith(("51", "52", "53", "54", "55")) or (len(pan) >= 4 and 2221 <= int(pan[:4]) <= 2720):
        return "MASTERCARD"
    elif pan.startswith(("34", "37")):
        return "AMEX"
    elif pan.startswith("62"):
        return "UNIONPAY"
    elif pan.startswith("35"):
        return "JCB"
    elif pan.startswith("6011") or pan.startswith("65"):
        return "DISCOVER"
    else:
        return "VISA"  # Fallback default


class CardVaultManager:
    """PCI DSS v4.0 Zero-Knowledge Tokenization, Card Vault, and Network Token Lifecycle Manager."""

    def __init__(self, store: DurableStore) -> None:
        self.store = store

    def tokenize_card(
        self,
        tenant_id: str,
        customer_id: str,
        raw_pan: str,
        exp_month: int,
        exp_year: int,
        cardholder_name: str,
    ) -> Dict[str, Any]:
        """Validates Luhn, extracts brand, and stores zero-knowledge surrogate & network tokens."""
        clean_pan = re.sub(r"\D", "", raw_pan)
        if not _validate_luhn(clean_pan):
            raise ValidationError("invalid card number: failed Luhn checksum validation")

        if not (1 <= exp_month <= 12):
            raise ValidationError("exp_month must be between 1 and 12")
        if exp_year < 2024:
            raise ValidationError("exp_year must be 2024 or later")
        if not cardholder_name or not cardholder_name.strip():
            raise ValidationError("cardholder_name cannot be empty")

        card_brand = _detect_card_brand(clean_pan)
        bin_first6 = clean_pan[:6]
        last4 = clean_pan[-4:]

        # Fingerprint: HMAC-SHA256 with tenant_id salt
        fingerprint = hmac.new(
            tenant_id.encode("utf-8"),
            clean_pan.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Zero-knowledge encrypted envelope simulation: cryptographic digest without raw PAN storage
        envelope = hashlib.sha256(
            f"ENC-AES256GCM:{tenant_id}:{clean_pan}:{exp_month}:{exp_year}".encode("utf-8")
        ).hexdigest()

        vault_token = f"tok_{uuid.uuid4().hex[:16]}"
        network_token = f"ntok_{uuid.uuid4().hex[:16]}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.store.transaction() as conn:
            # Check if card already vaulted for this customer
            existing = conn.execute(
                "SELECT * FROM card_vault WHERE tenant_id = ? AND customer_id = ? AND fingerprint = ?",
                (tenant_id, customer_id, fingerprint),
            ).fetchone()

            if existing:
                return {
                    "vault_token": existing["vault_token"],
                    "network_token": existing["network_token"],
                    "customer_id": customer_id,
                    "card_brand": existing["card_brand"],
                    "bin_first6": existing["bin_first6"],
                    "last4": existing["last4"],
                    "exp_month": existing["exp_month"],
                    "exp_year": existing["exp_year"],
                    "status": existing["status"],
                    "masked_pan": f"{existing['bin_first6']}******{existing['last4']}",
                }

            conn.execute(
                """
                INSERT INTO card_vault (
                    vault_token, network_token, tenant_id, customer_id,
                    card_brand, bin_first6, last4, exp_month, exp_year,
                    cardholder_name, fingerprint, encrypted_pan_envelope,
                    status, token_requester_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 'TRID_ELMPAY_400', ?, ?)
                """,
                (
                    vault_token, network_token, tenant_id, customer_id,
                    card_brand, bin_first6, last4, exp_month, exp_year,
                    cardholder_name.strip(), fingerprint, envelope,
                    now_iso, now_iso
                ),
            )

        return {
            "vault_token": vault_token,
            "network_token": network_token,
            "customer_id": customer_id,
            "card_brand": card_brand,
            "bin_first6": bin_first6,
            "last4": last4,
            "exp_month": exp_month,
            "exp_year": exp_year,
            "status": "ACTIVE",
            "masked_pan": f"{bin_first6}******{last4}",
        }

    def generate_network_token_cryptogram(self, tenant_id: str, vault_token: str) -> Dict[str, Any]:
        """Generates EMVCo 3DS / Network Token Authorization Cryptogram (TAVV/CAVV)."""
        with self.store.transaction() as conn:
            card = conn.execute(
                "SELECT * FROM card_vault WHERE vault_token = ? AND tenant_id = ?",
                (vault_token, tenant_id),
            ).fetchone()

            if not card:
                raise ValidationError(f"vault token {vault_token} not found")
            if card["status"] != "ACTIVE":
                raise ValidationError(f"card token is not ACTIVE (current: {card['status']})")

            # Generate standard EMVCo token cryptogram (28 bytes Base64)
            raw_cryptogram = hashlib.sha256(
                f"{card['network_token']}:{datetime.datetime.now(datetime.timezone.utc).isoformat()}".encode("utf-8")
            ).digest()[:20]
            cryptogram = base64.b64encode(raw_cryptogram).decode("utf-8")

        return {
            "vault_token": vault_token,
            "network_token": card["network_token"],
            "cryptogram": cryptogram,
            "eci": "05",  # ECI 05: Fully Authenticated Network Token Transaction
            "card_brand": card["card_brand"],
            "last4": card["last4"],
            "exp_month": card["exp_month"],
            "exp_year": card["exp_year"],
        }

    def apply_account_updater_event(
        self,
        tenant_id: str,
        vault_token: str,
        event_type: str,
        new_exp_month: Optional[int] = None,
        new_exp_year: Optional[int] = None,
        new_last4: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Visa Account Updater (VAU) / Mastercard Automatic Billing Updater (ABU) event processor."""
        allowed_events = {"EXPIRY_UPDATE", "CARD_REPLACED", "ACCOUNT_CLOSED", "CONTACT_CARDHOLDER"}
        if event_type not in allowed_events:
            raise ValidationError(f"invalid event_type: {event_type} ({allowed_events})")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        event_id = f"aue_{uuid.uuid4().hex[:12]}"

        with self.store.transaction() as conn:
            card = conn.execute(
                "SELECT * FROM card_vault WHERE vault_token = ? AND tenant_id = ?",
                (vault_token, tenant_id),
            ).fetchone()

            if not card:
                raise ValidationError(f"vault token {vault_token} not found")

            old_exp_month = card["exp_month"]
            old_exp_year = card["exp_year"]
            target_status = card["status"]

            if event_type == "EXPIRY_UPDATE":
                if not new_exp_month or not new_exp_year:
                    raise ValidationError("EXPIRY_UPDATE requires new_exp_month and new_exp_year")
                conn.execute(
                    """
                    UPDATE card_vault
                    SET exp_month = ?, exp_year = ?, updated_at = ?
                    WHERE vault_token = ?
                    """,
                    (new_exp_month, new_exp_year, now_iso, vault_token),
                )
            elif event_type == "CARD_REPLACED":
                if not new_last4 or len(new_last4) != 4:
                    raise ValidationError("CARD_REPLACED requires a valid new_last4 (4 digits)")
                month = new_exp_month or old_exp_month
                year = new_exp_year or old_exp_year
                conn.execute(
                    """
                    UPDATE card_vault
                    SET last4 = ?, exp_month = ?, exp_year = ?, updated_at = ?
                    WHERE vault_token = ?
                    """,
                    (new_last4, month, year, now_iso, vault_token),
                )
            elif event_type == "ACCOUNT_CLOSED":
                target_status = "REVOKED"
                conn.execute(
                    """
                    UPDATE card_vault
                    SET status = 'REVOKED', updated_at = ?
                    WHERE vault_token = ?
                    """,
                    (now_iso, vault_token),
                )

            conn.execute(
                """
                INSERT INTO card_updater_event (
                    event_id, tenant_id, vault_token, event_type,
                    old_exp_month, old_exp_year, new_exp_month, new_exp_year,
                    new_last4, processed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id, tenant_id, vault_token, event_type,
                    old_exp_month, old_exp_year, new_exp_month, new_exp_year,
                    new_last4, now_iso
                ),
            )

        return {
            "event_id": event_id,
            "vault_token": vault_token,
            "event_type": event_type,
            "status": target_status,
            "updated_at": now_iso,
        }

    def purge_expired_tokens(self, tenant_id: str, current_year: int, current_month: int) -> int:
        """PCI DSS Requirement 3: securely marks expired card tokens as EXPIRED."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.store.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE card_vault
                SET status = 'EXPIRED', updated_at = ?
                WHERE tenant_id = ?
                  AND status = 'ACTIVE'
                  AND (exp_year < ? OR (exp_year = ? AND exp_month < ?))
                """,
                (now_iso, tenant_id, current_year, current_year, current_month),
            )
            return cur.rowcount

    def get_vault_token(self, tenant_id: str, vault_token: str) -> Dict[str, Any]:
        with self.store.transaction() as conn:
            card = conn.execute(
                "SELECT * FROM card_vault WHERE vault_token = ? AND tenant_id = ?",
                (vault_token, tenant_id),
            ).fetchone()
            if not card:
                raise ValidationError(f"vault token {vault_token} not found")
        data = dict(card)
        data["masked_pan"] = f"{data['bin_first6']}******{data['last4']}"
        data.pop("encrypted_pan_envelope", None)
        return data
