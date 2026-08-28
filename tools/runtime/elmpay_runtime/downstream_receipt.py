"""Cryptographically bind privileged mutations to downstream-owned receipts.

The control-plane caller is never allowed to assert that a mutation succeeded.
It must present an Ed25519 DSSE receipt issued by the configured downstream
trust root and bound to the exact operation inputs.  Verification is replay
protected by the durable nonce database declared in that trust document.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from .attestation import VerifiedSigner, verify_dsse_record
from .common import ValidationError, require_mapping, require_text, sha256_json


def receipt_binding(receipt_type: str, fields: Mapping[str, Any]) -> str:
    """Return the canonical binding digest a downstream signer must use."""

    kind = require_text(receipt_type, "receipt_type")
    values = require_mapping(dict(fields), "receipt fields")
    return sha256_json({"receiptType": kind, "fields": dict(values)})


def verify_downstream_receipt(
    raw_receipt: Mapping[str, Any],
    trust: Mapping[str, Any],
    *,
    receipt_type: str,
    outcome: str,
    fields: Mapping[str, Any],
    required_role: str,
    require_independent: bool = False,
    now: datetime | None = None,
) -> tuple[str, VerifiedSigner]:
    """Verify one exact, downstream-issued mutation receipt.

    The returned digest is safe to persist as the immutable receipt reference;
    the caller need not retain potentially sensitive downstream response data.
    """

    receipt = require_mapping(raw_receipt, "downstream receipt")
    expected_fields = dict(require_mapping(dict(fields), "receipt fields"))
    if receipt.get("receiptType") != receipt_type:
        raise ValidationError("downstream receipt type mismatch")
    if receipt.get("outcome") != outcome:
        raise ValidationError("downstream receipt outcome mismatch")
    if receipt.get("fields") != expected_fields:
        raise ValidationError("downstream receipt fields mismatch")
    require_text(receipt.get("receiptId"), "downstream receipt id")
    binding = receipt_binding(receipt_type, expected_fields)
    signer = verify_dsse_record(receipt, trust, binding, now=now)
    if signer.role != required_role:
        raise ValidationError("downstream receipt signer role mismatch")
    if require_independent and not signer.independent:
        raise ValidationError("downstream receipt signer is not independent")
    return sha256_json(receipt), signer
