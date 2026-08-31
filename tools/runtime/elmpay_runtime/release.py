from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Mapping

from .attestation import NonceStore, nonce_store_from_trust, verify_dsse_record
from .common import (
    GateReport,
    ValidationError,
    parse_instant,
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from .kubernetes import IMAGE_PATTERN


DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")


def release_binding(manifest: Mapping[str, Any]) -> str:
    images = require_mapping(manifest.get("images"), "manifest.images")
    return sha256_json(
        {
            "releaseId": require_text(manifest.get("releaseId"), "releaseId"),
            "commitSha": require_text(manifest.get("commitSha"), "commitSha"),
            "artifactDigest": require_text(
                manifest.get("artifactDigest"), "artifactDigest"
            ),
            "productImageManifestDigest": require_text(
                manifest.get("productImageManifestDigest"), "productImageManifestDigest"
            ),
            "imageAdmissionPolicyDigest": require_text(
                manifest.get("imageAdmissionPolicyDigest"), "imageAdmissionPolicyDigest"
            ),
            "productImageIndexDigest": require_text(
                manifest.get("productImageIndexDigest"), "productImageIndexDigest"
            ),
            "images": dict(sorted(images.items())),
        }
    )


def sign_record(record: Mapping[str, Any], secret: str) -> str:
    """Refuse the retired symmetric attestation format.

    Kept as a hard-failing compatibility symbol so an older issuer cannot
    silently manufacture an "independent" review with a verifier-held secret.
    Use :func:`elmpay_runtime.attestation.attach_dsse` with an external Ed25519
    private key instead.
    """

    del record, secret
    raise ValidationError("symmetric HMAC attestations are disabled; Ed25519 DSSE is required")


def verify_release(
    manifest: Mapping[str, Any],
    gate_policy: Mapping[str, Any],
    trust: Mapping[str, Any],
    *,
    now: datetime | None = None,
    environment: Mapping[str, str] | None = None,
) -> GateReport:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    del environment
    reasons: list[str] = []
    checks: list[str] = []
    try:
        binding = release_binding(manifest)
    except ValidationError as exc:
        return GateReport.from_reasons([f"manifest_invalid:{exc}"])

    commit = manifest.get("commitSha")
    artifact = manifest.get("artifactDigest")
    if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
        reasons.append("commit_sha_invalid")
    if not isinstance(artifact, str) or not DIGEST_PATTERN.fullmatch(artifact):
        reasons.append("artifact_digest_invalid")
    images = require_mapping(manifest.get("images"), "images")
    for name, image in images.items():
        if not isinstance(name, str) or not IMAGE_PATTERN.fullmatch(str(image)):
            reasons.append(f"image_digest_invalid:{name}")
    required_images = gate_policy.get("requiredProductImages")
    if not isinstance(required_images, list) or not required_images \
            or any(not isinstance(name, str) or not name for name in required_images) \
            or len(set(required_images)) != len(required_images):
        reasons.append("gate_policy_invalid:requiredProductImages")
    elif set(images) != set(required_images):
        reasons.append("product_image_inventory_mismatch")
    for manifest_field, policy_field in (
        ("productImageManifestDigest", "productImageManifestDigest"),
        ("imageAdmissionPolicyDigest", "imageAdmissionPolicyDigest"),
    ):
        value = manifest.get(manifest_field)
        expected = gate_policy.get(policy_field)
        if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
            reasons.append(f"{manifest_field}_invalid")
        elif not isinstance(expected, str) or DIGEST_PATTERN.fullmatch(expected) is None:
            reasons.append(f"gate_policy_invalid:{policy_field}")
        elif value != expected:
            reasons.append(f"{manifest_field}_mismatch")
    product_index = manifest.get("productImageIndexDigest")
    if gate_policy.get("productImageIndexRequired") is not True:
        reasons.append("gate_policy_invalid:productImageIndexRequired")
    if not isinstance(product_index, str) or DIGEST_PATTERN.fullmatch(product_index) is None:
        reasons.append("productImageIndexDigest_invalid")
    try:
        expires_at = parse_instant(manifest.get("expiresAt"), "expiresAt")
        generated_at = parse_instant(manifest.get("generatedAt"), "generatedAt")
        if expires_at <= current:
            reasons.append("manifest_expired")
        if generated_at > current + timedelta(minutes=5):
            reasons.append("manifest_generated_in_future")
        if expires_at <= generated_at:
            reasons.append("manifest_expiry_not_after_generation")
    except ValidationError as exc:
        reasons.append(f"manifest_time_invalid:{exc}")

    require_mapping(trust.get("keys"), "trust.keys")
    try:
        nonce_store = nonce_store_from_trust(trust)
    except ValidationError as exc:
        return GateReport.from_reasons([f"replay_protection_unavailable:{exc}"])
    maximum_age = gate_policy.get("maximumApprovalAgeHours")
    if not isinstance(maximum_age, int) or maximum_age <= 0:
        return GateReport.from_reasons(["gate_policy_invalid:maximumApprovalAgeHours"])
    required_roles = set(require_list(gate_policy.get("requiredApprovalRoles"), "requiredApprovalRoles"))
    approvals = require_list(manifest.get("approvals"), "approvals")
    approved_roles: set[str] = set()
    approved_actors: set[str] = set()
    for index, raw in enumerate(approvals):
        approval = require_mapping(raw, f"approval[{index}]")
        prefix = f"approval[{index}]"
        valid, detail = _verify_signed_record(approval, trust, binding, current, nonce_store)
        if not valid:
            reasons.append(f"{prefix}:{detail}")
            continue
        actor = require_text(approval.get("actor"), f"{prefix}.actor")
        role = require_text(approval.get("role"), f"{prefix}.role")
        if approval.get("decision") != "APPROVE":
            reasons.append(f"{prefix}:decision_not_approve")
            continue
        try:
            signed_at = parse_instant(approval.get("signedAt"), f"{prefix}.signedAt")
            if signed_at > current + timedelta(minutes=5):
                reasons.append(f"{prefix}:signed_in_future")
                continue
            if current - signed_at > timedelta(hours=maximum_age):
                reasons.append(f"{prefix}:approval_stale")
                continue
        except ValidationError as exc:
            reasons.append(f"{prefix}:{exc}")
            continue
        approved_roles.add(role)
        approved_actors.add(actor)
        checks.append(f"approval:{role}:{actor}")
    for role in sorted(required_roles - approved_roles):
        reasons.append(f"missing_approval_role:{role}")
    minimum = gate_policy.get("minimumDistinctApprovers")
    if not isinstance(minimum, int) or len(approved_actors) < minimum:
        reasons.append("insufficient_distinct_approvers")

    required_evidence = set(
        require_list(gate_policy.get("requiredEvidence"), "requiredEvidence")
    )
    evidence_items = require_list(manifest.get("evidence"), "evidence")
    verified_categories: set[str] = set()
    evidence_verifiers: set[str] = set()
    for index, raw in enumerate(evidence_items):
        evidence = require_mapping(raw, f"evidence[{index}]")
        prefix = f"evidence[{index}]"
        valid, detail = _verify_signed_record(evidence, trust, binding, current, nonce_store)
        if not valid:
            reasons.append(f"{prefix}:{detail}")
            continue
        category = require_text(evidence.get("category"), f"{prefix}.category")
        verifier = require_text(evidence.get("verifier"), f"{prefix}.verifier")
        if category in verified_categories:
            reasons.append(f"duplicate_evidence_category:{category}")
            continue
        if evidence.get("status") != "VERIFIED":
            reasons.append(f"{prefix}:status_not_verified")
            continue
        digest = evidence.get("evidenceDigest")
        if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
            reasons.append(f"{prefix}:evidence_digest_invalid")
            continue
        envelope = require_mapping(evidence.get("dsse"), f"{prefix}.dsse")
        signatures = require_list(envelope.get("signatures"), f"{prefix}.dsse.signatures")
        key_id = require_text(require_mapping(signatures[0], "signature").get("keyid"), "signature.keyid")
        key = require_mapping(trust["keys"][key_id], "trust key")
        if gate_policy.get("evidenceMustBeIndependent") is True and key.get("independent") is not True:
            reasons.append(f"{prefix}:verifier_not_independent")
            continue
        try:
            observed_at = parse_instant(evidence.get("observedAt"), f"{prefix}.observedAt")
            evidence_expires = parse_instant(evidence.get("expiresAt"), f"{prefix}.expiresAt")
            if observed_at > current + timedelta(minutes=5):
                reasons.append(f"{prefix}:observed_in_future")
                continue
            if evidence_expires <= current or evidence_expires <= observed_at:
                reasons.append(f"{prefix}:evidence_expired")
                continue
        except ValidationError as exc:
            reasons.append(f"{prefix}:{exc}")
            continue
        verified_categories.add(category)
        evidence_verifiers.add(verifier)
        checks.append(f"evidence:{category}:{verifier}")
    for category in sorted(required_evidence - verified_categories):
        reasons.append(f"missing_evidence:{category}")
    if approved_actors & evidence_verifiers:
        reasons.append("approval_and_evidence_roles_not_independent")
    return GateReport.from_reasons(reasons, checks)


def _verify_signed_record(
    record: Mapping[str, Any],
    trust: Mapping[str, Any],
    binding: str,
    current: datetime,
    nonce_store: NonceStore,
) -> tuple[bool, str]:
    try:
        verify_dsse_record(
            record,
            trust,
            binding,
            now=current,
            nonce_store=nonce_store,
        )
        return True, "verified"
    except ValidationError as exc:
        return False, str(exc)
