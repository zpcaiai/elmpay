from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
from typing import Any, Mapping

from .common import (
    GateReport,
    ValidationError,
    canonical_json,
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
            "images": dict(sorted(images.items())),
        }
    )


def sign_record(record: Mapping[str, Any], secret: str) -> str:
    """Create a testable HMAC envelope; production secrets stay outside the repo."""
    if len(secret) < 32:
        raise ValidationError("signing secret must contain at least 32 characters")
    unsigned = {key: value for key, value in record.items() if key != "signature"}
    return hmac.new(secret.encode("utf-8"), canonical_json(unsigned), hashlib.sha256).hexdigest()


def verify_release(
    manifest: Mapping[str, Any],
    gate_policy: Mapping[str, Any],
    trust: Mapping[str, Any],
    *,
    now: datetime | None = None,
    environment: Mapping[str, str] | None = None,
) -> GateReport:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    env = environment if environment is not None else os.environ
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
    for name, image in require_mapping(manifest.get("images"), "images").items():
        if not isinstance(name, str) or not IMAGE_PATTERN.fullmatch(str(image)):
            reasons.append(f"image_digest_invalid:{name}")
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

    trust_keys = require_mapping(trust.get("keys"), "trust.keys")
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
        valid, detail = _verify_signed_record(approval, trust_keys, env, binding)
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
        valid, detail = _verify_signed_record(evidence, trust_keys, env, binding)
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
        key = require_mapping(trust_keys[evidence["keyId"]], "trust key")
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
    trust_keys: Mapping[str, Any],
    environment: Mapping[str, str],
    binding: str,
) -> tuple[bool, str]:
    key_id = record.get("keyId")
    if not isinstance(key_id, str) or key_id not in trust_keys:
        return False, "untrusted_key"
    key = require_mapping(trust_keys[key_id], f"trust.keys.{key_id}")
    if key.get("revoked") is True:
        return False, "revoked_key"
    secret_env = key.get("secretEnv")
    if not isinstance(secret_env, str) or secret_env not in environment:
        return False, "verification_secret_unavailable"
    secret = environment[secret_env]
    if len(secret) < 32:
        return False, "verification_secret_too_short"
    if record.get("bindingDigest") != binding:
        return False, "release_binding_mismatch"
    signature = record.get("signature")
    expected = sign_record(record, secret)
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        return False, "signature_invalid"
    identity = record.get("actor", record.get("verifier"))
    if identity != key.get("identity"):
        return False, "identity_key_mismatch"
    if record.get("role") is not None and record.get("role") != key.get("role"):
        return False, "role_key_mismatch"
    return True, "verified"
