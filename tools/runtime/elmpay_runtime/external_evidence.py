"""Fail-closed validation for evidence produced outside the repository.

The repository can validate the shape, cryptographic binding, freshness and
semantic claims of an external evidence bundle.  It cannot manufacture a
QSA report, provider certification, production observation or merchant
approval.  A bundle is therefore accepted only when every required category
is independently signed and contains the category-specific observations
declared by ``platform/compliance/external-evidence-policy.json``.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import re
from typing import Any, Mapping

from .common import (
    GateReport,
    ValidationError,
    parse_instant,
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from .release import _verify_signed_record


DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")


def validate_external_evidence(
    policy: Mapping[str, Any],
    bundle: Mapping[str, Any],
    trust: Mapping[str, Any] | None,
    *,
    now: datetime | None = None,
    environment: Mapping[str, str] | None = None,
    expected_binding: str | None = None,
) -> GateReport:
    """Validate a signed, release-bound external evidence bundle.

    ``trust`` and ``environment`` are deliberately explicit.  Without the
    external verifier's trust material the function returns a blocked report;
    a locally generated JSON file is never treated as certification evidence.
    """

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    env = environment if environment is not None else os.environ
    reasons: list[str] = []
    checks: list[str] = []

    if policy.get("schemaVersion") != 1:
        reasons.append("external_evidence_policy_schema_invalid")
    if policy.get("localValidationMayCertify") is not False:
        reasons.append("external_evidence_local_certification_forbidden")
    if policy.get("independentEvidenceRequired") is not True:
        reasons.append("external_evidence_independence_required")
    if bundle.get("schemaVersion") != 1:
        reasons.append("external_evidence_bundle_schema_invalid")
    if bundle.get("status") != "VERIFIED":
        reasons.append("external_evidence_bundle_not_verified")

    binding = bundle.get("releaseBindingDigest")
    if not isinstance(binding, str) or not DIGEST_PATTERN.fullmatch(binding):
        reasons.append("external_evidence_binding_invalid")
    elif expected_binding is not None and binding != expected_binding:
        reasons.append("external_evidence_binding_mismatch")

    try:
        generated_at = parse_instant(bundle.get("generatedAt"), "bundle.generatedAt")
        expires_at = parse_instant(bundle.get("expiresAt"), "bundle.expiresAt")
        if generated_at > current + timedelta(minutes=5):
            reasons.append("external_evidence_generated_in_future")
        if expires_at <= current or expires_at <= generated_at:
            reasons.append("external_evidence_bundle_expired")
    except ValidationError as exc:
        reasons.append(f"external_evidence_bundle_time_invalid:{exc}")

    if not isinstance(trust, dict) or not isinstance(trust.get("keys"), dict):
        reasons.append("external_evidence_trust_material_missing")

    required = policy.get("requiredCategories")
    if not isinstance(required, dict) or not required:
        reasons.append("external_evidence_policy_categories_missing")
        required = {}
    try:
        raw_evidence = require_list(bundle.get("evidence"), "bundle.evidence")
    except ValidationError as exc:
        return GateReport.from_reasons([*reasons, f"external_evidence_bundle_invalid:{exc}"], checks)

    seen: set[str] = set()
    verified: set[str] = set()
    verifier_ids: set[str] = set()
    for index, raw in enumerate(raw_evidence):
        prefix = f"external_evidence[{index}]"
        try:
            evidence = require_mapping(raw, prefix)
            category = require_text(evidence.get("category"), f"{prefix}.category")
        except ValidationError as exc:
            reasons.append(f"{prefix}:{exc}")
            continue
        if category in seen:
            reasons.append(f"duplicate_external_evidence_category:{category}")
            continue
        seen.add(category)
        category_policy = required.get(category)
        if not isinstance(category_policy, dict):
            reasons.append(f"external_evidence_category_not_allowed:{category}")
            continue
        valid, verifier, record_reasons = _validate_record(
            category_policy,
            evidence,
            prefix,
            current,
            trust if isinstance(trust, dict) else {},
            env,
            binding if isinstance(binding, str) else "",
        )
        if record_reasons:
            reasons.extend(f"{category}:{reason}" for reason in record_reasons)
        if valid:
            verified.add(category)
            if verifier:
                verifier_ids.add(verifier)
            checks.append(f"external_evidence:{category}:{verifier}")
    for category in sorted(set(required) - verified):
        reasons.append(f"missing_external_evidence:{category}")
    minimum = policy.get("minimumDistinctVerifiers", 1)
    if not isinstance(minimum, int) or minimum < 1:
        reasons.append("external_evidence_policy_verifier_count_invalid")
    elif len(verifier_ids) < minimum:
        reasons.append("insufficient_distinct_external_verifiers")
    return GateReport.from_reasons(reasons, checks)


def _validate_record(
    category_policy: Mapping[str, Any],
    evidence: Mapping[str, Any],
    prefix: str,
    current: datetime,
    trust: Mapping[str, Any],
    environment: Mapping[str, str],
    binding: str,
) -> tuple[bool, str | None, tuple[str, ...]]:
    reasons: list[str] = []
    try:
        verifier = require_text(evidence.get("verifier"), f"{prefix}.verifier")
        role = require_text(evidence.get("role"), f"{prefix}.role")
        evidence_id = require_text(evidence.get("evidenceId"), f"{prefix}.evidenceId")
        attestation = require_mapping(evidence.get("attestation"), f"{prefix}.attestation")
        if evidence.get("status") != "VERIFIED":
            reasons.append("status_not_verified")
        if evidence.get("bindingDigest") != binding:
            reasons.append("release_binding_mismatch")
        digest = evidence.get("attestationDigest")
        if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
            reasons.append("attestation_digest_invalid")
        elif digest != sha256_json(attestation):
            reasons.append("attestation_digest_mismatch")
        if not isinstance(evidence.get("signature"), str) or len(evidence["signature"]) < 32:
            reasons.append("signature_missing")
        if category_policy.get("requiredRole") != role:
            reasons.append("verifier_role_invalid")
        if category_policy.get("requiredSource") and evidence.get("source") != category_policy["requiredSource"]:
            reasons.append("evidence_source_invalid")
        if category_policy.get("externalVerifierRequired") is True and evidence.get("externallyVerified") is not True:
            reasons.append("external_verification_missing")
        observed = parse_instant(evidence.get("observedAt"), f"{prefix}.observedAt")
        expires = parse_instant(evidence.get("expiresAt"), f"{prefix}.expiresAt")
        if observed > current + timedelta(minutes=5):
            reasons.append("observed_in_future")
        if expires <= current or expires <= observed:
            reasons.append("evidence_expired")
        maximum_age = category_policy.get("maximumAgeHours")
        if isinstance(maximum_age, int) and current - observed > timedelta(hours=maximum_age):
            reasons.append("evidence_stale")
    except ValidationError as exc:
        reasons.append(str(exc))
        verifier = None
        attestation = {}

    key_valid = False
    if not reasons and isinstance(trust.get("keys"), dict):
        try:
            key_valid, detail = _verify_signed_record(evidence, trust["keys"], environment, binding)
            if not key_valid:
                reasons.append(f"signature:{detail}")
            else:
                key = trust["keys"].get(evidence.get("keyId"), {})
                if not isinstance(key, dict) or key.get("independent") is not True:
                    reasons.append("verifier_not_independent")
                if key.get("role") != evidence.get("role"):
                    reasons.append("verifier_role_key_mismatch")
        except (ValidationError, KeyError, TypeError) as exc:
            reasons.append(f"signature:{exc}")
    elif not reasons:
        reasons.append("trust_material_missing")

    if not reasons:
        semantic_attestation = {**attestation, "verifierId": verifier}
        reasons.extend(_semantic_reasons(category_policy, semantic_attestation, prefix))
    return not reasons, verifier if not reasons and key_valid else None, tuple(sorted(set(reasons)))


def _semantic_reasons(
    category_policy: Mapping[str, Any], attestation: Mapping[str, Any], prefix: str
) -> list[str]:
    """Apply category-specific requirements from the policy document."""

    reasons: list[str] = []
    required_fields = category_policy.get("requiredFields", [])
    if not isinstance(required_fields, list):
        return [f"{prefix}.requiredFields policy_invalid"]
    for field in required_fields:
        if not isinstance(field, str) or field not in attestation or attestation[field] in (None, "", []):
            reasons.append(f"missing_field:{field}")

    category = category_policy.get("category")
    if category == "independent_human_review":
        if attestation.get("decision") != "APPROVE":
            reasons.append("human_review_not_approved")
        if attestation.get("reviewerId") == attestation.get("implementerId"):
            reasons.append("human_review_not_independent")
        if attestation.get("reviewerId") != attestation.get("verifierId"):
            reasons.append("human_review_verifier_identity_mismatch")
        if attestation.get("openFindings", 0) != 0:
            reasons.append("human_review_open_findings")
        if attestation.get("phishingResistantAuth") is not True:
            reasons.append("human_review_authentication_not_phishing_resistant")
    elif category == "provider_certification":
        if attestation.get("environment") != "PRODUCTION":
            reasons.append("provider_certification_not_production")
        if attestation.get("official") is not True or attestation.get("sandboxValidated") is not True:
            reasons.append("provider_certification_not_official")
        if not isinstance(attestation.get("capabilities"), list) or not attestation["capabilities"]:
            reasons.append("provider_capability_matrix_missing")
    elif category == "production_kubernetes":
        if attestation.get("environment") != "PRODUCTION":
            reasons.append("kubernetes_evidence_not_production")
        if attestation.get("gitopsDriftCount") != 0 or attestation.get("admissionPolicyPassed") is not True:
            reasons.append("kubernetes_policy_or_drift_failed")
        if not isinstance(attestation.get("imageDigests"), list) or any(
            not isinstance(item, str) or "@sha256:" not in item for item in attestation["imageDigests"]
        ):
            reasons.append("kubernetes_image_digests_invalid")
        if not isinstance(attestation.get("commitSha"), str) or not COMMIT_PATTERN.fullmatch(attestation["commitSha"]):
            reasons.append("kubernetes_commit_sha_invalid")
        if not isinstance(attestation.get("artifactDigest"), str) or not DIGEST_PATTERN.fullmatch(attestation["artifactDigest"]):
            reasons.append("kubernetes_artifact_digest_invalid")
    elif category == "dr_exercise":
        regions = attestation.get("regions")
        if not isinstance(regions, list) or len(set(regions)) < 2:
            reasons.append("dr_requires_two_distinct_regions")
        if attestation.get("measuredRpoSeconds", 10**9) > category_policy.get("maximumRpoSeconds", 60):
            reasons.append("dr_rpo_exceeded")
        if attestation.get("measuredRtoSeconds", 10**9) > category_policy.get("maximumRtoSeconds", 900):
            reasons.append("dr_rto_exceeded")
        for field in ("failbackPassed", "writeFenceObserved", "providerRoutingVerified", "dataLossDetected"):
            expected = False if field == "dataLossDetected" else True
            if attestation.get(field) is not expected:
                reasons.append(f"dr_{field}_invalid")
    elif category == "pci_assessor":
        if attestation.get("assessorIndependent") is not True or attestation.get("status") != "PASS":
            reasons.append("pci_assessor_not_independent_pass")
    elif category == "uat_acceptance":
        if attestation.get("environment") != "UAT":
            reasons.append("uat_environment_invalid")
        if attestation.get("scenariosTotal", 0) <= 0 or attestation.get("scenariosPassed") != attestation.get("scenariosTotal"):
            reasons.append("uat_scenarios_incomplete")
        for field in ("financeSignoff", "operationsSignoff", "merchantSignoff"):
            if attestation.get(field) is not True:
                reasons.append(f"uat_{field}_missing")
    elif category == "penetration_test":
        if attestation.get("testerIndependent") is not True:
            reasons.append("penetration_tester_not_independent")
        findings = attestation.get("findings", {})
        if not isinstance(findings, dict) or findings.get("critical", 1) != 0 or findings.get("high", 1) != 0:
            reasons.append("penetration_findings_exceeded")
    elif category == "shadow_rollout":
        if attestation.get("stage") != "SHADOW" or attestation.get("candidateSideEffects", 1) != 0 or attestation.get("mismatchCount", 1) != 0:
            reasons.append("shadow_rollout_failed")
        if not isinstance(attestation.get("sampleCount"), int) or attestation["sampleCount"] <= 0:
            reasons.append("shadow_sample_count_invalid")
    elif category == "canary_rollout":
        if attestation.get("stage") not in {"CANARY", "PRODUCTION"} or attestation.get("autoStopTriggered") is not False:
            reasons.append("canary_rollout_failed")
        if attestation.get("duplicateSideEffectCount", 1) != 0 or attestation.get("securityCriticalCount", 1) != 0:
            reasons.append("canary_safety_threshold_exceeded")
        for field, maximum in (
            ("errorRateDelta", 0.002),
            ("latencyP99DeltaMs", 100),
            ("authorizationRateDrop", 0.01),
        ):
            value = attestation.get(field)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0 or value > maximum:
                reasons.append(f"canary_{field}_exceeded")
    elif category == "merchant_acceptance":
        if attestation.get("accepted") is not True or attestation.get("merchantSignoff") is not True:
            reasons.append("merchant_acceptance_missing")
    elif category in {"legal_compliance", "regional_market_approval"}:
        if attestation.get("decision") != "APPROVE" or attestation.get("externalAuthority") is not True:
            reasons.append("external_legal_approval_missing")
    return reasons
