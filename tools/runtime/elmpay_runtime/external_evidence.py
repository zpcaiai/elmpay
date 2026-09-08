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
import math
import re
from typing import Any, Mapping

from .attestation import ConnectionNonceStore, NonceStore, nonce_store_from_trust
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


def _contains_positive_external_claim(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.upper() in {"APPROVE", "PASS", "PRODUCTION", "VERIFIED"}
    if isinstance(value, Mapping):
        return any(_contains_positive_external_claim(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_positive_external_claim(item) for item in value)
    return False


def validate_test_evidence_template(
    policy: Mapping[str, Any],
    release_policy: Mapping[str, Any],
    template: Mapping[str, Any],
) -> GateReport:
    """Validate completeness of a non-certifying external-evidence request.

    This deliberately validates only that every required external party has a
    place to supply its future evidence.  It rejects positive claims,
    signatures and verified status so a convenient local template cannot be
    confused with an attestation or cross the production release gate.
    """

    reasons: list[str] = []
    checks: list[str] = []
    if policy.get("schemaVersion") != 1:
        reasons.append("test_template_policy_schema_invalid")
    if template.get("schemaVersion") != 1:
        reasons.append("test_template_schema_invalid")
    if template.get("kind") != "EXTERNAL_EVIDENCE_REQUEST_TEMPLATE":
        reasons.append("test_template_kind_invalid")
    if template.get("testOnly") is not True:
        reasons.append("test_template_test_only_marker_missing")
    if template.get("status") != "DRAFT":
        reasons.append("test_template_must_remain_draft")
    if template.get("certificationStatus") != "NOT_CERTIFIED":
        reasons.append("test_template_certification_status_invalid")
    if template.get("deploymentProfile") != policy.get("deploymentProfile"):
        reasons.append("test_template_deployment_profile_mismatch")

    required = policy.get("requiredCategories")
    if not isinstance(required, dict) or not required:
        return GateReport.from_reasons(
            [*reasons, "test_template_policy_categories_missing"], checks
        )
    provider_matrix = policy.get("requiredProviderCapabilities")
    if not isinstance(provider_matrix, dict) or not provider_matrix:
        return GateReport.from_reasons(
            [*reasons, "test_template_provider_matrix_missing"], checks
        )
    required_roles = release_policy.get("requiredApprovalRoles")
    if not isinstance(required_roles, list) or not required_roles:
        return GateReport.from_reasons(
            [*reasons, "test_template_release_approval_policy_missing"], checks
        )
    try:
        approvals = require_list(
            template.get("releaseApprovals"), "template.releaseApprovals"
        )
    except ValidationError as exc:
        return GateReport.from_reasons(
            [*reasons, f"test_template_release_approvals_invalid:{exc}"], checks
        )
    approval_roles: list[str] = []
    for index, raw in enumerate(approvals):
        prefix = f"test_template.releaseApprovals[{index}]"
        try:
            approval = require_mapping(raw, prefix)
            role = require_text(approval.get("role"), f"{prefix}.role")
            actor = require_text(approval.get("actor"), f"{prefix}.actor")
        except ValidationError as exc:
            reasons.append(f"{prefix}:invalid:{exc}")
            continue
        approval_roles.append(role)
        if approval.get("testOnly") is not True \
                or approval.get("status") != "PENDING_EXTERNAL" \
                or approval.get("decision") != "PENDING_EXTERNAL" \
                or not actor.startswith("PENDING_"):
            reasons.append(f"{prefix}:must_be_pending_test_only")
        if "dsse" in approval or "signature" in approval:
            reasons.append(f"{prefix}:test_template_must_not_be_signed")
        checks.append(f"test_template:release_approval:{role}")
    if sorted(approval_roles) != sorted(required_roles):
        reasons.append("test_template_release_approval_roles_incomplete")

    pending_sections = {
        "commercialReadiness": {
            "pricingVersion", "slaVersion", "supportOwner",
            "usageBillingReconciliation", "status", "testOnly",
        },
        "goNoGo": {
            "decisionId", "decision", "releaseManager", "securityApprover",
            "targetDigest", "status", "testOnly",
        },
        "finalReleaseSignoff": {
            "releaseId", "decision", "releaseManager", "securityApprover",
            "status", "testOnly",
        },
    }
    for section_name, required_fields in pending_sections.items():
        try:
            section = require_mapping(template.get(section_name), section_name)
        except ValidationError as exc:
            reasons.append(f"test_template_{section_name}_invalid:{exc}")
            continue
        if any(field not in section for field in required_fields):
            reasons.append(f"test_template_{section_name}_fields_missing")
        if section.get("testOnly") is not True \
                or section.get("status") != "PENDING_EXTERNAL":
            reasons.append(f"test_template_{section_name}_must_remain_pending")
        claim_fields = {key: value for key, value in section.items() if key != "testOnly"}
        if _contains_positive_external_claim(claim_fields):
            reasons.append(f"test_template_{section_name}_positive_claim_forbidden")
        if "dsse" in section or "signature" in section:
            reasons.append(f"test_template_{section_name}_must_not_be_signed")
        checks.append(f"test_template:{section_name}")
    try:
        records = require_list(template.get("evidence"), "template.evidence")
    except ValidationError as exc:
        return GateReport.from_reasons(
            [*reasons, f"test_template_evidence_invalid:{exc}"], checks
        )

    counts: dict[str, int] = {}
    template_providers: set[str] = set()
    for index, raw in enumerate(records):
        prefix = f"test_template[{index}]"
        try:
            record = require_mapping(raw, prefix)
            category = require_text(record.get("category"), f"{prefix}.category")
        except ValidationError as exc:
            reasons.append(f"{prefix}:invalid:{exc}")
            continue
        category_policy = required.get(category)
        if not isinstance(category_policy, dict):
            reasons.append(f"{prefix}:unknown_category:{category}")
            continue
        counts[category] = counts.get(category, 0) + 1
        if record.get("testOnly") is not True \
                or record.get("status") != "PENDING_EXTERNAL" \
                or record.get("externallyVerified") is not False:
            reasons.append(f"{prefix}:must_be_pending_test_only")
        if record.get("role") != "external_verifier" \
                or record.get("source") != category_policy.get("requiredSource"):
            reasons.append(f"{prefix}:external_owner_contract_mismatch")
        if "dsse" in record or "attestationDigest" in record:
            reasons.append(f"{prefix}:test_template_must_not_be_signed")
        try:
            attestation = require_mapping(record.get("attestation"), f"{prefix}.attestation")
        except ValidationError as exc:
            reasons.append(f"{prefix}:attestation_invalid:{exc}")
            continue
        required_fields = category_policy.get("requiredFields")
        if not isinstance(required_fields, list) or any(
            field not in attestation for field in required_fields
        ):
            reasons.append(f"{prefix}:required_field_placeholders_missing")
        if _contains_positive_external_claim(attestation):
            reasons.append(f"{prefix}:positive_external_claim_forbidden")
        if category == "provider_certification":
            provider = attestation.get("providerId")
            capabilities = attestation.get("capabilities")
            if not isinstance(provider, str) or provider not in provider_matrix:
                reasons.append(f"{prefix}:provider_outside_launch_scope")
            else:
                template_providers.add(provider)
                if capabilities != provider_matrix[provider]:
                    reasons.append(f"{prefix}:provider_capability_scope_mismatch")
        checks.append(f"test_template:{category}:{index}")

    for category in required:
        expected_count = len(provider_matrix) if category == "provider_certification" else 1
        if counts.get(category, 0) != expected_count:
            reasons.append(f"test_template_category_count:{category}")
    if template_providers != set(provider_matrix):
        reasons.append("test_template_provider_coverage_incomplete")
    return GateReport.from_reasons(reasons, checks)


def validate_external_evidence(
    policy: Mapping[str, Any],
    bundle: Mapping[str, Any],
    trust: Mapping[str, Any] | None,
    *,
    now: datetime | None = None,
    environment: Mapping[str, str] | None = None,
    expected_binding: str | None = None,
    expected_tenant_id: str | None = None,
    expected_artifact_digest: str | None = None,
    expected_target_digest: str | None = None,
    expected_region: str | None = None,
    expected_images: Mapping[str, str] | None = None,
    expected_admission_policy_digest: str | None = None,
    expected_commit_sha: str | None = None,
    nonce_store: NonceStore | ConnectionNonceStore | None = None,
) -> GateReport:
    """Validate a signed, release-bound external evidence bundle.

    ``trust`` and ``environment`` are deliberately explicit.  Without the
    external verifier's trust material the function returns a blocked report;
    a locally generated JSON file is never treated as certification evidence.
    """

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValidationError("external evidence verification time must be timezone-aware")
    current = current.astimezone(timezone.utc)
    del environment
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
    if bundle.get("testOnly") is True:
        reasons.append("external_evidence_test_only_bundle")
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
        nonce_store = None
    else:
        if nonce_store is None:
            try:
                nonce_store = nonce_store_from_trust(trust)
            except ValidationError as exc:
                reasons.append(f"external_evidence_replay_protection_missing:{exc}")
                nonce_store = None

    required = policy.get("requiredCategories")
    if not isinstance(required, dict) or not required:
        reasons.append("external_evidence_policy_categories_missing")
        required = {}
    try:
        raw_evidence = require_list(bundle.get("evidence"), "bundle.evidence")
    except ValidationError as exc:
        return GateReport.from_reasons([*reasons, f"external_evidence_bundle_invalid:{exc}"], checks)
    if len(raw_evidence) > 64:
        return GateReport.from_reasons(
            [*reasons, "external_evidence_bundle_record_limit_exceeded"], checks
        )

    seen: set[str] = set()
    verified: set[str] = set()
    verifier_ids: set[str] = set()
    certified_provider_capabilities: dict[str, set[str]] = {}
    for index, raw in enumerate(raw_evidence):
        prefix = f"external_evidence[{index}]"
        try:
            evidence = require_mapping(raw, prefix)
            category = require_text(evidence.get("category"), f"{prefix}.category")
        except ValidationError as exc:
            reasons.append(f"{prefix}:{exc}")
            continue
        category_policy = required.get(category)
        if not isinstance(category_policy, dict):
            reasons.append(f"external_evidence_category_not_allowed:{category}")
            continue
        if evidence.get("testOnly") is True:
            reasons.append(f"{category}:test_only_external_evidence_record")
        uniqueness_key = category
        if category == "provider_certification":
            attestation = evidence.get("attestation")
            provider_id = attestation.get("providerId") if isinstance(attestation, dict) else None
            uniqueness_key = f"{category}:{provider_id}"
        if uniqueness_key in seen:
            reasons.append(f"duplicate_external_evidence_record:{uniqueness_key}")
            continue
        seen.add(uniqueness_key)
        valid, verifier, record_reasons = _validate_record(
            category_policy,
            evidence,
            prefix,
            current,
            trust if isinstance(trust, dict) else {},
            binding if isinstance(binding, str) else "",
            nonce_store,
            expected_tenant_id,
            expected_artifact_digest,
            expected_target_digest,
            expected_region,
            expected_images,
            expected_admission_policy_digest,
            expected_commit_sha,
        )
        if record_reasons:
            reasons.extend(f"{category}:{reason}" for reason in record_reasons)
        if valid:
            verified.add(category)
            if category == "provider_certification":
                attestation = require_mapping(evidence.get("attestation"), "provider attestation")
                provider_id = require_text(attestation.get("providerId"), "providerId")
                capabilities = {
                    require_text(item, "provider capability")
                    for item in require_list(attestation.get("capabilities"), "capabilities")
                }
                certified_provider_capabilities[provider_id] = capabilities
            if verifier:
                verifier_ids.add(verifier)
            checks.append(f"external_evidence:{category}:{verifier}")
    for category in sorted(set(required) - verified):
        reasons.append(f"missing_external_evidence:{category}")
    required_matrix = policy.get("requiredProviderCapabilities")
    if not isinstance(required_matrix, dict) or not required_matrix:
        reasons.append("provider_certification_matrix_missing")
    else:
        for provider, raw_capabilities in sorted(required_matrix.items()):
            try:
                required_capabilities = {
                    require_text(item, f"requiredProviderCapabilities.{provider}")
                    for item in require_list(raw_capabilities, f"requiredProviderCapabilities.{provider}")
                }
            except ValidationError as exc:
                reasons.append(f"provider_certification_policy_invalid:{exc}")
                continue
            supplied = certified_provider_capabilities.get(provider)
            if supplied is None:
                reasons.append(f"provider_certification_missing:{provider}")
            else:
                for capability in sorted(required_capabilities - supplied):
                    reasons.append(f"provider_capability_not_certified:{provider}:{capability}")
    minimum = policy.get("minimumDistinctVerifiers", 1)
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
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
    binding: str,
    nonce_store: NonceStore | ConnectionNonceStore | None,
    expected_tenant_id: str | None,
    expected_artifact_digest: str | None,
    expected_target_digest: str | None,
    expected_region: str | None,
    expected_images: Mapping[str, str] | None,
    expected_admission_policy_digest: str | None,
    expected_commit_sha: str | None,
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
        if not isinstance(evidence.get("dsse"), dict):
            reasons.append("dsse_signature_missing")
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
        if (
            isinstance(maximum_age, bool)
            or not isinstance(maximum_age, int)
            or maximum_age <= 0
        ):
            reasons.append("maximum_age_policy_invalid")
        elif current - observed > timedelta(hours=maximum_age):
            reasons.append("evidence_stale")
    except ValidationError as exc:
        reasons.append(str(exc))
        verifier = None
        attestation = {}

    key_valid = False
    if not reasons and isinstance(trust.get("keys"), dict) and nonce_store is not None:
        try:
            key_valid, detail = _verify_signed_record(
                evidence, trust, binding, current, nonce_store
            )
            if not key_valid:
                reasons.append(f"signature:{detail}")
            else:
                envelope = require_mapping(evidence.get("dsse"), "evidence.dsse")
                signatures = require_list(envelope.get("signatures"), "evidence.dsse.signatures")
                signature = require_mapping(signatures[0], "evidence.dsse.signature")
                key = trust["keys"].get(signature.get("keyid"), {})
                if not isinstance(key, dict) or key.get("independent") is not True:
                    reasons.append("verifier_not_independent")
                if key.get("role") != evidence.get("role"):
                    reasons.append("verifier_role_key_mismatch")
        except (ValidationError, KeyError, TypeError) as exc:
            reasons.append(f"signature:{exc}")
    elif not reasons:
        reasons.append("trust_or_replay_material_missing")

    if not reasons:
        semantic_attestation = {**attestation, "verifierId": verifier}
        reasons.extend(_semantic_reasons(category_policy, semantic_attestation, prefix))
        category = category_policy.get("category")
        if expected_tenant_id is not None:
            attested_tenant = attestation.get("tenantId")
            if category == "uat_acceptance" and attested_tenant != expected_tenant_id:
                reasons.append("uat_tenant_binding_mismatch")
            elif attested_tenant is not None and attested_tenant != expected_tenant_id:
                reasons.append("evidence_tenant_binding_mismatch")
        if (
            expected_artifact_digest is not None
            and category == "production_kubernetes"
            and attestation.get("artifactDigest") != expected_artifact_digest
        ):
            reasons.append("kubernetes_artifact_binding_mismatch")
        if (
            expected_target_digest is not None
            and category in {
                "uat_acceptance", "shadow_rollout", "canary_rollout",
                "merchant_acceptance",
            }
            and attestation.get("targetDigest") != expected_target_digest
        ):
            reasons.append("evidence_target_binding_mismatch")
        if expected_region is not None and category == "production_kubernetes":
            regions = attestation.get("regions")
            if not isinstance(regions, list) or expected_region not in regions:
                reasons.append("kubernetes_target_region_missing")
        if expected_images is not None and category == "production_kubernetes":
            supplied_images = attestation.get("imageDigests")
            expected_values = list(expected_images.values())
            if not isinstance(supplied_images, list) \
                    or len(supplied_images) != len(expected_values) \
                    or set(supplied_images) != set(expected_values):
                reasons.append("kubernetes_image_inventory_binding_mismatch")
        if expected_admission_policy_digest is not None \
                and category == "production_kubernetes" \
                and attestation.get("admissionPolicyDigest") \
                != expected_admission_policy_digest:
            reasons.append("kubernetes_admission_policy_binding_mismatch")
        if expected_commit_sha is not None and category == "production_kubernetes" \
                and attestation.get("commitSha") != expected_commit_sha:
            reasons.append("kubernetes_commit_binding_mismatch")
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
        open_findings = attestation.get("openFindings")
        if (
            isinstance(open_findings, bool)
            or not isinstance(open_findings, int)
            or open_findings != 0
        ):
            reasons.append("human_review_open_findings")
        if attestation.get("phishingResistantAuth") is not True:
            reasons.append("human_review_authentication_not_phishing_resistant")
    elif category == "provider_certification":
        if attestation.get("environment") != "PRODUCTION":
            reasons.append("provider_certification_not_production")
        if attestation.get("official") is not True or attestation.get("sandboxValidated") is not True:
            reasons.append("provider_certification_not_official")
        capabilities = attestation.get("capabilities")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or any(not isinstance(item, str) or not item.strip() for item in capabilities)
            or len(set(capabilities)) != len(capabilities)
        ):
            reasons.append("provider_capability_matrix_missing")
    elif category == "production_kubernetes":
        if attestation.get("environment") != "PRODUCTION":
            reasons.append("kubernetes_evidence_not_production")
        drift = attestation.get("gitopsDriftCount")
        if (
            isinstance(drift, bool)
            or not isinstance(drift, int)
            or drift != 0
            or attestation.get("admissionPolicyPassed") is not True
        ):
            reasons.append("kubernetes_policy_or_drift_failed")
        images = attestation.get("imageDigests")
        if not isinstance(images, list) or not images or any(
            not isinstance(item, str) or not re.fullmatch(r"^.+@sha256:[0-9a-f]{64}$", item)
            for item in images
        ) or len(set(images)) != len(images):
            reasons.append("kubernetes_image_digests_invalid")
        regions = attestation.get("regions")
        if (
            not isinstance(regions, list)
            or any(not isinstance(item, str) or not item.strip() for item in regions)
            or len(set(regions)) < 2
        ):
            reasons.append("kubernetes_regions_insufficient")
        if not isinstance(attestation.get("commitSha"), str) or not COMMIT_PATTERN.fullmatch(attestation["commitSha"]):
            reasons.append("kubernetes_commit_sha_invalid")
        if not isinstance(attestation.get("artifactDigest"), str) or not DIGEST_PATTERN.fullmatch(attestation["artifactDigest"]):
            reasons.append("kubernetes_artifact_digest_invalid")
        admission_digest = attestation.get("admissionPolicyDigest")
        if not isinstance(admission_digest, str) \
                or not DIGEST_PATTERN.fullmatch(admission_digest) \
                or admission_digest == "0" * 64:
            reasons.append("kubernetes_admission_policy_digest_invalid")
        if attestation.get("artifactDigest") == "0" * 64 \
                or attestation.get("rolloutStage") != "PRODUCTION":
            reasons.append("kubernetes_release_subject_invalid")
    elif category == "dr_exercise":
        regions = attestation.get("regions")
        if (
            not isinstance(regions, list)
            or any(not isinstance(item, str) or not item.strip() for item in regions)
            or len(set(regions)) < 2
        ):
            reasons.append("dr_requires_two_distinct_regions")
        measured_rpo = attestation.get("measuredRpoSeconds")
        maximum_rpo = category_policy.get("maximumRpoSeconds")
        if (
            isinstance(measured_rpo, bool)
            or not isinstance(measured_rpo, int)
            or measured_rpo < 0
            or isinstance(maximum_rpo, bool)
            or not isinstance(maximum_rpo, int)
            or maximum_rpo < 0
            or measured_rpo > maximum_rpo
        ):
            reasons.append("dr_rpo_exceeded")
        measured_rto = attestation.get("measuredRtoSeconds")
        maximum_rto = category_policy.get("maximumRtoSeconds")
        if (
            isinstance(measured_rto, bool)
            or not isinstance(measured_rto, int)
            or measured_rto < 0
            or isinstance(maximum_rto, bool)
            or not isinstance(maximum_rto, int)
            or maximum_rto < 0
            or measured_rto > maximum_rto
        ):
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
        total = attestation.get("scenariosTotal")
        passed = attestation.get("scenariosPassed")
        if (
            isinstance(total, bool)
            or not isinstance(total, int)
            or total <= 0
            or isinstance(passed, bool)
            or not isinstance(passed, int)
            or passed != total
        ):
            reasons.append("uat_scenarios_incomplete")
        for field in ("financeSignoff", "operationsSignoff", "merchantSignoff"):
            if attestation.get(field) is not True:
                reasons.append(f"uat_{field}_missing")
        for field in ("targetDigest", "suiteDigest", "resultDigest"):
            value = attestation.get(field)
            if not isinstance(value, str) or not DIGEST_PATTERN.fullmatch(value):
                reasons.append(f"uat_{field}_invalid")
    elif category == "penetration_test":
        if attestation.get("testerIndependent") is not True:
            reasons.append("penetration_tester_not_independent")
        findings = attestation.get("findings", {})
        if (
            not isinstance(findings, dict)
            or any(
                isinstance(findings.get(level), bool)
                or not isinstance(findings.get(level), int)
                or findings.get(level) != 0
                for level in ("critical", "high")
            )
        ):
            reasons.append("penetration_findings_exceeded")
    elif category == "shadow_rollout":
        side_effects = attestation.get("candidateSideEffects")
        mismatches = attestation.get("mismatchCount")
        if (
            attestation.get("stage") != "SHADOW"
            or isinstance(side_effects, bool)
            or not isinstance(side_effects, int)
            or side_effects != 0
            or isinstance(mismatches, bool)
            or not isinstance(mismatches, int)
            or mismatches != 0
        ):
            reasons.append("shadow_rollout_failed")
        if (
            isinstance(attestation.get("sampleCount"), bool)
            or not isinstance(attestation.get("sampleCount"), int)
            or attestation["sampleCount"] <= 0
        ):
            reasons.append("shadow_sample_count_invalid")
        for field in ("targetDigest", "datasetDigest", "resultDigest"):
            value = attestation.get(field)
            if not isinstance(value, str) or not DIGEST_PATTERN.fullmatch(value):
                reasons.append(f"shadow_{field}_invalid")
    elif category == "canary_rollout":
        if attestation.get("stage") not in {"CANARY", "PRODUCTION"} or attestation.get("autoStopTriggered") is not False:
            reasons.append("canary_rollout_failed")
        if any(
            isinstance(attestation.get(field), bool)
            or not isinstance(attestation.get(field), int)
            or attestation.get(field) != 0
            for field in ("duplicateSideEffectCount", "securityCriticalCount")
        ):
            reasons.append("canary_safety_threshold_exceeded")
        traffic = attestation.get("trafficPercent")
        window = attestation.get("windowMinutes")
        if (
            isinstance(traffic, bool)
            or not isinstance(traffic, int)
            or not 0 < traffic <= 100
            or isinstance(window, bool)
            or not isinstance(window, int)
            or window <= 0
        ):
            reasons.append("canary_window_or_traffic_invalid")
        for field, maximum in (
            ("errorRateDelta", 0.002),
            ("latencyP99DeltaMs", 100),
            ("authorizationRateDrop", 0.01),
        ):
            value = attestation.get(field)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value < 0
                or value > maximum
            ):
                reasons.append(f"canary_{field}_exceeded")
    elif category == "merchant_acceptance":
        if attestation.get("accepted") is not True or attestation.get("merchantSignoff") is not True:
            reasons.append("merchant_acceptance_missing")
        for field in ("targetDigest", "scenarioDigest"):
            value = attestation.get(field)
            if not isinstance(value, str) or not DIGEST_PATTERN.fullmatch(value):
                reasons.append(f"merchant_{field}_invalid")
    elif category in {"legal_compliance", "regional_market_approval"}:
        if attestation.get("decision") != "APPROVE" or attestation.get("externalAuthority") is not True:
            reasons.append("external_legal_approval_missing")
    return reasons
