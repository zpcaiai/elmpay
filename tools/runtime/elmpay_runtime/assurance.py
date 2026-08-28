"""B104-B111 executable compliance boundaries and data lifecycle controls.

These controls decide whether a configured operation is allowed.  They never
turn local configuration into PCI, legal, provider or production certification.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import re
import sqlite3
from typing import Any, Callable, Mapping

from .common import GateReport, ValidationError, canonical_json, parse_instant, require_list, require_mapping, require_text
from .downstream_receipt import verify_downstream_receipt


DIGEST = re.compile(r"^[0-9a-f]{64}$")


def evaluate_pci_scope(inventory: Mapping[str, Any]) -> GateReport:
    reasons: list[str] = []
    components = require_list(inventory.get("components"), "components")
    if not components:
        reasons.append("pci_component_inventory_empty")
    names: set[str] = set()
    for raw in components:
        component = require_mapping(raw, "component")
        name = require_text(component.get("name"), "component.name")
        if name in names:
            reasons.append(f"pci_component_duplicate:{name}")
        names.add(name)
        stores = set(require_list(component.get("storedDataClasses"), "storedDataClasses"))
        if stores & {"PAN", "CVV", "TRACK_DATA", "PIN_BLOCK"}:
            reasons.append(f"pci_forbidden_data_storage:{name}")
        if component.get("cardEntry") is True and component.get("hostedProviderField") is not True:
            reasons.append(f"pci_unhosted_card_entry:{name}")
        if component.get("responsibilityOwner") not in {"ELMPAY", "MERCHANT", "PSP", "SHARED"}:
            reasons.append(f"pci_responsibility_missing:{name}")
    if inventory.get("segmentationTestRequired") is not True:
        reasons.append("pci_segmentation_test_not_required")
    if inventory.get("externalAssessmentRequired") is not True:
        reasons.append("pci_external_assessment_not_required")
    return GateReport.from_reasons(reasons, (f"pci_component:{name}" for name in names))


def evaluate_regional_onboarding(
    policy: Mapping[str, Any],
    request: Mapping[str, Any],
    trust: Mapping[str, Any],
    *,
    now: datetime,
) -> GateReport:
    """Validate market entry from independently signed legal evidence.

    Locally-authored ``independent`` or ``verifier`` flags are deliberately not
    accepted.  Each category is a DSSE receipt bound to the selected market,
    processing region and cross-border posture.
    """

    market = require_text(request.get("market"), "market")
    markets = {item["market"]: item for item in require_list(policy.get("markets"), "markets")}
    if market not in markets:
        return GateReport.from_reasons(["unknown_market_blocked"])
    configured = require_mapping(markets[market], "market policy")
    supplied = require_mapping(request.get("evidence"), "evidence")
    reasons: list[str] = []
    checks: list[str] = []
    verifiers: set[str] = set()
    required_categories = {
        require_text(category, "requiredEvidence category")
        for category in require_list(configured.get("requiredEvidence"), "requiredEvidence")
    }
    if set(supplied) != required_categories:
        reasons.append("regional_evidence_category_set_mismatch")
    processing_region = require_text(request.get("processingRegion"), "processingRegion")
    cross_border = request.get("crossBorderData") is True
    transfer_mechanism = request.get("approvedTransferMechanism")
    for category in sorted(required_categories):
        item = supplied.get(category)
        if not isinstance(item, dict):
            reasons.append(f"regional_evidence_missing:{category}")
            continue
        fields = item.get("fields")
        if not isinstance(fields, dict):
            reasons.append(f"regional_evidence_fields_invalid:{category}")
            continue
        expected_keys = {
            "market", "category", "evidenceDigest", "processingRegion",
            "crossBorderData", "approvedTransferMechanism", "expiresAt",
        }
        if set(fields) != expected_keys:
            reasons.append(f"regional_evidence_field_set_invalid:{category}")
        if fields.get("market") != market or fields.get("category") != category:
            reasons.append(f"regional_evidence_binding_mismatch:{category}")
        if fields.get("processingRegion") != processing_region \
                or fields.get("crossBorderData") is not cross_border \
                or fields.get("approvedTransferMechanism") != transfer_mechanism:
            reasons.append(f"regional_evidence_scope_mismatch:{category}")
        digest = fields.get("evidenceDigest")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            reasons.append(f"regional_evidence_digest_invalid:{category}")
        try:
            expires = parse_instant(fields.get("expiresAt"), f"{category}.expiresAt")
            if expires <= now.astimezone(timezone.utc):
                reasons.append(f"regional_evidence_expired:{category}")
        except ValidationError:
            reasons.append(f"regional_evidence_time_invalid:{category}")
        try:
            receipt_digest, signer = verify_downstream_receipt(
                item,
                trust,
                receipt_type="REGIONAL_LEGAL_EVIDENCE",
                outcome="VERIFIED",
                fields=fields,
                required_role="regional_legal_verifier",
                require_independent=True,
                now=now,
            )
            verifiers.add(signer.identity)
            checks.append(f"regional_evidence:{category}:{signer.identity}:{receipt_digest}")
        except (ValidationError, TypeError, ValueError) as exc:
            reasons.append(f"regional_evidence_unverified:{category}:{exc}")
    if configured.get("externalLegalValidationRequired") is True and len(verifiers) < 1:
        reasons.append("external_legal_verifier_missing")
    if cross_border and configured.get("crossBorderDataDefault") == "DENY":
        if transfer_mechanism not in {"SCC", "PIPL_SECURITY_ASSESSMENT", "CERTIFICATION", "ADEQUACY"}:
            reasons.append("cross_border_transfer_not_approved")
    if processing_region not in require_list(request.get("allowedProcessingRegions"), "allowedProcessingRegions"):
        reasons.append("processing_region_not_allowed")
    if policy.get("localConfigurationMayApproveMarket") is not False:
        reasons.append("local_market_approval_must_be_forbidden")
    return GateReport.from_reasons(reasons, checks)


def evaluate_regulated_identity_decision(
    boundary: Mapping[str, Any],
    decision: Mapping[str, Any],
    trust: Mapping[str, Any],
    *,
    now: datetime,
) -> GateReport:
    reasons: list[str] = []
    checks: list[str] = []
    for field in ("tenantId", "provider", "providerDecisionId", "subjectReference", "policyVersion"):
        try:
            require_text(decision.get(field), field)
        except ValidationError:
            reasons.append(f"regulated_decision_missing:{field}")
    if decision.get("status") not in {"APPROVED", "REJECTED", "REVIEW"}:
        reasons.append("regulated_decision_status_invalid")
    try:
        observed = parse_instant(decision.get("observedAt"), "observedAt")
        if observed > now.astimezone(timezone.utc) + timedelta(minutes=5):
            reasons.append("regulated_decision_in_future")
        if now.astimezone(timezone.utc) - observed > timedelta(hours=24):
            reasons.append("regulated_decision_stale")
    except ValidationError:
        reasons.append("regulated_decision_time_invalid")
    fields = {
        name: decision.get(name)
        for name in (
            "tenantId", "provider", "providerDecisionId", "subjectReference",
            "policyVersion", "status", "observedAt",
        )
    }
    try:
        receipt_digest, signer = verify_downstream_receipt(
            require_mapping(decision.get("receipt"), "regulated provider receipt"),
            trust,
            receipt_type="REGULATED_IDENTITY_DECISION",
            outcome=str(decision.get("status")),
            fields=fields,
            required_role="licensed_identity_provider",
            require_independent=True,
            now=now,
        )
        if signer.identity != decision.get("provider"):
            reasons.append("regulated_provider_identity_mismatch")
        checks.extend((f"regulated_receipt:{receipt_digest}",
                       f"licensed_provider:{signer.identity}"))
    except (ValidationError, TypeError, ValueError) as exc:
        reasons.append(f"regulated_decision_unverified:{exc}")
    sar = require_mapping(boundary.get("suspiciousActivityReporting"), "suspiciousActivityReporting")
    if sar.get("automatedFilingAllowed") is not False:
        reasons.append("automated_regulatory_filing_forbidden")
    if decision.get("platformFiledRegulatoryReport") is True:
        reasons.append("platform_crossed_regulatory_boundary")
    return GateReport.from_reasons(reasons, (*checks, "signed_decision", "regulatory_boundary"))


def evaluate_sca_transaction(
    policy: Mapping[str, Any],
    transaction: Mapping[str, Any],
    trust: Mapping[str, Any],
    *,
    now: datetime,
) -> GateReport:
    """Evaluate a PSD2/SCA transaction without claiming regulator approval.

    In-scope payments either carry a transaction-bound, provider-verified SCA
    result with two independent factors and dynamic linking, or a narrowly
    governed exemption.  Unknown scope, stale evidence and provider errors all
    fail closed to step-up/review rather than authorizing money movement.
    """
    reasons: list[str] = []
    checks: list[str] = []
    tenant_id = require_text(transaction.get("tenantId"), "tenantId")
    transaction_id = require_text(transaction.get("transactionId"), "transactionId")
    market = require_text(transaction.get("market"), "market").upper()
    amount = transaction.get("amountMinor")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
        reasons.append("sca_amount_invalid")
    currency = transaction.get("currency")
    if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
        reasons.append("sca_currency_invalid")
    in_scope_markets = set(require_list(policy.get("inScopeMarkets"), "inScopeMarkets"))
    out_of_scope_markets = set(require_list(policy.get("explicitOutOfScopeMarkets"),
                                             "explicitOutOfScopeMarkets"))
    if policy.get("localConfigurationMayClaimCompliance") is not False:
        reasons.append("sca_local_compliance_claim_must_be_forbidden")
    if market in out_of_scope_markets:
        return GateReport.from_reasons(reasons, (
            f"sca_out_of_scope:{market}", f"tenant:{tenant_id}", f"transaction:{transaction_id}"
        ))
    if market not in in_scope_markets:
        reasons.append("sca_market_scope_unknown")
    authentication = transaction.get("authentication")
    exemption = transaction.get("exemption")
    if authentication is not None and exemption is not None:
        reasons.append("sca_authentication_and_exemption_conflict")
    elif authentication is not None:
        auth = require_mapping(authentication, "authentication")
        fields = require_mapping(auth.get("fields"), "authentication.fields")
        required_fields = {
            "provider", "providerAuthenticationId", "tenantId", "transactionId",
            "amountMinor", "currency", "payeeReference", "factors", "observedAt",
        }
        if set(fields) != required_fields:
            reasons.append("sca_authentication_field_set_invalid")
        if fields.get("tenantId") != tenant_id or fields.get("transactionId") != transaction_id:
            reasons.append("sca_transaction_binding_mismatch")
        if fields.get("amountMinor") != amount or fields.get("currency") != currency:
            reasons.append("sca_dynamic_link_amount_mismatch")
        payee = require_text(transaction.get("payeeReference"), "payeeReference")
        if fields.get("payeeReference") != payee:
            reasons.append("sca_dynamic_link_payee_mismatch")
        factors = set(require_list(fields.get("factors"), "authentication.factors"))
        valid_factors = {"KNOWLEDGE", "POSSESSION", "INHERENCE"}
        if len(factors) < 2 or not factors <= valid_factors:
            reasons.append("sca_two_independent_factors_missing")
        try:
            observed = parse_instant(fields.get("observedAt"), "authentication.observedAt")
            maximum_age = timedelta(seconds=int(policy["maximumAuthenticationAgeSeconds"]))
            if observed > now.astimezone(timezone.utc) + timedelta(minutes=5):
                reasons.append("sca_authentication_in_future")
            elif now.astimezone(timezone.utc) - observed > maximum_age:
                reasons.append("sca_authentication_stale")
        except (KeyError, TypeError, ValueError, ValidationError):
            reasons.append("sca_authentication_time_invalid")
        try:
            receipt_digest, signer = verify_downstream_receipt(
                auth,
                trust,
                receipt_type="SCA_AUTHENTICATION",
                outcome="SUCCEEDED",
                fields=fields,
                required_role="sca_provider",
                require_independent=True,
                now=now,
            )
            if signer.identity != fields.get("provider"):
                reasons.append("sca_provider_identity_mismatch")
            checks.append(f"sca:provider_receipt:{receipt_digest}:{signer.identity}")
        except (ValidationError, TypeError, ValueError) as exc:
            reasons.append(f"sca_authentication_unverified:{exc}")
        checks.extend(("sca:provider_signature", "sca:two_factors", "sca:dynamic_link"))
    elif exemption is not None:
        item = require_mapping(exemption, "exemption")
        fields = require_mapping(item.get("fields"), "exemption.fields")
        kind = fields.get("type")
        exemptions = require_mapping(policy.get("exemptions"), "exemptions")
        configured = exemptions.get(kind)
        if not isinstance(configured, dict) or configured.get("enabled") is not True:
            reasons.append("sca_exemption_not_allowed")
        else:
            if fields.get("tenantId") != tenant_id or fields.get("transactionId") != transaction_id:
                reasons.append("sca_exemption_binding_mismatch")
            if fields.get("amountMinor") != amount or fields.get("currency") != currency \
                    or fields.get("payeeReference") != transaction.get("payeeReference"):
                reasons.append("sca_exemption_dynamic_link_mismatch")
            evidence_digest = fields.get("evidenceDigest")
            if not isinstance(evidence_digest, str) or not DIGEST.fullmatch(evidence_digest):
                reasons.append("sca_exemption_evidence_invalid")
            if configured.get("maximumAmountMinor") is not None and isinstance(amount, int) \
                    and amount > int(configured["maximumAmountMinor"]):
                reasons.append("sca_exemption_amount_exceeded")
            if configured.get("maximumCumulativeAmountMinor") is not None:
                cumulative = fields.get("cumulativeAmountMinor")
                if isinstance(cumulative, bool) or not isinstance(cumulative, int) \
                        or not isinstance(amount, int) or cumulative < amount \
                        or cumulative > int(configured["maximumCumulativeAmountMinor"]):
                    reasons.append("sca_exemption_cumulative_limit_exceeded")
            if configured.get("maximumConsecutiveTransactions") is not None:
                count = fields.get("consecutiveTransactions")
                if isinstance(count, bool) or not isinstance(count, int) or count < 1 \
                        or count > int(configured["maximumConsecutiveTransactions"]):
                    reasons.append("sca_exemption_count_exceeded")
            if configured.get("providerFraudRateEvidenceRequired") is True:
                fraud_digest = fields.get("providerFraudRateEvidenceDigest")
                if not isinstance(fraud_digest, str) or not DIGEST.fullmatch(fraud_digest):
                    reasons.append("sca_provider_fraud_rate_evidence_missing")
            if configured.get("providerManagedListRequired") is True:
                trusted_digest = fields.get("providerManagedListEvidenceDigest")
                if not isinstance(trusted_digest, str) or not DIGEST.fullmatch(trusted_digest):
                    reasons.append("sca_trusted_beneficiary_evidence_missing")
            if configured.get("initialScaMandateRequired") is True:
                mandate_id = fields.get("initialScaMandateId")
                mandate_digest = fields.get("initialScaEvidenceDigest")
                if not isinstance(mandate_id, str) or not mandate_id.strip() \
                        or not isinstance(mandate_digest, str) or not DIGEST.fullmatch(mandate_digest):
                    reasons.append("sca_initial_mandate_evidence_missing")
            try:
                observed = parse_instant(fields.get("observedAt"), "exemption.observedAt")
                if observed > now.astimezone(timezone.utc) + timedelta(minutes=5) \
                        or now.astimezone(timezone.utc) - observed > timedelta(minutes=5):
                    reasons.append("sca_exemption_evidence_stale")
            except ValidationError:
                reasons.append("sca_exemption_time_invalid")
            try:
                receipt_digest, signer = verify_downstream_receipt(
                    item,
                    trust,
                    receipt_type="SCA_EXEMPTION",
                    outcome="ACCEPTED",
                    fields=fields,
                    required_role="sca_provider",
                    require_independent=True,
                    now=now,
                )
                if signer.identity != fields.get("provider"):
                    reasons.append("sca_provider_identity_mismatch")
                checks.append(f"sca:exemption_receipt:{receipt_digest}:{signer.identity}")
            except (ValidationError, TypeError, ValueError) as exc:
                reasons.append(f"sca_exemption_provider_unverified:{exc}")
            checks.extend((f"sca:exemption:{kind}", "sca:provider_acceptance", "sca:evidence_digest"))
    else:
        reasons.append("sca_step_up_required")

    if transaction.get("clientDeclaredSuccess") is True and authentication is None:
        reasons.append("sca_client_success_not_authoritative")
    return GateReport.from_reasons(reasons, checks)


class SQLiteDeletionWorkflow:
    """Digest-bound, tenant-scoped, four-eyes deletion with backup expiry gate."""

    def __init__(self, path: str) -> None:
        self._db = sqlite3.connect(path, timeout=5, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS deletion_job (
              job_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, data_class TEXT NOT NULL,
              selection_digest TEXT NOT NULL, record_count INTEGER NOT NULL,
              proposer TEXT NOT NULL, approver TEXT, executor TEXT,
              state TEXT NOT NULL, legal_hold_clear INTEGER NOT NULL,
              execution_receipt TEXT, backup_receipt TEXT,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )"""
        )

    def close(self) -> None:
        self._db.close()

    def propose(
        self,
        policy: Mapping[str, Any],
        *,
        tenant_id: str,
        data_class: str,
        record_digests: list[str],
        legal_hold_clear: bool,
        proposer: str,
        now: datetime,
    ) -> str:
        classes = {item["name"]: item for item in require_list(policy.get("classes"), "classes")}
        if data_class not in classes:
            raise ValidationError("unknown data class")
        if not record_digests or any(not DIGEST.fullmatch(item) for item in record_digests):
            raise ValidationError("dry-run record digest set invalid")
        if len(record_digests) != len(set(record_digests)):
            raise ValidationError("dry-run contains duplicate records")
        if classes[data_class].get("legalHoldAware") is True and legal_hold_clear is not True:
            raise ValidationError("legal hold blocks deletion")
        selection = hashlib.sha256(canonical_json(sorted(record_digests))).hexdigest()
        job_id = hashlib.sha256(canonical_json({
            "tenant": tenant_id, "class": data_class, "selection": selection,
        })).hexdigest()
        instant = now.astimezone(timezone.utc).isoformat()
        self._db.execute(
            "INSERT INTO deletion_job VALUES(?,?,?,?,?,?,NULL,NULL,'PROPOSED',?,NULL,NULL,?,?)",
            (job_id, tenant_id, data_class, selection, len(record_digests), proposer,
             1 if legal_hold_clear else 0, instant, instant),
        )
        return job_id

    def approve(self, job_id: str, approver: str, now: datetime) -> None:
        row = self._db.execute("SELECT proposer,state FROM deletion_job WHERE job_id=?", (job_id,)).fetchone()
        if row is None or row[1] != "PROPOSED" or row[0] == approver:
            raise ValidationError("deletion approval violates four-eyes or state")
        self._db.execute(
            "UPDATE deletion_job SET approver=?,state='APPROVED',updated_at=? WHERE job_id=? AND state='PROPOSED'",
            (approver, now.astimezone(timezone.utc).isoformat(), job_id),
        )

    def execute(
        self,
        job_id: str,
        executor: str,
        delete: Callable[[str, str, str, str, int], tuple[int, str]],
        now: datetime,
    ) -> str:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute(
                "SELECT tenant_id,data_class,selection_digest,record_count,state,execution_receipt FROM deletion_job WHERE job_id=?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise ValidationError("deletion job missing")
            if row[4] == "BACKUP_EXPIRY_PENDING":
                self._db.execute("COMMIT")
                return str(row[5])
            if row[4] != "APPROVED":
                raise ValidationError("deletion job not approved or execution is unresolved")
            changed = self._db.execute(
                "UPDATE deletion_job SET executor=?,state='EXECUTING',updated_at=? WHERE job_id=? AND state='APPROVED'",
                (executor, now.astimezone(timezone.utc).isoformat(), job_id),
            ).rowcount
            if changed != 1:
                raise ValidationError("deletion execution claim conflict")
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        count, receipt = delete(job_id, str(row[0]), str(row[1]), str(row[2]), int(row[3]))
        if count != int(row[3]) or not require_text(receipt, "execution receipt"):
            raise ValidationError("deletion execution does not match dry-run")
        changed = self._db.execute(
            "UPDATE deletion_job SET state='BACKUP_EXPIRY_PENDING',execution_receipt=?,updated_at=? "
            "WHERE job_id=? AND state='EXECUTING'",
            (receipt, now.astimezone(timezone.utc).isoformat(), job_id),
        ).rowcount
        if changed != 1:
            raise ValidationError("deletion execution receipt conflict")
        return receipt

    def confirm_backup_expiry(
        self,
        job_id: str,
        verifier: str,
        verify: Callable[[str, str], str],
        now: datetime,
    ) -> None:
        row = self._db.execute(
            "SELECT proposer,approver,executor,state,execution_receipt FROM deletion_job WHERE job_id=?",
            (job_id,),
        ).fetchone()
        if row is None or row[3] != "BACKUP_EXPIRY_PENDING":
            raise ValidationError("backup expiry is not confirmable")
        if verifier in set(row[:3]):
            raise ValidationError("backup expiry verifier must be independent")
        execution_receipt = require_text(row[4], "deletion execution receipt")
        receipt = require_text(
            verify(job_id, execution_receipt), "backup expiry receipt"
        )
        self._db.execute(
            "UPDATE deletion_job SET state='COMPLETED',backup_receipt=?,updated_at=? WHERE job_id=?",
            (receipt, now.astimezone(timezone.utc).isoformat(), job_id),
        )


def evaluate_supply_chain(
    policy: Mapping[str, Any],
    statement: Mapping[str, Any],
    expected_artifact_digest: str,
    verify_signature: Callable[[Mapping[str, Any]], bool],
) -> GateReport:
    reasons: list[str] = []
    if not DIGEST.fullmatch(expected_artifact_digest):
        reasons.append("artifact_digest_invalid")
    if statement.get("artifactDigest") != expected_artifact_digest:
        reasons.append("provenance_subject_mismatch")
    for field in ("sbomDigest", "provenanceDigest"):
        value = statement.get(field)
        if not isinstance(value, str) or not DIGEST.fullmatch(value):
            reasons.append(f"{field}_invalid")
    if statement.get("dependenciesLocked") is not True:
        reasons.append("dependencies_not_locked")
    if statement.get("hermeticBuild") is not True:
        reasons.append("build_not_hermetic")
    if statement.get("sourceCommit") != statement.get("provenanceSourceCommit"):
        reasons.append("source_commit_not_bound")
    allowed_builders = set(require_list(policy.get("allowedBuilders"), "allowedBuilders"))
    if statement.get("builderId") not in allowed_builders:
        reasons.append("builder_not_trusted")
    if not verify_signature(statement):
        reasons.append("artifact_signature_unverified")
    required = set(require_list(policy.get("requiredMaterials"), "requiredMaterials"))
    supplied = set(require_list(statement.get("materials"), "materials"))
    for missing in sorted(required - supplied):
        reasons.append(f"provenance_material_missing:{missing}")
    return GateReport.from_reasons(reasons, ("sbom", "provenance", "signature", "locked_dependencies"))


def evaluate_vulnerability_exception(
    policy: Mapping[str, Any], exception: Mapping[str, Any], artifact_digest: str, *, now: datetime
) -> GateReport:
    reasons: list[str] = []
    controls = require_mapping(policy.get("exceptions"), "exceptions")
    if exception.get("artifactDigest") != artifact_digest or not DIGEST.fullmatch(artifact_digest):
        reasons.append("exception_artifact_mismatch")
    risk_owner = require_text(exception.get("riskOwner"), "riskOwner")
    security = require_text(exception.get("securityApprover"), "securityApprover")
    if risk_owner == security:
        reasons.append("exception_approvers_not_independent")
    if not require_list(exception.get("compensatingControls"), "compensatingControls"):
        reasons.append("exception_compensating_controls_missing")
    try:
        created = parse_instant(exception.get("createdAt"), "createdAt")
        expires = parse_instant(exception.get("expiresAt"), "expiresAt")
        if expires <= now.astimezone(timezone.utc):
            reasons.append("exception_expired")
        if expires - created > timedelta(days=int(controls["maximumDays"])):
            reasons.append("exception_duration_exceeded")
    except ValidationError:
        reasons.append("exception_time_invalid")
    if exception.get("status") != "APPROVED":
        reasons.append("exception_not_approved")
    return GateReport.from_reasons(reasons, ("risk_owner", "security_approver", "expiry", "compensating_controls"))
