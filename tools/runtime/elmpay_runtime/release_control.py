"""Durable signed Go/No-Go and staged rollout execution (B123-B124)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time
from typing import Any, Callable, Mapping

from .attestation import ConnectionNonceStore, nonce_store_from_trust, verify_dsse_record
from .capacity import evaluate_capacity
from .common import (
    GateReport,
    ValidationError,
    canonical_json,
    parse_instant,
    read_json,
    require_exact_keys,
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from .downstream_receipt import verify_downstream_receipt
from .durable import DurableStore
from .external_evidence import validate_external_evidence
from .oci import (
    ADMISSION_POLICY_PATH,
    PRODUCT_MANIFEST_PATH,
    validate_product_release_index,
)
from .release import release_binding, verify_release
from .rollout import compare_shadow, evaluate_canary


def _now(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValidationError("release control time must be timezone-aware")
    return current.astimezone(timezone.utc)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def rollout_target_digest(target: Mapping[str, Any]) -> str:
    required = ("tenantId", "projectId", "providerId", "region")
    normalized = {key: require_text(target.get(key), f"target.{key}") for key in required}
    return sha256_json(normalized)


class ReleaseControl:
    def __init__(
        self,
        database: str,
        trust: Mapping[str, Any],
        policy: Mapping[str, Any],
        release_policy: Mapping[str, Any],
        capacity_policy: Mapping[str, Any],
        external_evidence_policy: Mapping[str, Any],
        external_evidence_trust: Mapping[str, Any],
    ) -> None:
        self.store = DurableStore(database)
        self.trust = dict(trust)
        self.policy = dict(policy)
        self.release_policy = dict(release_policy)
        self.capacity_policy = dict(capacity_policy)
        self.external_evidence_policy = dict(external_evidence_policy)
        self.external_evidence_trust = dict(external_evidence_trust)
        self.nonces = nonce_store_from_trust(self.trust)

    def control_policy_document(self) -> dict[str, Any]:
        return {
            "rolloutPolicy": self.policy,
            "releasePolicy": self.release_policy,
            "capacityPolicy": self.capacity_policy,
            "externalEvidencePolicy": self.external_evidence_policy,
        }

    def control_policy_digest(self) -> str:
        """Bind every repository-side input that changes a Go/No-Go result.

        Trust roots remain live so revocation takes effect immediately. The
        gate and rollout policies are immutable signed decision inputs and
        cannot drift between approval and execution.
        """

        return sha256_json(self.control_policy_document())

    def _nonce_store_for_transaction(self, connection: Any) -> Any:
        replay_database = self.nonces.database
        control_database = self.store.database
        same_database = replay_database == control_database
        if not same_database and not (
            replay_database.startswith("file:") or control_database.startswith("file:")
        ):
            same_database = Path(replay_database).resolve() == Path(
                control_database
            ).resolve()
        return ConnectionNonceStore(connection) if same_database else self.nonces

    def evaluate_gates(
        self,
        target: Mapping[str, Any],
        gate_inputs: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> tuple[str, dict[str, GateReport]]:
        """Recompute every Go/No-Go gate from bound raw inputs.

        Caller-created ``GateReport`` objects are deliberately not accepted.
        The operations observation is the one non-local fact and therefore has
        to be an independently signed, replay-protected downstream receipt.
        """

        current = _now(now)
        inputs = require_mapping(gate_inputs, "Go/No-Go inputs")
        required = {
            "releaseManifest", "shadowBaseline", "shadowCandidate",
            "canaryBaseline", "canaryCandidate", "capacitySamples",
            "operationsReceipt", "externalEvidenceBundle", "productImageIndex",
        }
        require_exact_keys(inputs, required=required, optional=set(), field="Go/No-Go inputs")
        manifest = require_mapping(inputs["releaseManifest"], "release manifest")
        binding = release_binding(manifest)
        target_digest = rollout_target_digest(target)

        release_report = verify_release(
            manifest, self.release_policy, self.trust, now=current
        )
        product_index = require_mapping(inputs["productImageIndex"], "product image index")
        product_index_reasons: list[str] = []
        try:
            validate_product_release_index(
                require_mapping(
                    read_json(REPOSITORY_ROOT / PRODUCT_MANIFEST_PATH),
                    "governed product image manifest",
                ),
                require_mapping(
                    read_json(REPOSITORY_ROOT / ADMISSION_POLICY_PATH),
                    "governed image admission policy",
                ),
                product_index,
                manifest,
            )
        except ValidationError as exc:
            product_index_reasons.append(f"product_image_index_invalid:{exc}")
        release_report = GateReport.from_reasons(
            (*release_report.reasons, *product_index_reasons),
            (
                *release_report.checks,
                f"release_manifest_digest:{sha256_json(manifest)}",
                f"product_image_index_digest:{sha256_json(product_index)}",
            ),
        )
        shadow = compare_shadow(
            require_list(inputs["shadowBaseline"], "shadow baseline"),
            require_list(inputs["shadowCandidate"], "shadow candidate"),
        )
        shadow_reasons = [
            *(f"mismatch:{item}" for item in shadow.mismatches),
            *(f"missing_baseline:{item}" for item in shadow.missing_baseline),
            *(f"missing_candidate:{item}" for item in shadow.missing_candidate),
            *(f"candidate_side_effect:{item}" for item in shadow.candidate_side_effects),
        ]
        shadow_report = GateReport.from_reasons(
            shadow_reasons, (
                f"shadow_compared:{shadow.compared}",
                f"shadow_inputs_digest:{sha256_json({'baseline': inputs['shadowBaseline'], 'candidate': inputs['shadowCandidate']})}",
            )
        )
        canary_report = evaluate_canary(
            require_mapping(inputs["canaryBaseline"], "canary baseline"),
            require_mapping(inputs["canaryCandidate"], "canary candidate"),
            self.policy,
        )
        canary_report = GateReport.from_reasons(
            canary_report.reasons,
            (*canary_report.checks, f"canary_inputs_digest:{sha256_json({'baseline': inputs['canaryBaseline'], 'candidate': inputs['canaryCandidate']})}"),
        )
        capacity_report = evaluate_capacity(
            self.capacity_policy,
            require_mapping(inputs["capacitySamples"], "capacity samples"),
        ).report
        capacity_report = GateReport.from_reasons(
            capacity_report.reasons,
            (*capacity_report.checks, f"capacity_inputs_digest:{sha256_json(inputs['capacitySamples'])}"),
        )

        operation_receipt = require_mapping(inputs["operationsReceipt"], "operations receipt")
        operation_fields = require_mapping(operation_receipt.get("fields"), "operations receipt fields")
        required_operation_fields = {
            "releaseBindingDigest", "targetDigest", "rollbackTestPassed",
            "gitopsDriftCount", "openCriticalIncidents",
        }
        require_exact_keys(
            operation_fields, required=required_operation_fields, optional=set(),
            field="operations receipt fields",
        )
        if operation_fields.get("releaseBindingDigest") != binding \
                or operation_fields.get("targetDigest") != target_digest:
            raise ValidationError("operations receipt release target mismatch")
        operations_receipt_digest, operations_signer = verify_downstream_receipt(
            operation_receipt,
            self.trust,
            receipt_type="RELEASE_OPERATIONS",
            outcome="VERIFIED",
            fields=operation_fields,
            required_role="operations_verifier",
            require_independent=True,
            now=current,
        )
        go_no_go = require_mapping(self.policy.get("goNoGo"), "goNoGo")
        operations_reasons: list[str] = []
        if operation_fields.get("rollbackTestPassed") is not True:
            operations_reasons.append("rollback_test_not_passed")
        drift = operation_fields.get("gitopsDriftCount")
        incidents = operation_fields.get("openCriticalIncidents")
        if isinstance(drift, bool) or not isinstance(drift, int) or drift != 0:
            operations_reasons.append("gitops_drift_present")
        if isinstance(incidents, bool) or not isinstance(incidents, int) \
                or incidents != go_no_go.get("requireOpenCriticalIncidents"):
            operations_reasons.append("critical_incidents_open")
        operations_report = GateReport.from_reasons(
            operations_reasons, (
                f"operations_signer:{operations_signer.identity}",
                f"operations_receipt_digest:{operations_receipt_digest}",
            )
        )
        artifact_digest = require_text(manifest.get("artifactDigest"), "artifactDigest")
        release_images = require_mapping(manifest.get("images"), "release images")
        external_report = validate_external_evidence(
            self.external_evidence_policy,
            require_mapping(inputs["externalEvidenceBundle"], "external evidence bundle"),
            self.external_evidence_trust,
            now=current,
            expected_binding=binding,
            expected_tenant_id=require_text(target.get("tenantId"), "target.tenantId"),
            expected_artifact_digest=artifact_digest,
            expected_target_digest=target_digest,
            expected_region=require_text(target.get("region"), "target.region"),
            expected_images={
                require_text(name, "release image name"): require_text(reference, "release image")
                for name, reference in release_images.items()
            },
            expected_admission_policy_digest=require_text(
                manifest.get("imageAdmissionPolicyDigest"), "imageAdmissionPolicyDigest"
            ),
            expected_commit_sha=require_text(manifest.get("commitSha"), "commitSha"),
        )
        external_report = GateReport.from_reasons(
            external_report.reasons,
            (*external_report.checks,
             f"external_evidence_bundle_digest:{sha256_json(inputs['externalEvidenceBundle'])}"),
        )
        return binding, {
            "release": release_report,
            "shadow": shadow_report,
            "canary": canary_report,
            "capacity": capacity_report,
            "operations": operations_report,
            "external_evidence": external_report,
        }

    def record_go_no_go(
        self,
        signed_decision: Mapping[str, Any],
        target: Mapping[str, Any],
        gate_inputs: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        record = require_mapping(signed_decision, "signed decision")
        inputs = require_mapping(gate_inputs, "Go/No-Go inputs")
        binding, evaluated_gates = self.evaluate_gates(target, inputs, now=current)
        if record.get("bindingDigest") != binding:
            raise ValidationError("signed decision release binding mismatch")
        target_digest = rollout_target_digest(target)
        if record.get("targetDigest") != target_digest:
            raise ValidationError("signed decision target mismatch")
        signer = verify_dsse_record(record, self.trust, binding, now=current, nonce_store=self.nonces)
        if signer.role != "release_manager":
            raise ValidationError("Go/No-Go signer must have release_manager role")
        other_control_actors: set[str] = set()
        for report in evaluated_gates.values():
            for check in report.checks:
                if check.startswith("operations_signer:"):
                    other_control_actors.add(check.split(":", 1)[1])
                elif check.startswith("external_evidence:"):
                    # Preserve ':' inside a verifier identity.
                    components = check.split(":", 2)
                    if len(components) == 3:
                        other_control_actors.add(components[2])
        if signer.identity in other_control_actors:
            raise ValidationError(
                "Go/No-Go release manager must be distinct from evidence verifiers"
            )
        required_approvers = require_mapping(
            self.policy.get("goNoGo"), "goNoGo"
        ).get("distinctApprovers")
        if (
            isinstance(required_approvers, bool)
            or not isinstance(required_approvers, int)
            or required_approvers < 2
            or len({signer.identity, *other_control_actors}) < required_approvers
        ):
            raise ValidationError("Go/No-Go distinct approver policy is not satisfied")
        required = {"release", "shadow", "canary", "capacity", "operations", "external_evidence"}
        failed = sorted(name for name in required if not evaluated_gates[name].allowed)
        expected_decision = "GO" if not failed else "NO_GO"
        if record.get("decision") != expected_decision:
            raise ValidationError("signed Go/No-Go decision contradicts evaluated gates")
        gate_document = {
            name: {
                "allowed": evaluated_gates[name].allowed,
                "reasons": list(evaluated_gates[name].reasons),
                "checks": list(evaluated_gates[name].checks),
            }
            for name in sorted(required)
        }
        gate_digest = sha256_json(gate_document)
        if record.get("gateDigest") != gate_digest:
            raise ValidationError("signed Go/No-Go gate digest mismatch")
        gate_inputs_digest = sha256_json(inputs)
        if record.get("gateInputsDigest") != gate_inputs_digest:
            raise ValidationError("signed Go/No-Go input digest mismatch")
        control_policy_digest = self.control_policy_digest()
        if record.get("controlPolicyDigest") != control_policy_digest:
            raise ValidationError("signed Go/No-Go control policy digest mismatch")
        decision_id = require_text(record.get("decisionId"), "decision.decisionId")
        decided_at = parse_instant(record.get("issuedAt"), "decision.issuedAt").isoformat()
        encoded = canonical_json(record).decode()
        manifest = require_mapping(inputs.get("releaseManifest"), "release manifest")
        external_evidence = require_mapping(
            inputs.get("externalEvidenceBundle"), "external evidence bundle"
        )
        artifact_digest = require_text(manifest.get("artifactDigest"), "artifactDigest")
        manifest_encoded = canonical_json(manifest).decode()
        external_evidence_encoded = canonical_json(external_evidence).decode()
        gate_inputs_encoded = canonical_json(inputs).decode()
        with self.store.transaction() as connection:
            prior = connection.execute("SELECT signed_record_json FROM release_decision WHERE decision_id=?", (decision_id,)).fetchone()
            if prior:
                if prior["signed_record_json"] != encoded:
                    raise ValidationError("immutable Go/No-Go decision id collision")
            else:
                connection.execute(
                    "INSERT INTO release_decision(decision_id,release_binding_digest,"
                    "target_digest,decision,gate_digest,signed_record_json,decided_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (decision_id, binding, target_digest, expected_decision, gate_digest,
                     encoded, decided_at),
                )
            material = connection.execute(
                "SELECT artifact_digest,release_manifest_json,external_evidence_json "
                "FROM release_decision_material WHERE decision_id=?",
                (decision_id,),
            ).fetchone()
            intended_material = (
                artifact_digest, manifest_encoded, external_evidence_encoded,
            )
            if material and tuple(material) != intended_material:
                raise ValidationError("immutable Go/No-Go release material collision")
            if not material:
                connection.execute(
                    "INSERT INTO release_decision_material(decision_id,artifact_digest,"
                    "release_manifest_json,external_evidence_json) VALUES(?,?,?,?)",
                    (decision_id, *intended_material),
                )
            input_material = connection.execute(
                "SELECT gate_inputs_digest,gate_inputs_json "
                "FROM release_decision_gate_input WHERE decision_id=?",
                (decision_id,),
            ).fetchone()
            intended_input = (gate_inputs_digest, gate_inputs_encoded)
            if input_material and tuple(input_material) != intended_input:
                raise ValidationError("immutable Go/No-Go gate input collision")
            if not input_material:
                connection.execute(
                    "INSERT INTO release_decision_gate_input VALUES(?,?,?)",
                    (decision_id, *intended_input),
                )
        return {
            "decisionId": decision_id,
            "decision": expected_decision,
            "bindingDigest": binding,
            "targetDigest": target_digest,
            "controlPolicyDigest": control_policy_digest,
            "failedGates": failed,
            "signer": signer.identity,
        }

    def start_rollout(
        self,
        rollout_id: str,
        release_binding_digest: str,
        target: Mapping[str, Any],
        artifact_digest: str,
        previous_artifact_digest: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        target_digest = rollout_target_digest(target)
        for label, digest in (("artifact", artifact_digest), ("previous artifact", previous_artifact_digest)):
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValidationError(f"{label} digest must be SHA-256")
        stages = require_list(self.policy.get("stages"), "rollout stages")
        if not stages:
            raise ValidationError("rollout policy has no stages")
        approved_query = (
            "SELECT d.decision_id,d.decision,d.signed_record_json,d.decided_at,"
            "m.artifact_digest,m.release_manifest_json,m.external_evidence_json,"
            "g.gate_inputs_digest,g.gate_inputs_json "
            "FROM release_decision d LEFT JOIN release_decision_material m "
            "ON m.decision_id=d.decision_id "
            "LEFT JOIN release_decision_gate_input g ON g.decision_id=d.decision_id "
            "WHERE d.release_binding_digest=? "
            "AND d.target_digest=? ORDER BY d.decided_at DESC,d.decision_id DESC LIMIT 1"
        )
        with self.store.connect() as connection:
            approved = connection.execute(
                approved_query,
                (release_binding_digest, target_digest),
            ).fetchone()
        if not approved or approved["decision"] != "GO":
            raise ValidationError("signed GO decision for exact release target is required")
        try:
            signed_go = require_mapping(
                json.loads(approved["signed_record_json"]), "stored signed GO decision"
            )
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValidationError("stored signed GO decision is invalid") from exc
        if (
            signed_go.get("decisionId") != approved["decision_id"]
            or signed_go.get("decision") != "GO"
            or signed_go.get("targetDigest") != target_digest
        ):
            raise ValidationError("stored GO decision fields do not match signed record")
        signer = verify_dsse_record(
            signed_go, self.trust,
            release_binding_digest, now=current, nonce_store=self.nonces,
        )
        if signer.role != "release_manager":
            raise ValidationError("stored GO decision signer is not a release_manager")
        control_policy_digest = self.control_policy_digest()
        if signed_go.get("controlPolicyDigest") != control_policy_digest:
            raise ValidationError("stored GO decision control policy binding mismatch")
        go_no_go = require_mapping(self.policy.get("goNoGo"), "goNoGo")
        maximum_age_hours = go_no_go.get("approvalMaximumAgeHours")
        if (
            isinstance(maximum_age_hours, bool)
            or not isinstance(maximum_age_hours, int)
            or maximum_age_hours <= 0
        ):
            raise ValidationError("Go/No-Go maximum decision age policy is invalid")
        decided_at = parse_instant(signed_go.get("issuedAt"), "decision.issuedAt")
        if parse_instant(approved["decided_at"], "decision.decidedAt") != decided_at:
            raise ValidationError("stored GO decision time does not match signed record")
        if decided_at > current + timedelta(minutes=5):
            raise ValidationError("stored GO decision is dated in the future")
        if current - decided_at > timedelta(hours=maximum_age_hours):
            raise ValidationError("stored GO decision exceeded maximum age")
        if not all(
            approved[name]
            for name in (
                "artifact_digest", "release_manifest_json", "external_evidence_json",
                "gate_inputs_digest", "gate_inputs_json",
            )
        ):
            raise ValidationError("stored GO decision is missing release material")
        try:
            manifest = require_mapping(
                json.loads(approved["release_manifest_json"]), "stored release manifest"
            )
            external_evidence = require_mapping(
                json.loads(approved["external_evidence_json"]),
                "stored external evidence bundle",
            )
            stored_gate_inputs = require_mapping(
                json.loads(approved["gate_inputs_json"]), "stored Go/No-Go inputs"
            )
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValidationError("stored GO release material is invalid") from exc
        if sha256_json(stored_gate_inputs) != approved["gate_inputs_digest"]:
            raise ValidationError("stored Go/No-Go input digest mismatch")
        if signed_go.get("gateInputsDigest") != approved["gate_inputs_digest"]:
            raise ValidationError("signed Go/No-Go input binding mismatch")
        reevaluated_binding, reevaluated = self.evaluate_gates(
            target, stored_gate_inputs, now=current
        )
        reevaluated_document = {
            name: {
                "allowed": report.allowed,
                "reasons": list(report.reasons),
                "checks": list(report.checks),
            }
            for name, report in sorted(reevaluated.items())
        }
        if (
            reevaluated_binding != release_binding_digest
            or not all(report.allowed for report in reevaluated.values())
            or signed_go.get("gateDigest") != sha256_json(reevaluated_document)
        ):
            raise ValidationError(
                "external release evidence or stored Go/No-Go gates no longer authorize rollout"
            )
        if release_binding(manifest) != release_binding_digest:
            raise ValidationError("stored release manifest binding mismatch")
        manifest_artifact = require_text(
            manifest.get("artifactDigest"), "stored manifest artifactDigest"
        )
        if approved["artifact_digest"] != manifest_artifact:
            raise ValidationError("stored GO artifact binding mismatch")
        if artifact_digest != manifest_artifact:
            raise ValidationError("rollout artifact does not match signed GO manifest")
        release_report = verify_release(
            manifest, self.release_policy, self.trust, now=current
        )
        if not release_report.allowed:
            raise ValidationError(
                "signed release manifest is no longer valid: "
                + ",".join(release_report.reasons)
            )
        external_report = validate_external_evidence(
            self.external_evidence_policy,
            external_evidence,
            self.external_evidence_trust,
            now=current,
            expected_binding=release_binding_digest,
            expected_tenant_id=require_text(target.get("tenantId"), "target.tenantId"),
            expected_artifact_digest=manifest_artifact,
            expected_target_digest=target_digest,
            expected_region=require_text(target.get("region"), "target.region"),
            expected_images={
                require_text(name, "release image name"): require_text(reference, "release image")
                for name, reference in require_mapping(
                    manifest.get("images"), "stored release images"
                ).items()
            },
            expected_admission_policy_digest=require_text(
                manifest.get("imageAdmissionPolicyDigest"), "imageAdmissionPolicyDigest"
            ),
            expected_commit_sha=require_text(manifest.get("commitSha"), "commitSha"),
        )
        if not external_report.allowed:
            raise ValidationError(
                "external release evidence is no longer valid: "
                + ",".join(external_report.reasons)
            )
        with self.store.transaction() as connection:
            latest = connection.execute(
                approved_query, (release_binding_digest, target_digest)
            ).fetchone()
            if (
                not latest
                or latest["decision"] != "GO"
                or latest["decision_id"] != approved["decision_id"]
                or any(
                    latest[name] != approved[name]
                    for name in (
                        "signed_record_json", "decided_at", "artifact_digest",
                        "release_manifest_json", "external_evidence_json",
                        "gate_inputs_digest", "gate_inputs_json",
                    )
                )
            ):
                raise ValidationError("GO decision changed during rollout authorization")
            intended = (
                release_binding_digest, target_digest, target["tenantId"],
                target["projectId"], target["providerId"], target["region"],
                artifact_digest, previous_artifact_digest,
            )
            prior_rollout = connection.execute(
                "SELECT release_binding_digest,target_digest,tenant_id,project_id,"
                "provider_id,region,artifact_digest,previous_artifact_digest,"
                "stage_index,status,fence_token FROM rollout_execution WHERE rollout_id=?",
                (rollout_id,),
            ).fetchone()
            policy_encoded = canonical_json(self.control_policy_document()).decode()
            rollout_policy_digest = sha256_json(self.policy)
            policy_binding = connection.execute(
                "SELECT decision_id,control_policy_digest,rollout_policy_digest,"
                "control_policy_json FROM rollout_policy_binding WHERE rollout_id=?",
                (rollout_id,),
            ).fetchone()
            intended_policy_binding = (
                approved["decision_id"], control_policy_digest,
                rollout_policy_digest, policy_encoded,
            )
            if prior_rollout:
                if tuple(prior_rollout)[:8] != intended:
                    raise ValidationError("immutable rollout id collision")
                if not policy_binding or tuple(policy_binding) != intended_policy_binding:
                    raise ValidationError(
                        "immutable rollout policy binding is missing or changed"
                    )
                return {
                    "rolloutId": rollout_id,
                    "stage": stages[prior_rollout["stage_index"]]["name"],
                    "trafficPercent": stages[prior_rollout["stage_index"]]["trafficPercent"],
                    "status": prior_rollout["status"],
                    "fenceToken": prior_rollout["fence_token"],
                }
            connection.execute(
                "INSERT INTO rollout_execution VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rollout_id, *intended, 0, current.isoformat(), "RUNNING", 1),
            )
            connection.execute(
                "INSERT INTO rollout_policy_binding VALUES(?,?,?,?,?)",
                (rollout_id, *intended_policy_binding),
            )
        return {"rolloutId": rollout_id, "stage": stages[0]["name"], "trafficPercent": stages[0]["trafficPercent"], "fenceToken": 1}

    def observe_and_advance(
        self,
        rollout_id: str,
        signed_observation: Mapping[str, Any],
        baseline_metrics: Mapping[str, Any],
        candidate_metrics: Mapping[str, Any],
        rollback_adapter: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        signed_stage_approval: Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        with self.store.transaction() as connection:
            rollout = connection.execute(
                "SELECT * FROM rollout_execution WHERE rollout_id=?", (rollout_id,)
            ).fetchone()
            if not rollout or rollout["status"] != "RUNNING":
                raise ValidationError("rollout is not running")
            policy_binding = connection.execute(
                "SELECT control_policy_digest,rollout_policy_digest,control_policy_json "
                "FROM rollout_policy_binding WHERE rollout_id=?",
                (rollout_id,),
            ).fetchone()
            if not policy_binding:
                raise ValidationError("rollout policy binding is missing")
            try:
                bound_control_policy = require_mapping(
                    json.loads(policy_binding["control_policy_json"]),
                    "stored control policy",
                )
            except (json.JSONDecodeError, TypeError) as exc:
                raise ValidationError("stored control policy is invalid") from exc
            if sha256_json(bound_control_policy) != policy_binding["control_policy_digest"]:
                raise ValidationError("stored control policy digest mismatch")
            bound_policy = require_mapping(
                bound_control_policy.get("rolloutPolicy"), "stored rollout policy"
            )
            if sha256_json(bound_policy) != policy_binding["rollout_policy_digest"]:
                raise ValidationError("stored rollout policy digest mismatch")
            stages = require_list(bound_policy.get("stages"), "rollout stages")
            if not stages or not 0 <= rollout["stage_index"] < len(stages):
                raise ValidationError("stored rollout stage is outside the bound policy")
            transaction_nonces = self._nonce_store_for_transaction(connection)
            observation = require_mapping(signed_observation, "signed observation")
            signer = verify_dsse_record(
                observation, self.trust, rollout["release_binding_digest"],
                now=current, nonce_store=transaction_nonces,
            )
            if signer.role != "rollout_observer" or not signer.independent:
                raise ValidationError(
                    "rollout observation requires an independent rollout_observer"
                )
            if (
                observation.get("targetDigest") != rollout["target_digest"]
                or observation.get("rolloutId") != rollout_id
                or observation.get("fenceToken") != rollout["fence_token"]
            ):
                raise ValidationError("rollout observation target or fence mismatch")
            stage = require_mapping(stages[rollout["stage_index"]], "stage")
            if (
                observation.get("stage") != stage.get("name")
                or observation.get("trafficPercent") != stage.get("trafficPercent")
            ):
                raise ValidationError("rollout observation stage binding mismatch")
            stage_approval: Mapping[str, Any] | None = None
            if stage.get("requiresApproval") is True:
                if signed_stage_approval is None:
                    raise ValidationError("signed stage approval is required")
                stage_approval = require_mapping(
                    signed_stage_approval, "signed stage approval"
                )
                approver = verify_dsse_record(
                    stage_approval, self.trust, rollout["release_binding_digest"],
                    now=current, nonce_store=transaction_nonces,
                )
                if approver.role != "release_manager" or approver.identity == signer.identity:
                    raise ValidationError(
                        "stage approval requires a distinct release_manager"
                    )
                if (
                    stage_approval.get("targetDigest") != rollout["target_digest"]
                    or stage_approval.get("rolloutId") != rollout_id
                    or stage_approval.get("stage") != stage.get("name")
                    or stage_approval.get("decision") != "APPROVE"
                    or stage_approval.get("fenceToken") != rollout["fence_token"]
                ):
                    raise ValidationError("stage approval binding mismatch")
            metrics_doc = {
                "baseline": dict(baseline_metrics),
                "candidate": dict(candidate_metrics),
            }
            if observation.get("metricsDigest") != sha256_json(metrics_doc):
                raise ValidationError("rollout observation metrics digest mismatch")
            observed_at = parse_instant(
                observation.get("observedAt"), "observation.observedAt"
            )
            if observed_at > current:
                raise ValidationError("rollout observation cannot be in the future")
            started_at = parse_instant(
                rollout["stage_started_at"], "rollout.stage_started_at"
            )
            minimum = stage.get("minimumMinutes")
            if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
                raise ValidationError("rollout minimumMinutes is invalid")
            if observed_at < started_at + timedelta(minutes=minimum):
                raise ValidationError("rollout observation window is incomplete")
            report = evaluate_canary(baseline_metrics, candidate_metrics, bound_policy)
            if (
                stage.get("requiresDiffPass") is True
                and observation.get("shadowDiffPassed") is not True
            ):
                report = GateReport.from_reasons(
                    [*report.reasons, "shadow_diff_not_passed"], report.checks
                )
            observation_id = require_text(
                observation.get("observationId"), "observation.observationId"
            )
            signed_records = {
                "observation": dict(observation),
                "stageApproval": (
                    dict(stage_approval) if stage_approval is not None else None
                ),
            }
            if report.allowed:
                if rollout["stage_index"] + 1 >= len(stages):
                    status = "COMPLETE"
                    next_index = rollout["stage_index"]
                else:
                    status = "RUNNING"
                    next_index = rollout["stage_index"] + 1
                connection.execute(
                    "INSERT INTO rollout_observation VALUES(?,?,?,?,?,?,?)",
                    (
                        rollout_id, observation_id, stage["name"],
                        observed_at.isoformat(), observation["metricsDigest"],
                        canonical_json(signed_records).decode(), "PASS",
                    ),
                )
                connection.execute(
                    "UPDATE rollout_execution SET stage_index=?,stage_started_at=?,"
                    "status=?,fence_token=fence_token+1 WHERE rollout_id=? "
                    "AND status='RUNNING' AND fence_token=?",
                    (
                        next_index, current.isoformat(), status, rollout_id,
                        rollout["fence_token"],
                    ),
                )
                return {
                    "rolloutId": rollout_id, "decision": "PASS", "status": status,
                    "stage": stages[next_index]["name"], "reasons": [],
                    "signer": signer.identity,
                }

            operation_id = sha256_json({
                "operation": "ROLLOUT_ROLLBACK",
                "rolloutId": rollout_id,
                "releaseBindingDigest": rollout["release_binding_digest"],
                "targetDigest": rollout["target_digest"],
                "artifactDigest": rollout["artifact_digest"],
                "previousArtifactDigest": rollout["previous_artifact_digest"],
            })
            command = {
                "operationId": operation_id,
                "rolloutId": rollout_id,
                "tenantId": rollout["tenant_id"],
                "releaseBindingDigest": rollout["release_binding_digest"],
                "targetDigest": rollout["target_digest"],
                "artifactDigest": rollout["artifact_digest"],
                "previousArtifactDigest": rollout["previous_artifact_digest"],
                "fenceToken": rollout["fence_token"],
            }
            command["idempotencyKey"] = sha256_json(command)
            request_digest = sha256_json(command)
            prior = connection.execute(
                "SELECT * FROM rollout_rollback_operation WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if prior:
                if (
                    prior["request_digest"] != request_digest
                    or prior["rollout_id"] != rollout_id
                    or prior["fence_token"] != rollout["fence_token"]
                ):
                    raise ValidationError("immutable rollout rollback operation collision")
                raise ValidationError(
                    "rollout rollback already dispatched; reconciliation is required"
                )
            lease_owner = f"rollout:{rollout_id}"
            lease_until = current + timedelta(minutes=2)
            rollback_records = {**signed_records, "rollbackCommand": command}
            connection.execute(
                "INSERT INTO rollout_rollback_operation VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    operation_id, rollout_id, rollout["tenant_id"],
                    rollout["release_binding_digest"], rollout["target_digest"],
                    rollout["artifact_digest"], rollout["previous_artifact_digest"],
                    observation_id, stage["name"], observed_at.isoformat(),
                    observation["metricsDigest"], request_digest,
                    command["idempotencyKey"], rollout["fence_token"], "IN_FLIGHT",
                    lease_owner, lease_until.isoformat(),
                    canonical_json(rollback_records).decode(), None, None,
                    current.isoformat(),
                ),
            )
            changed = connection.execute(
                "UPDATE rollout_execution SET status='ROLLBACK_IN_FLIGHT' "
                "WHERE rollout_id=? AND status='RUNNING' AND fence_token=?",
                (rollout_id, rollout["fence_token"]),
            ).rowcount
            if changed != 1:
                raise ValidationError("rollout rollback pre-dispatch fencing failed")

        dispatch_started = time.monotonic()
        try:
            raw_result = require_mapping(
                rollback_adapter({**command, "mode": "ROLLBACK"}),
                "rollout rollback adapter result",
            )
            receipt = require_mapping(
                raw_result.get("receipt"), "rollout rollback receipt"
            )
            completed = current + timedelta(
                seconds=max(0.0, time.monotonic() - dispatch_started)
            )
            receipt_digest = self._verify_rollback_receipt(receipt, command, completed)
            self._complete_rollback(
                operation_id, command, receipt, receipt_digest, completed,
                lease_owner,
            )
        except BaseException as exc:
            failed_at = current + timedelta(
                seconds=max(0.0, time.monotonic() - dispatch_started)
            )
            self._mark_rollback_unknown(
                operation_id, command, failed_at, lease_owner
            )
            raise ValidationError(
                "rollout rollback outcome is UNKNOWN; reconcile before any further rollout"
            ) from exc
        return {
            "rolloutId": rollout_id, "decision": "ROLLBACK",
            "status": "ROLLED_BACK", "stage": stage["name"],
            "reasons": list(report.reasons), "signer": signer.identity,
            "operationId": operation_id, "receiptDigest": receipt_digest,
        }

    def reconcile_rollback(
        self,
        rollout_id: str,
        rollback_adapter: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Resolve UNKNOWN/expired IN_FLIGHT via a signed adapter lookup receipt."""

        current = _now(now)
        with self.store.transaction() as connection:
            operation = connection.execute(
                "SELECT * FROM rollout_rollback_operation WHERE rollout_id=?",
                (rollout_id,),
            ).fetchone()
            if not operation or operation["status"] not in {
                "IN_FLIGHT", "UNKNOWN", "SUCCEEDED",
            }:
                raise ValidationError("rollout has no unresolved rollback to reconcile")
            command = {
                "operationId": operation["operation_id"],
                "rolloutId": rollout_id,
                "tenantId": operation["tenant_id"],
                "releaseBindingDigest": operation["release_binding_digest"],
                "targetDigest": operation["target_digest"],
                "artifactDigest": operation["artifact_digest"],
                "previousArtifactDigest": operation["previous_artifact_digest"],
                "fenceToken": operation["fence_token"],
                "idempotencyKey": operation["idempotency_key"],
            }
            if sha256_json(command) != operation["request_digest"]:
                raise ValidationError("stored rollout rollback command digest mismatch")
            if operation["status"] == "SUCCEEDED":
                if not operation["receipt_json"] or not operation["receipt_digest"]:
                    raise ValidationError("completed rollout rollback receipt is missing")
                try:
                    stored_receipt = require_mapping(
                        json.loads(operation["receipt_json"]),
                        "stored rollout rollback receipt",
                    )
                except (json.JSONDecodeError, TypeError) as exc:
                    raise ValidationError(
                        "completed rollout rollback receipt is corrupt"
                    ) from exc
                if sha256_json(stored_receipt) != operation["receipt_digest"]:
                    raise ValidationError(
                        "completed rollout rollback receipt digest mismatch"
                    )
                verified_at = parse_instant(
                    operation["updated_at"], "completed rollback time"
                )
                if self._verify_rollback_receipt(
                    stored_receipt, command, verified_at
                ) != operation["receipt_digest"]:
                    raise ValidationError(
                        "completed rollout rollback receipt verification mismatch"
                    )
                return {
                    "rolloutId": rollout_id, "status": "ROLLED_BACK",
                    "decision": "ROLLBACK",
                    "operationId": operation["operation_id"],
                    "receiptDigest": operation["receipt_digest"],
                    "duplicate": True,
                }
            if (
                operation["status"] == "IN_FLIGHT"
                and parse_instant(operation["lease_until"], "rollback lease") > current
            ):
                raise ValidationError("rollout rollback dispatch lease is still active")
            lease_until = current + timedelta(minutes=2)
            reconcile_owner = f"reconcile:{rollout_id}:{current.isoformat()}"
            changed = connection.execute(
                "UPDATE rollout_rollback_operation SET status='IN_FLIGHT',"
                "lease_owner=?,lease_until=?,updated_at=? WHERE operation_id=? "
                "AND status IN ('IN_FLIGHT','UNKNOWN') AND fence_token=?",
                (
                    reconcile_owner, lease_until.isoformat(),
                    current.isoformat(), operation["operation_id"],
                    operation["fence_token"],
                ),
            ).rowcount
            if changed != 1:
                raise ValidationError("rollout rollback reconciliation lease was lost")
        reconcile_started = time.monotonic()
        try:
            raw_result = require_mapping(
                rollback_adapter({**command, "mode": "RECONCILE"}),
                "rollout rollback reconciliation result",
            )
            receipt = require_mapping(
                raw_result.get("receipt"), "rollout rollback receipt"
            )
            completed = current + timedelta(
                seconds=max(0.0, time.monotonic() - reconcile_started)
            )
            receipt_digest = self._verify_rollback_receipt(receipt, command, completed)
            self._complete_rollback(
                operation["operation_id"], command, receipt, receipt_digest,
                completed, reconcile_owner,
            )
        except BaseException as exc:
            failed_at = current + timedelta(
                seconds=max(0.0, time.monotonic() - reconcile_started)
            )
            self._mark_rollback_unknown(
                operation["operation_id"], command, failed_at, reconcile_owner
            )
            raise ValidationError("rollout rollback remains UNKNOWN") from exc
        return {
            "rolloutId": rollout_id, "status": "ROLLED_BACK",
            "decision": "ROLLBACK", "operationId": operation["operation_id"],
            "receiptDigest": receipt_digest,
        }

    def _verify_rollback_receipt(
        self,
        receipt: Mapping[str, Any],
        command: Mapping[str, Any],
        now: datetime,
    ) -> str:
        digest, _signer = verify_downstream_receipt(
            receipt,
            self.trust,
            receipt_type="ROLLOUT_ROLLBACK",
            outcome="ROLLED_BACK",
            fields=command,
            required_role="rollout_rollback_executor",
            now=now,
        )
        return digest

    def _complete_rollback(
        self,
        operation_id: str,
        command: Mapping[str, Any],
        receipt: Mapping[str, Any],
        receipt_digest: str,
        completed_at: datetime,
        lease_owner: str,
    ) -> None:
        with self.store.transaction() as connection:
            operation = connection.execute(
                "SELECT * FROM rollout_rollback_operation WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if not operation or operation["request_digest"] != sha256_json(command):
                raise ValidationError("rollout rollback operation binding mismatch")
            if (
                operation["status"] != "IN_FLIGHT"
                or operation["lease_owner"] != lease_owner
                or parse_instant(operation["lease_until"], "rollback lease") <= completed_at
                or operation["fence_token"] != command.get("fenceToken")
            ):
                raise ValidationError("rollout rollback lease or fence expired")
            rollout = connection.execute(
                "SELECT status,fence_token FROM rollout_execution WHERE rollout_id=?",
                (operation["rollout_id"],),
            ).fetchone()
            if (
                not rollout
                or rollout["status"] not in {"ROLLBACK_IN_FLIGHT", "UNKNOWN"}
                or rollout["fence_token"] != operation["fence_token"]
            ):
                raise ValidationError("rollout rollback execution fence changed")
            prior_observation = connection.execute(
                "SELECT stage_name,observed_at,metrics_digest,signed_record_json,decision "
                "FROM rollout_observation WHERE rollout_id=? AND observation_id=?",
                (operation["rollout_id"], operation["observation_id"]),
            ).fetchone()
            intended_observation = (
                operation["stage_name"], operation["observed_at"],
                operation["metrics_digest"], operation["signed_record_json"], "ROLLBACK",
            )
            if prior_observation and tuple(prior_observation) != intended_observation:
                raise ValidationError("immutable rollout observation collision")
            if not prior_observation:
                connection.execute(
                    "INSERT INTO rollout_observation VALUES(?,?,?,?,?,?,?)",
                    (
                        operation["rollout_id"], operation["observation_id"],
                        *intended_observation,
                    ),
                )
            changed = connection.execute(
                "UPDATE rollout_rollback_operation SET status='SUCCEEDED',"
                "receipt_digest=?,receipt_json=?,updated_at=? WHERE operation_id=? "
                "AND status='IN_FLIGHT' AND fence_token=? AND lease_owner=?",
                (
                    receipt_digest, canonical_json(receipt).decode(),
                    completed_at.isoformat(), operation_id,
                    operation["fence_token"], lease_owner,
                ),
            ).rowcount
            rollout_changed = connection.execute(
                "UPDATE rollout_execution SET status='ROLLED_BACK',stage_started_at=?,"
                "fence_token=fence_token+1 WHERE rollout_id=? "
                "AND status IN ('ROLLBACK_IN_FLIGHT','UNKNOWN') AND fence_token=?",
                (
                    completed_at.isoformat(), operation["rollout_id"],
                    operation["fence_token"],
                ),
            ).rowcount
            if changed != 1 or rollout_changed != 1:
                raise ValidationError("rollout rollback completion fencing failed")

    def _mark_rollback_unknown(
        self,
        operation_id: str,
        command: Mapping[str, Any],
        occurred_at: datetime,
        lease_owner: str,
    ) -> None:
        with self.store.transaction() as connection:
            operation = connection.execute(
                "SELECT rollout_id,fence_token,request_digest,status,lease_owner "
                "FROM rollout_rollback_operation WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if not operation or operation["status"] == "SUCCEEDED":
                return
            if (
                operation["request_digest"] != sha256_json(command)
                or operation["fence_token"] != command.get("fenceToken")
                or operation["lease_owner"] != lease_owner
            ):
                raise ValidationError("rollout rollback UNKNOWN binding mismatch")
            connection.execute(
                "UPDATE rollout_rollback_operation SET status='UNKNOWN',updated_at=? "
                "WHERE operation_id=? AND status='IN_FLIGHT' AND fence_token=? "
                "AND lease_owner=?",
                (
                    occurred_at.isoformat(), operation_id,
                    operation["fence_token"], lease_owner,
                ),
            )
            connection.execute(
                "UPDATE rollout_execution SET status='UNKNOWN' WHERE rollout_id=? "
                "AND status='ROLLBACK_IN_FLIGHT' AND fence_token=?",
                (operation["rollout_id"], operation["fence_token"]),
            )
