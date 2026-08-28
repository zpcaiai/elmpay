"""Durable signed Go/No-Go and staged rollout execution (B123-B124)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Callable, Mapping

from .attestation import nonce_store_from_trust, verify_dsse_record
from .capacity import evaluate_capacity
from .common import (
    GateReport,
    ValidationError,
    canonical_json,
    parse_instant,
    require_exact_keys,
    require_list,
    require_mapping,
    require_text,
    sha256_json,
)
from .downstream_receipt import verify_downstream_receipt
from .durable import DurableStore
from .external_evidence import validate_external_evidence
from .release import release_binding, verify_release
from .rollout import compare_shadow, evaluate_canary


def _now(value: datetime | None = None) -> datetime:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc)


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
            "operationsReceipt", "externalEvidenceBundle",
        }
        require_exact_keys(inputs, required=required, optional=set(), field="Go/No-Go inputs")
        manifest = require_mapping(inputs["releaseManifest"], "release manifest")
        binding = release_binding(manifest)
        target_digest = rollout_target_digest(target)

        release_report = verify_release(
            manifest, self.release_policy, self.trust, now=current
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
            shadow_reasons, (f"shadow_compared:{shadow.compared}",)
        )
        canary_report = evaluate_canary(
            require_mapping(inputs["canaryBaseline"], "canary baseline"),
            require_mapping(inputs["canaryCandidate"], "canary candidate"),
            self.policy,
        )
        capacity_report = evaluate_capacity(
            self.capacity_policy,
            require_mapping(inputs["capacitySamples"], "capacity samples"),
        ).report

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
        _, operations_signer = verify_downstream_receipt(
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
            operations_reasons, (f"operations_signer:{operations_signer.identity}",)
        )
        external_report = validate_external_evidence(
            self.external_evidence_policy,
            require_mapping(inputs["externalEvidenceBundle"], "external evidence bundle"),
            self.external_evidence_trust,
            now=current,
            expected_binding=binding,
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
        binding, evaluated_gates = self.evaluate_gates(target, gate_inputs, now=current)
        if record.get("bindingDigest") != binding:
            raise ValidationError("signed decision release binding mismatch")
        target_digest = rollout_target_digest(target)
        if record.get("targetDigest") != target_digest:
            raise ValidationError("signed decision target mismatch")
        signer = verify_dsse_record(record, self.trust, binding, now=current, nonce_store=self.nonces)
        if signer.role != "release_manager":
            raise ValidationError("Go/No-Go signer must have release_manager role")
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
        decision_id = require_text(record.get("decisionId"), "decision.decisionId")
        decided_at = parse_instant(record.get("issuedAt"), "decision.issuedAt").isoformat()
        encoded = canonical_json(record).decode()
        with self.store.transaction() as connection:
            prior = connection.execute("SELECT signed_record_json FROM release_decision WHERE decision_id=?", (decision_id,)).fetchone()
            if prior:
                if prior["signed_record_json"] != encoded:
                    raise ValidationError("immutable Go/No-Go decision id collision")
            else:
                connection.execute("INSERT INTO release_decision VALUES(?,?,?,?,?,?,?)", (decision_id, binding, target_digest, expected_decision, gate_digest, encoded, decided_at))
        return {"decisionId": decision_id, "decision": expected_decision, "bindingDigest": binding, "targetDigest": target_digest, "failedGates": failed, "signer": signer.identity}

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
        target_digest = rollout_target_digest(target)
        for label, digest in (("artifact", artifact_digest), ("previous artifact", previous_artifact_digest)):
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValidationError(f"{label} digest must be SHA-256")
        stages = require_list(self.policy.get("stages"), "rollout stages")
        if not stages:
            raise ValidationError("rollout policy has no stages")
        with self.store.transaction() as connection:
            approved = connection.execute("SELECT decision,signed_record_json FROM release_decision WHERE release_binding_digest=? AND target_digest=? ORDER BY decided_at DESC,decision_id DESC LIMIT 1", (release_binding_digest, target_digest)).fetchone()
            if not approved or approved["decision"] != "GO":
                raise ValidationError("signed GO decision for exact release target is required")
            verify_dsse_record(json.loads(approved["signed_record_json"]), self.trust, release_binding_digest, now=_now(now), nonce_store=self.nonces)
            connection.execute(
                "INSERT INTO rollout_execution VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rollout_id, release_binding_digest, target_digest, target["tenantId"], target["projectId"], target["providerId"], target["region"], artifact_digest, previous_artifact_digest, 0, _now(now).isoformat(), "RUNNING", 1),
            )
        return {"rolloutId": rollout_id, "stage": stages[0]["name"], "trafficPercent": stages[0]["trafficPercent"], "fenceToken": 1}

    def observe_and_advance(
        self,
        rollout_id: str,
        signed_observation: Mapping[str, Any],
        baseline_metrics: Mapping[str, Any],
        candidate_metrics: Mapping[str, Any],
        rollback_adapter: Callable[[Mapping[str, Any]], str],
        signed_stage_approval: Mapping[str, Any] | None = None,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = _now(now)
        stages = require_list(self.policy.get("stages"), "rollout stages")
        with self.store.transaction() as connection:
            rollout = connection.execute("SELECT * FROM rollout_execution WHERE rollout_id=?", (rollout_id,)).fetchone()
            if not rollout or rollout["status"] != "RUNNING":
                raise ValidationError("rollout is not running")
            observation = require_mapping(signed_observation, "signed observation")
            signer = verify_dsse_record(observation, self.trust, rollout["release_binding_digest"], now=current, nonce_store=self.nonces)
            if signer.role != "rollout_observer" or not signer.independent:
                raise ValidationError("rollout observation requires an independent rollout_observer")
            if observation.get("targetDigest") != rollout["target_digest"] or observation.get("rolloutId") != rollout_id:
                raise ValidationError("rollout observation target mismatch")
            stage = require_mapping(stages[rollout["stage_index"]], "stage")
            if observation.get("stage") != stage.get("name"):
                raise ValidationError("rollout observation stage mismatch")
            if observation.get("trafficPercent") != stage.get("trafficPercent"):
                raise ValidationError("rollout observation traffic allocation mismatch")
            stage_approval: Mapping[str, Any] | None = None
            if stage.get("requiresApproval") is True:
                if signed_stage_approval is None:
                    raise ValidationError("signed stage approval is required")
                stage_approval = require_mapping(signed_stage_approval, "signed stage approval")
                approver = verify_dsse_record(stage_approval, self.trust, rollout["release_binding_digest"], now=current, nonce_store=self.nonces)
                if approver.role != "release_manager":
                    raise ValidationError("stage approval requires release_manager role")
                if (
                    stage_approval.get("targetDigest") != rollout["target_digest"]
                    or stage_approval.get("rolloutId") != rollout_id
                    or stage_approval.get("stage") != stage.get("name")
                    or stage_approval.get("decision") != "APPROVE"
                ):
                    raise ValidationError("stage approval binding mismatch")
            metrics_doc = {"baseline": dict(baseline_metrics), "candidate": dict(candidate_metrics)}
            if observation.get("metricsDigest") != sha256_json(metrics_doc):
                raise ValidationError("rollout observation metrics digest mismatch")
            observed_at = parse_instant(observation.get("observedAt"), "observation.observedAt")
            started_at = parse_instant(rollout["stage_started_at"], "rollout.stage_started_at")
            minimum = stage.get("minimumMinutes")
            if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
                raise ValidationError("rollout minimumMinutes is invalid")
            if observed_at < started_at + timedelta(minutes=minimum):
                raise ValidationError("rollout observation window is incomplete")
            report = evaluate_canary(baseline_metrics, candidate_metrics, self.policy)
            if stage.get("requiresDiffPass") is True and observation.get("shadowDiffPassed") is not True:
                report = GateReport.from_reasons([*report.reasons, "shadow_diff_not_passed"], report.checks)
            observation_id = require_text(observation.get("observationId"), "observation.observationId")
            if not report.allowed:
                adapter_result = rollback_adapter(dict(rollout))
                if adapter_result != rollout["previous_artifact_digest"]:
                    raise ValidationError("rollback adapter did not confirm the previous artifact digest")
                decision = "ROLLBACK"
                status = "ROLLED_BACK"
                next_index = rollout["stage_index"]
            elif rollout["stage_index"] + 1 >= len(stages):
                decision = "PASS"
                status = "COMPLETE"
                next_index = rollout["stage_index"]
            else:
                decision = "PASS"
                status = "RUNNING"
                next_index = rollout["stage_index"] + 1
            signed_records = {"observation": dict(observation), "stageApproval": dict(stage_approval) if stage_approval is not None else None}
            connection.execute("INSERT INTO rollout_observation VALUES(?,?,?,?,?,?,?)", (rollout_id, observation_id, stage["name"], observed_at.isoformat(), observation["metricsDigest"], canonical_json(signed_records).decode(), decision))
            connection.execute("UPDATE rollout_execution SET stage_index=?,stage_started_at=?,status=?,fence_token=fence_token+1 WHERE rollout_id=?", (next_index, current.isoformat(), status, rollout_id))
        next_stage = stages[next_index]["name"]
        return {"rolloutId": rollout_id, "decision": decision, "status": status, "stage": next_stage, "reasons": list(report.reasons), "signer": signer.identity}
