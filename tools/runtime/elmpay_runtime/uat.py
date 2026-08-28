"""Executable, synthetic-only UAT DSL with durable candidate evidence (B118).

The runner deliberately cannot create an approved UAT attestation.  It records
an immutable, digest-bound result bundle which an independent human workflow
may inspect and sign later.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from typing import Any, Callable, Mapping

from .common import ValidationError, canonical_json, require_list, require_mapping, require_text, sha256_json
from .durable import DurableStore


DIGEST = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
FORBIDDEN_KEYS = re.compile(r"(?:pan|cvv|cvc|card.?number|password|secret|private.?key|access.?token)", re.I)
FORBIDDEN_VALUES = re.compile(r"(?:sk_live_|-----BEGIN .*PRIVATE KEY-----)")


def _utc(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


def _reject_sensitive(value: object, path: str = "suite") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if FORBIDDEN_KEYS.search(str(key)):
                raise ValidationError(f"sensitive UAT field is forbidden: {path}.{key}")
            _reject_sensitive(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive(item, f"{path}[{index}]")
    elif isinstance(value, str) and FORBIDDEN_VALUES.search(value):
        raise ValidationError(f"live credential material is forbidden: {path}")


def _expect(output: Mapping[str, Any], expectation: Mapping[str, Any]) -> tuple[bool, str]:
    allowed = {"equals", "contains"}
    unknown = set(expectation) - allowed
    if unknown:
        raise ValidationError(f"unknown UAT expectation operators: {sorted(unknown)}")
    equals = expectation.get("equals", {})
    contains = expectation.get("contains", {})
    for label, raw in (("equals", equals), ("contains", contains)):
        if not isinstance(raw, dict):
            raise ValidationError(f"expect.{label} must be an object")
    for key, wanted in equals.items():
        if output.get(key) != wanted:
            return False, f"field {key} did not equal expected value"
    for key, wanted in contains.items():
        actual = output.get(key)
        if not isinstance(actual, (str, list, dict)) or wanted not in actual:
            return False, f"field {key} did not contain expected value"
    return True, "expectation satisfied"


@dataclass(frozen=True)
class UatAdapter:
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    environment: str = "UAT"
    synthetic_only: bool = True


class UatRunner:
    def __init__(self, database: str, adapters: Mapping[str, UatAdapter]) -> None:
        self.store = DurableStore(database)
        self.adapters = dict(adapters)
        for action, adapter in self.adapters.items():
            if not isinstance(adapter, UatAdapter) or adapter.environment != "UAT" or adapter.synthetic_only is not True:
                raise ValidationError(f"UAT adapter is not synthetic-only: {action}")

    def run(self, suite: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        document = require_mapping(dict(suite), "suite")
        _reject_sensitive(document)
        if document.get("schemaVersion") != 1:
            raise ValidationError("UAT suite schemaVersion must be 1")
        if document.get("environment") != "UAT" or document.get("syntheticOnly") is not True:
            raise ValidationError("UAT execution is restricted to synthetic UAT data")
        tenant = require_text(document.get("tenantId"), "suite.tenantId")
        suite_id = require_text(document.get("suiteId"), "suite.suiteId")
        version = require_text(document.get("version"), "suite.version")
        if not IDENTIFIER.fullmatch(tenant) or not IDENTIFIER.fullmatch(suite_id):
            raise ValidationError("tenantId and suiteId must be bounded identifiers")
        binding = require_text(document.get("releaseBindingDigest"), "suite.releaseBindingDigest")
        if not DIGEST.fullmatch(binding):
            raise ValidationError("releaseBindingDigest must be SHA-256")
        scenarios = require_list(document.get("scenarios"), "suite.scenarios")
        if not scenarios:
            raise ValidationError("UAT suite requires at least one scenario")
        suite_digest = sha256_json(document)
        run_id = sha256_json({"tenantId": tenant, "suiteId": suite_id, "version": version, "binding": binding})
        instant = _utc(now)
        with self.store.transaction() as connection:
            existing = connection.execute("SELECT suite_digest,candidate_bundle_json FROM uat_run WHERE run_id=?", (run_id,)).fetchone()
            if existing:
                if existing["suite_digest"] != suite_digest or not existing["candidate_bundle_json"]:
                    raise ValidationError("immutable UAT run identifier collision")
                return json.loads(existing["candidate_bundle_json"])
            connection.execute(
                "INSERT INTO uat_run(run_id,tenant_id,suite_id,suite_version,release_binding_digest,suite_digest,status,started_at) VALUES(?,?,?,?,?,?,?,?)",
                (run_id, tenant, suite_id, version, binding, suite_digest, "RUNNING", instant),
            )
            results: list[dict[str, Any]] = []
            scenario_ids: set[str] = set()
            for raw_scenario in scenarios:
                scenario = require_mapping(raw_scenario, "scenario")
                scenario_id = require_text(scenario.get("id"), "scenario.id")
                if scenario_id in scenario_ids or not IDENTIFIER.fullmatch(scenario_id):
                    raise ValidationError(f"duplicate or invalid scenario id: {scenario_id}")
                scenario_ids.add(scenario_id)
                steps = require_list(scenario.get("steps"), f"scenario.{scenario_id}.steps")
                if not steps:
                    raise ValidationError(f"scenario {scenario_id} requires steps")
                for index, raw_step in enumerate(steps):
                    step = require_mapping(raw_step, "step")
                    action = require_text(step.get("action"), "step.action")
                    adapter = self.adapters.get(action)
                    if adapter is None:
                        raise ValidationError(f"UAT action is not wired: {action}")
                    input_data = require_mapping(step.get("input", {}), "step.input")
                    expectation = require_mapping(step.get("expect", {}), "step.expect")
                    try:
                        output = require_mapping(adapter.handler(input_data), "adapter output")
                        _reject_sensitive(output, "adapter output")
                        passed, detail = _expect(output, expectation)
                    except ValidationError:
                        raise
                    except Exception as exc:  # adapter failures are results, never fabricated passes
                        output = {"errorType": type(exc).__name__}
                        passed, detail = False, "adapter execution failed"
                    result = {
                        "scenarioId": scenario_id,
                        "stepIndex": index,
                        "action": action,
                        "status": "PASSED" if passed else "FAILED",
                        "inputDigest": sha256_json(input_data),
                        "outputDigest": sha256_json(output),
                        "detail": detail,
                    }
                    connection.execute(
                        "INSERT INTO uat_step_result VALUES(?,?,?,?,?,?,?,?)",
                        (run_id, scenario_id, index, action, result["status"], result["inputDigest"], result["outputDigest"], detail),
                    )
                    results.append(result)
            passed_count = sum(item["status"] == "PASSED" for item in results)
            status = "PASSED" if passed_count == len(results) else "FAILED"
            result_digest = sha256_json(results)
            bundle = {
                "schemaVersion": 1,
                "kind": "UAT_RESULT_CANDIDATE",
                "status": "CANDIDATE",
                "certificationStatus": "NOT_CERTIFIED",
                "humanSignoffRequired": True,
                "runId": run_id,
                "tenantId": tenant,
                "suiteId": suite_id,
                "suiteVersion": version,
                "releaseBindingDigest": binding,
                "suiteDigest": suite_digest,
                "resultDigest": result_digest,
                "stepsTotal": len(results),
                "stepsPassed": passed_count,
                "executionStatus": status,
                "generatedAt": instant,
            }
            connection.execute(
                "UPDATE uat_run SET status=?,finished_at=?,result_digest=?,candidate_bundle_json=? WHERE run_id=?",
                (status, instant, result_digest, canonical_json(bundle).decode("utf-8"), run_id),
            )
            return bundle
