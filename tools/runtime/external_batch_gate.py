#!/usr/bin/env python3
"""Validate the real external evidence required by one release batch.

This command filters a release-wide evidence bundle to the categories assigned
to one batch, while preserving every record's release binding and DSSE
signature. It never creates trust material, attestations, or approvals.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "runtime"))

from elmpay_runtime.common import ValidationError, read_json  # noqa: E402
from elmpay_runtime.external_evidence import validate_external_evidence  # noqa: E402
from elmpay_runtime.release import release_binding  # noqa: E402


DEFAULT_GATE_POLICY = ROOT / "platform/compliance/rebaseline-external-gates.json"
DEFAULT_EVIDENCE_POLICY = ROOT / "platform/compliance/external-evidence-policy.json"


def _emit(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _batch_policy(
    batch: str,
    gate_policy: dict[str, Any],
    evidence_policy: dict[str, Any],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    if gate_policy.get("schemaVersion") != 1:
        raise ValidationError("external batch gate policy schema is invalid")
    batches = gate_policy.get("batches")
    if not isinstance(batches, dict) or not isinstance(batches.get(batch), dict):
        raise ValidationError(f"no external evidence gate is declared for {batch}")
    assignment = batches[batch]
    raw_categories = assignment.get("requiredCategories")
    if (
        not isinstance(raw_categories, list)
        or not raw_categories
        or any(not isinstance(item, str) or not item for item in raw_categories)
        or len(set(raw_categories)) != len(raw_categories)
    ):
        raise ValidationError(f"{batch} requiredCategories is invalid")
    categories = tuple(raw_categories)
    available = evidence_policy.get("requiredCategories")
    if not isinstance(available, dict):
        raise ValidationError("external evidence policy categories are invalid")
    unknown = sorted(set(categories) - set(available))
    if unknown:
        raise ValidationError(f"{batch} references unknown categories: {unknown}")
    minimum = assignment.get("minimumDistinctVerifiers")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 1:
        raise ValidationError(f"{batch} minimumDistinctVerifiers is invalid")

    narrowed = copy.deepcopy(evidence_policy)
    narrowed["requiredCategories"] = {name: available[name] for name in categories}
    narrowed["minimumDistinctVerifiers"] = minimum
    if "provider_certification" not in categories:
        narrowed["requiredProviderCapabilities"] = {}
    return narrowed, categories


def validate_batch(
    batch: str,
    gate_policy: dict[str, Any],
    evidence_policy: dict[str, Any],
    bundle: dict[str, Any],
    trust: dict[str, Any],
    manifest: dict[str, Any],
    *,
    now: datetime | None = None,
):
    policy, categories = _batch_policy(batch, gate_policy, evidence_policy)
    records = bundle.get("evidence")
    if not isinstance(records, list):
        raise ValidationError("external evidence bundle evidence must be an array")
    selected = [
        copy.deepcopy(item)
        for item in records
        if isinstance(item, dict) and item.get("category") in categories
    ]
    narrowed_bundle = copy.deepcopy(bundle)
    narrowed_bundle["evidence"] = selected
    return validate_external_evidence(
        policy,
        narrowed_bundle,
        trust,
        now=now,
        expected_binding=release_binding(manifest),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate independently signed external evidence for one batch"
    )
    parser.add_argument("batch")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trust", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--gate-policy", type=Path, default=DEFAULT_GATE_POLICY)
    parser.add_argument("--evidence-policy", type=Path, default=DEFAULT_EVIDENCE_POLICY)
    args = parser.parse_args(argv)
    try:
        report = validate_batch(
            args.batch,
            read_json(args.gate_policy),
            read_json(args.evidence_policy),
            read_json(args.bundle),
            read_json(args.trust),
            read_json(args.manifest),
        )
    except (OSError, ValidationError, ValueError) as exc:
        _emit({"allowed": False, "batch": args.batch, "reasons": [str(exc)], "checks": []})
        return 2
    _emit(
        {
            "allowed": report.allowed,
            "batch": args.batch,
            "reasons": list(report.reasons),
            "checks": list(report.checks),
        }
    )
    return 0 if report.allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
