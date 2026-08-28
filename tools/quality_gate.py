#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.common import (  # noqa: E402
    ValidationError,
    read_json,
    require_mapping,
    require_text,
)
from elmpay_runtime.quality_metrics import run_quality_metrics, write_result  # noqa: E402
from elmpay_runtime.security_testing import orchestrate_security_pipeline  # noqa: E402
from elmpay_runtime.quality import (  # noqa: E402
    DeterministicProviderSimulator,
    exercise_payment_model,
    run_http_load_profile,
    run_http_resilience_plan,
    run_load_profile,
    webhook_fault_corpus,
)


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ELMPay deterministic B112-B117 quality gates")
    commands = parser.add_subparsers(dest="command", required=True)
    model = commands.add_parser("model")
    model.add_argument("--seed", type=int, default=127)
    model.add_argument("--cases", type=int, default=10000)
    security = commands.add_parser("security")
    security.add_argument("--plan", type=Path, required=True)
    simulator = commands.add_parser("simulate-provider")
    simulator.add_argument("--request", type=Path, required=True)
    simulator.add_argument("--state", type=Path, required=True)
    simulator.add_argument("--secret-env", required=True)
    simulator.add_argument("--scenario", choices=(
        "SUCCESS", "DECLINED", "UNKNOWN", "TIMEOUT", "MALFORMED_WEBHOOK"
    ), default="SUCCESS")
    faults = commands.add_parser("webhook-fault-corpus")
    faults.add_argument("--payload", type=Path, required=True)
    faults.add_argument("--seed", type=int, default=114)
    concurrency = commands.add_parser("concurrency")
    concurrency.add_argument("--request", type=Path, required=True)
    concurrency.add_argument("--state", type=Path, required=True)
    concurrency.add_argument("--secret-env", required=True)
    concurrency.add_argument("--workers", type=int, default=8)
    concurrency.add_argument("--calls", type=int, default=32)
    load = commands.add_parser("load-profile")
    load.add_argument("--profile", type=Path, required=True)
    metrics = commands.add_parser("coverage-mutation")
    metrics.add_argument(
        "--policy",
        type=Path,
        default=ROOT / "testing/quality-metrics-policy.json",
    )
    metrics.add_argument("--output", type=Path)
    metrics.add_argument(
        "--offline",
        action="store_true",
        help="Require all Gradle quality dependencies to already exist in local caches.",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "coverage-mutation":
            raw_policy = require_mapping(read_json(args.policy), "quality metrics policy")
            result = run_quality_metrics(ROOT, raw_policy, offline=args.offline)
            raw_output = args.output or Path(
                require_text(raw_policy.get("result"), "quality metrics result path")
            )
            output = raw_output if raw_output.is_absolute() else ROOT / raw_output
            write_result(output, result)
            print(json.dumps(result.document(), sort_keys=True))
            return 0 if result.allowed else 2
        if args.command == "model":
            result = exercise_payment_model(args.seed, args.cases)
            print(json.dumps({"passed": result.passed, "cases": result.cases, "failures": result.failures}))
            return 0 if result.passed else 2
        if args.command == "security":
            plan = read_json(args.plan)
            if not isinstance(plan, dict):
                raise ValidationError("security plan must be a JSON object")
            result = orchestrate_security_pipeline(plan, environment=os.environ)
            print(json.dumps(asdict(result), sort_keys=True))
            return 0 if result.allowed else 2
        if args.command == "webhook-fault-corpus":
            corpus = webhook_fault_corpus(args.payload.read_bytes(), args.seed)
            print(json.dumps({
                "allowed": True,
                "seed": args.seed,
                "cases": [{"name": name, "payloadBase64": base64.b64encode(payload).decode(),
                           "schedule": dict(schedule)} for name, payload, schedule in corpus],
            }, sort_keys=True))
            return 0
        if args.command in {"simulate-provider", "concurrency"}:
            request = read_json(args.request)
            if not isinstance(request, dict):
                raise ValidationError("provider request must be a JSON object")
            secret = os.environ.get(args.secret_env)
            if secret is None or not secret.startswith("sim-") or len(secret.encode()) < 32:
                raise ValidationError("provider simulator requires a bounded synthetic sim- secret")
            provider = str(request.get("provider", ""))
            tenant = str(request.get("tenantId", ""))
            account = str(request.get("providerAccountId", ""))
            simulator = DeterministicProviderSimulator(
                str(args.state), {(tenant, account, provider): secret.encode()}
            )
            try:
                if args.command == "simulate-provider":
                    value = simulator.execute(request, args.scenario)
                    print(json.dumps({
                        "allowed": True, "provider": value.provider,
                        "requestId": value.request_id, "outcome": value.outcome,
                        "providerReference": value.provider_reference,
                        "webhookHeaders": dict(value.webhook_headers),
                        "webhookPayloadBase64": base64.b64encode(value.webhook_payload).decode()
                            if value.webhook_payload is not None else None,
                        "delayMs": value.delay_ms,
                    }, sort_keys=True))
                    return 0
                if args.workers < 1 or args.workers > 64 or args.calls < 2 or args.calls > 10_000:
                    raise ValidationError("concurrency profile is outside the safe bound")
                with ThreadPoolExecutor(max_workers=args.workers) as pool:
                    results = list(pool.map(lambda _: simulator.execute(request), range(args.calls)))
                references = {item.provider_reference for item in results}
                request_ids = {item.request_id for item in results}
                allowed = len(references) == 1 and len(request_ids) == 1
                print(json.dumps({"allowed": allowed, "calls": args.calls,
                                  "uniqueProviderReferences": len(references),
                                  "uniqueRequestIds": len(request_ids)}, sort_keys=True))
                return 0 if allowed else 2
            finally:
                simulator.close()
        if args.command == "load-profile":
            profile = read_json(args.profile)
            if not isinstance(profile, dict):
                raise ValidationError("load profile must be a JSON object")
            target = profile.get("target")
            if target == "synthetic-handler-v1":
                cases = profile.get("requests")
                workers = profile.get("workers")
                if not isinstance(cases, list) or not cases or len(cases) > 100_000:
                    raise ValidationError("load request list is outside the safe bound")
                if isinstance(workers, bool) or not isinstance(workers, int):
                    raise ValidationError("load workers must be an integer")
                by_id: dict[str, dict[str, object]] = {}
                identifiers: list[str] = []
                for item in cases:
                    if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                        raise ValidationError("load request fixture is invalid")
                    identifier = item["id"]
                    if identifier in by_id:
                        raise ValidationError("load fixture ids must be unique")
                    if set(item) - {"id", "ok", "sideEffectId", "resultId", "score"}:
                        raise ValidationError("load fixture contains an unsafe field")
                    by_id[identifier] = item
                    identifiers.append(identifier)
                measured = run_load_profile(
                    lambda identifier: by_id[identifier], identifiers, workers
                )
                allowed = (measured.errors == 0 and measured.duplicate_side_effects == 0
                           and measured.duplicate_results == 0
                           and measured.non_finite_results == 0)
            elif target == "loopback-http-test-v1":
                token_env = profile.get("testTokenEnv")
                if (not isinstance(token_env, str)
                        or not token_env.startswith("ELMPAY_TEST_")
                        or not token_env.replace("_", "").isalnum()):
                    raise ValidationError("testTokenEnv must name an explicit ELMPAY_TEST_ variable")
                test_token = os.environ.get(token_env)
                if test_token is None:
                    raise ValidationError("load test token is unavailable")
                if "phases" in profile:
                    plan = run_http_resilience_plan(profile, test_token)
                    raw_phases = profile.get("phases")
                    assert isinstance(raw_phases, list)
                    allowed = plan.complete_b117_proof and all(
                        phase.recovered and _load_allowed(
                            phase.load, {**profile, **raw}
                        )
                        for phase, raw in zip(plan.phases, raw_phases, strict=True)
                        if isinstance(raw, dict)
                    ) and len(plan.phases) == len(raw_phases)
                    print(json.dumps({"allowed": allowed, **asdict(plan)}, sort_keys=True))
                    return 0 if allowed else 2
                measured = run_http_load_profile(profile, test_token)
                allowed = _load_allowed(measured, profile)
            else:
                raise ValidationError(
                    "load target must be synthetic-handler-v1 or loopback-http-test-v1"
                )
            print(json.dumps({"allowed": allowed, **measured.__dict__}, sort_keys=True))
            return 0 if allowed else 2
        raise ValidationError("unsupported quality command")
    except (KeyError, OSError, ValidationError, ValueError, TypeError) as exc:
        print(json.dumps({"allowed": False, "reasons": [f"input_invalid:{exc}"], "checks": []}))
        return 2


def _bounded_int(value: object, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValidationError(f"{field} is outside the safe bound")
    return value


def _finite_number(value: object, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field} must be a finite number")
    result = float(value)
    if not __import__("math").isfinite(result) or not minimum <= result <= maximum:
        raise ValidationError(f"{field} is outside the safe bound")
    return result


def _load_allowed(measured: object, profile: dict[str, object]) -> bool:
    thresholds = profile.get("thresholds")
    if not isinstance(thresholds, dict):
        raise ValidationError("real load profile requires explicit thresholds")
    minimum_rps = _finite_number(
        thresholds.get("minimumThroughputRps"), "minimumThroughputRps", 0, 1_000_000
    )
    maximum_error_rate = _finite_number(
        thresholds.get("maximumErrorRate"), "maximumErrorRate", 0, 1
    )
    maximum_p99_ms = _bounded_int(
        thresholds.get("maximumP99Milliseconds"), "maximumP99Milliseconds", 1, 60_000
    )
    minimum_requests = _bounded_int(
        thresholds.get("minimumRequests"), "minimumRequests", 1, 100_000
    )
    duration = profile.get("durationSeconds")
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        raise ValidationError("durationSeconds must be a finite number")
    requested_duration_ms = int(float(duration) * 1_000)
    return bool(
        getattr(measured, "complete_b117_proof")
        and getattr(measured, "requests") >= minimum_requests
        and getattr(measured, "duration_ms") >= max(1, int(requested_duration_ms * 0.9))
        and getattr(measured, "throughput_rps") >= minimum_rps
        and getattr(measured, "error_rate") <= maximum_error_rate
        and getattr(measured, "p99_ms") <= maximum_p99_ms
        and getattr(measured, "duplicate_side_effects") == 0
        and getattr(measured, "duplicate_results") == 0
        and getattr(measured, "non_finite_results") == 0
    )


if __name__ == "__main__":
    sys.exit(main())
