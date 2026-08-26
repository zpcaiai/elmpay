"""B33 — the payment attempt: one immutable record per provider call.

The brief asks that every provider call form an independent attempt keeping the
request digest, the response, an error classification, retries and finality.
The rule that carries the batch is ``ATTEMPT_TIMEOUT_IS_FAILURE``.

A call that timed out has an **unknown** outcome: the money may already have
moved. Classifying it as a failure and retrying is the standard way a payment
system charges twice, and it is always introduced as a simplification — the
retry loop needs a boolean, and "did not succeed" looks like one. So timeouts
are ``unknown``, an unresolved unknown blocks the next attempt, and only a
provider query or a reconciliation file may resolve it.

The rest are the mistakes this area repeats:

* ``ATTEMPT_REUSED`` — updating the existing attempt row on retry. It erases what
  was actually sent, and with it the only way to answer whether the first call
  reached the provider;
* ``ATTEMPT_UNMAPPED_IS_SUCCESS`` — defaulting an unrecognised provider code to
  anything other than ``unknown``. A code we have never seen is, by definition,
  a result we do not know;
* ``ATTEMPT_STORES_PAYLOAD`` — keeping the request instead of its digest, which
  turns the audit trail into a card-number store, and a replayable one at that;
* ``ATTEMPT_FINAL_OVERWRITTEN`` — letting a later contradicting event overwrite a
  final attempt instead of opening a reconciliation item.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

ATTEMPT = Path("governance/payment-attempt.json")
STATES = Path("governance/state-machines.json")
INTENT = Path("governance/payment-intent.json")
ACCOUNTS = Path("governance/provider-accounts.json")
AUDIT = Path("governance/audit-log.json")

CODE = re.compile(r"^[a-z][a-z0-9_]*$")
REQUIRED_CLASSES = {"succeeded", "failed_final", "failed_retryable", "unknown"}
REQUIRED_FIELDS = {
    "tenant_id", "intent_id", "provider", "sequence", "request_digest", "response_digest",
    "provider_request_id", "provider_transaction_id", "outcome_class", "provider_code",
    "provider_code_namespace", "started_at", "finished_at",
}
REDACTED = {"pan", "cvv", "credential"}
RESPONSE_EVIDENCE_FIELDS = {
    "provider_code", "provider_code_namespace", "provider_request_id",
    "provider_transaction_id", "outcome_class", "response_digest",
}
RESPONSE_FORBIDDEN_FIELDS = {
    "raw_response", "response_body", "headers", "authorization", "credential", "token",
    "pan", "cvv",
}
RAW_RESPONSE_FIELDS = {"raw_response", "response", "response_body", "response_headers"}
CODE_NAMESPACES = {
    "stripe": {"stripe.error.code", "stripe.decline_code"},
    "wechat": {"wechat.api_v3.code"},
    "alipay": {"alipay.sub_code"},
    "paypal": {"paypal.name", "paypal.details.issue"},
    "apple_pay": {"adapter.normalized"},
}
RESOLUTION_METHODS = {"provider_query", "reconciliation_file"}
MAX_RESOLUTION_HOURS = 72
MAX_ATTEMPTS = 5
TENANT_LOOKUP_KEY = ["tenant_id", "intent_id"]
CONCURRENCY_KEY = ["tenant_id", "intent_id"]


VALIDATOR = ("payment-attempt", "B33")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(ATTEMPT)
    budget.check(where)
    try:
        model = load_json(root / ATTEMPT)
    except Exception as exc:
        return [Problem("ATTEMPT_UNREADABLE", where,
                        f"cannot read the attempt model: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("ATTEMPT_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "ATTEMPT_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "ATTEMPT_PRINCIPLE",
                       where, "say what a timeout means", "NN-14")
    problems += _attempt(model, where)
    problems += _tenant_scope(model, where)
    problems += _concurrency(model, where)
    problems += _reference_runtime(model, where)
    problems += _deployable_runtime(model, where)
    problems += _request_record(model, where)
    problems += _response_record(model, where)
    classes, problems_ = _classes(model, where, budget)
    problems += problems_
    problems += _timeout(model, where, classes)
    problems += _retry(model, where)
    problems += _taxonomy(model, root, where, classes, budget)
    problems += _finality(model, where)
    problems += _lifecycle(model, root, where, budget)
    problems += _audit_binding(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _attempt(model: dict, where: str) -> list[Problem]:
    attempt = model.get("attempt")
    if not isinstance(attempt, dict):
        return [Problem("ATTEMPT_REUSED", where,
                        "without an attempt policy, a retry overwrites the record of the call "
                        "before it", "NN-03")]
    problems = list(expect(attempt.get("immutable") is True, "ATTEMPT_MUTABLE", where,
                           "an attempt records what happened; a mutable one records what "
                           "somebody last thought happened", "NN-13"))
    problems += expect(attempt.get("one_per_provider_call") is True, "ATTEMPT_REUSED", where,
                       "every provider call must produce its own attempt", "NN-03")
    problems += expect(attempt.get("reuse_on_retry_forbidden") is True, "ATTEMPT_REUSED", where,
                       "a retry must not write over the previous attempt", "NN-03")
    problems += expect(attempt.get("sequence_monotonic_per_intent") is True,
                       "ATTEMPT_NO_SEQUENCE", where,
                       "attempts need a monotonic sequence; timestamps drift and the order is "
                       "the only thing that reconstructs the timeline", "NN-13")
    fields = set(attempt.get("required_fields") or [])
    problems += expect(REQUIRED_FIELDS <= fields, "ATTEMPT_FIELD_MISSING", where,
                       f"the attempt is missing {sorted(REQUIRED_FIELDS - fields)}", "NN-13")
    problems += expect(not (fields & RAW_RESPONSE_FIELDS), "ATTEMPT_RESPONSE_PAYLOAD_STORED",
                       where,
                       "an attempt may retain a normalised response summary and digest, never "
                       f"raw response fields {sorted(fields & RAW_RESPONSE_FIELDS)}", "NN-14")
    problems += expect(len(str(attempt.get("notes") or "")) >= 8, "ATTEMPT_NOTES", where,
                       "say why the sequence matters", "NN-14")
    return problems


def _tenant_scope(model: dict, where: str) -> list[Problem]:
    scope = model.get("tenant_scope")
    if not isinstance(scope, dict):
        return [Problem("ATTEMPT_TENANT_SCOPE_MISSING", where,
                        "attempt operations must declare their tenant boundary", "NN-01")]
    problems = list(expect(scope.get("tenant_id_required") is True,
                           "ATTEMPT_TENANT_ID_OPTIONAL", where,
                           "tenant_id must be explicit on every attempt operation", "NN-01"))
    problems += expect(scope.get("lookup_key") == TENANT_LOOKUP_KEY,
                       "ATTEMPT_TENANT_LOOKUP_UNSCOPED", where,
                       "attempt lookup must be scoped by tenant_id and intent_id", "NN-01")
    problems += expect(scope.get("external_ids_never_used_as_internal_ids") is True,
                       "ATTEMPT_ID_NAMESPACE_MIXED", where,
                       "tenant, intent and provider identifiers must not be reused as the "
                       "internal attempt identifier", "NN-01")
    problems += expect(len(str(scope.get("notes") or "")) >= 8,
                       "ATTEMPT_TENANT_SCOPE_NOTES", where,
                       "explain how equal intent ids remain isolated across tenants", "NN-14")
    return problems


def _concurrency(model: dict, where: str) -> list[Problem]:
    policy = model.get("concurrency")
    if not isinstance(policy, dict):
        return [Problem("ATTEMPT_CONCURRENCY_MISSING", where,
                        "creating an attempt must have an atomic concurrency policy", "NN-03")]
    problems = list(expect(policy.get("atomic_start") is True,
                           "ATTEMPT_START_NOT_ATOMIC", where,
                           "concurrent starts must not both reach the provider", "NN-03"))
    problems += expect(policy.get("conflict_key") == CONCURRENCY_KEY,
                       "ATTEMPT_CONCURRENCY_UNSCOPED", where,
                       "the concurrency key must include tenant_id and intent_id", "NN-01")
    problems += expect(policy.get("concurrent_duplicate_policy") ==
                       "reject_without_provider_call", "ATTEMPT_CONCURRENT_DUPLICATE_CALL", where,
                       "a racing duplicate must be rejected before a provider call", "NN-03")
    problems += expect(len(str(policy.get("notes") or "")) >= 8,
                       "ATTEMPT_CONCURRENCY_NOTES", where,
                       "state the atomic mechanism and its production boundary", "NN-14")
    return problems


def _reference_runtime(model: dict, where: str) -> list[Problem]:
    runtime = model.get("reference_runtime")
    if not isinstance(runtime, dict):
        return [Problem("ATTEMPT_REFERENCE_LIMITS_MISSING", where,
                        "the reference runtime must disclose storage, audit and concurrency "
                        "limits", "NN-14")]
    problems = list(expect(runtime.get("process_local_lock") is True,
                           "ATTEMPT_REFERENCE_LOCK_UNSTATED", where,
                           "the reference runtime must disclose its process-local lock", "NN-14"))
    for field in ("durable_storage", "database_unique_constraint", "runtime_audit_sink",
                  "production_ready"):
        problems += expect(runtime.get(field) is False, "ATTEMPT_REFERENCE_OVERCLAIM", where,
                           f"the in-memory reference must not claim {field}", "NN-14")
    problems += expect(runtime.get("b32_replacement_confirmation_integrated") is False,
                       "ATTEMPT_B32_REPLACEMENT_OVERCLAIM", where,
                       "B32 Intents.confirm still refuses a new key after the first "
                       "confirmation; B33 must not claim its replacement request is wired "
                       "end to end", "NN-14")
    problems += expect(len(str(runtime.get("notes") or "")) >= 20,
                       "ATTEMPT_REFERENCE_LIMITS_NOTES", where,
                       "state why the reference runtime is not production evidence", "NN-14")
    return problems


def _deployable_runtime(model: dict, where: str) -> list[Problem]:
    """Keep the production implementation claim concrete without certifying it.

    The Python reference remains intentionally process-local.  This separate
    block binds the deployable Java implementation to its durable migration so
    future documentation cannot collapse those two very different runtimes.
    """
    runtime = model.get("deployable_runtime")
    if not isinstance(runtime, dict):
        return [Problem("ATTEMPT_DEPLOYABLE_RUNTIME_MISSING", where,
                        "declare the durable Java attempt runtime separately from the "
                        "in-memory reference", "NN-12")]
    problems = list(expect(
        runtime.get("implementation") ==
        "services/payment-core/src/main/java/com/elmpay/payment",
        "ATTEMPT_DEPLOYABLE_RUNTIME_UNBOUND", where,
        "bind the deployable runtime to the payment-core implementation", "NN-12"))
    problems += expect(
        runtime.get("migration") ==
        "apps/edge-gateway/src/main/resources/db/migration/V032__payment_runtime.sql",
        "ATTEMPT_DEPLOYABLE_MIGRATION_UNBOUND", where,
        "bind the deployable runtime to its checksum-controlled migration", "NN-12")
    for field in ("durable_storage", "database_unique_constraint", "transactional_outbox",
                  "tenant_rls", "b32_confirmation_integrated", "unknown_query_recovery"):
        problems += expect(runtime.get(field) is True,
                           "ATTEMPT_DEPLOYABLE_CONTROL_MISSING", where,
                           f"the Java runtime must declare {field}", "NN-03")
    problems += expect(runtime.get("local_tests_are_certification") is False,
                       "ATTEMPT_LOCAL_TEST_CERTIFICATION_OVERCLAIM", where,
                       "repository tests are implementation evidence, not certification",
                       "NN-12")
    problems += expect(len(str(runtime.get("notes") or "")) >= 20,
                       "ATTEMPT_DEPLOYABLE_RUNTIME_NOTES", where,
                       "explain the durable runtime and its certification boundary", "NN-14")
    return problems


def _request_record(model: dict, where: str) -> list[Problem]:
    record = model.get("request_record")
    if not isinstance(record, dict):
        return [Problem("ATTEMPT_STORES_PAYLOAD", where,
                        "without a record policy the whole request ends up in the audit trail",
                        "NN-04")]
    problems = list(expect(record.get("store_digest_not_payload") is True,
                           "ATTEMPT_STORES_PAYLOAD", where,
                           "store the digest, not the request: we must prove what was sent "
                           "without keeping the card number that was in it", "NN-04"))
    problems += expect(str(record.get("digest_algorithm") or "") == "sha256",
                       "ATTEMPT_WEAK_DIGEST", where,
                       "the request digest must be sha256", "NN-04")
    redacted = set(record.get("redacted_fields") or [])
    problems += expect(REDACTED <= redacted, "ATTEMPT_UNREDACTED", where,
                       f"the redaction list is missing {sorted(REDACTED - redacted)}", "NN-04")
    problems += expect(record.get("payload_replayable") is False, "ATTEMPT_REPLAYABLE", where,
                       "a replayable request record is a button that charges the money again",
                       "NN-03")
    problems += expect(len(str(record.get("notes") or "")) >= 8, "ATTEMPT_RECORD_NOTES", where,
                       "say what the digest proves and what it must not enable", "NN-14")
    return problems


def _response_record(model: dict, where: str) -> list[Problem]:
    record = model.get("response_record")
    if not isinstance(record, dict):
        return [Problem("ATTEMPT_RESPONSE_PAYLOAD_STORED", where,
                        "without a response-record policy handlers eventually persist the raw "
                        "provider response, including headers and tokens", "NN-14")]
    problems = list(expect(record.get("store_summary_not_payload") is True,
                           "ATTEMPT_RESPONSE_PAYLOAD_STORED", where,
                           "retain a normalised response summary and digest, never the raw "
                           "provider response", "NN-14"))
    problems += expect(str(record.get("digest_algorithm") or "") == "sha256",
                       "ATTEMPT_RESPONSE_WEAK_DIGEST", where,
                       "the normalised response evidence must use sha256", "NN-14")
    evidence = set(record.get("required_evidence_fields") or [])
    problems += expect(RESPONSE_EVIDENCE_FIELDS <= evidence,
                       "ATTEMPT_RESPONSE_EVIDENCE_MISSING", where,
                       "response evidence is missing "
                       f"{sorted(RESPONSE_EVIDENCE_FIELDS - evidence)}", "NN-13")
    forbidden = set(record.get("forbidden_fields") or [])
    problems += expect(RESPONSE_FORBIDDEN_FIELDS <= forbidden,
                       "ATTEMPT_RESPONSE_UNREDACTED", where,
                       "the response forbidden-field list is missing "
                       f"{sorted(RESPONSE_FORBIDDEN_FIELDS - forbidden)}", "NN-14")
    problems += expect(record.get("payload_replayable") is False,
                       "ATTEMPT_RESPONSE_REPLAYABLE", where,
                       "stored response evidence must not preserve a replayable provider "
                       "payload", "NN-03")
    problems += expect(len(str(record.get("notes") or "")) >= 8,
                       "ATTEMPT_RESPONSE_NOTES", where,
                       "say which response evidence is retained and which sensitive material "
                       "is forbidden", "NN-14")
    return problems


def _classes(model: dict, where: str, budget: Budget) -> tuple[dict, list[Problem]]:
    entries = model.get("outcome_classes")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("ATTEMPT_NO_CLASSES", where,
                            "without outcome classes every non-success is the same thing, and "
                            "'unknown' disappears into 'failed'", "NN-03")]
    problems: list[Problem] = []
    classes: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("ATTEMPT_SHAPE", where, "each class must be an object",
                                    "NN-12"))
            continue
        cid = str(entry.get("id") or "")
        scope = f"{where}#{cid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(CODE.match(cid)), "ATTEMPT_CLASS_ID", scope,
                           f"class id '{cid}' must be snake_case", "NN-12")
        problems += expect(cid not in classes, "ATTEMPT_CLASS_DUPLICATE", scope,
                           f"class '{cid}' is declared twice", "NN-12")
        for field in ("final", "settles_intent", "retry_allowed", "requires_resolution"):
            problems += expect(isinstance(entry.get(field), bool), "ATTEMPT_CLASS_UNSTATED",
                               scope, f"'{cid}' must answer '{field}' with a boolean", "NN-03")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "ATTEMPT_CLASS_NOTES",
                           scope, f"say what '{cid}' means", "NN-14")
        if cid:
            classes[cid] = entry
    problems += expect(REQUIRED_CLASSES <= set(classes), "ATTEMPT_NO_CLASSES", where,
                       f"the model is missing {sorted(REQUIRED_CLASSES - set(classes))}",
                       "NN-03")

    unknown = classes.get("unknown") or {}
    if unknown:
        problems += expect(unknown.get("final") is False, "ATTEMPT_UNKNOWN_IS_FINAL", where,
                           "'unknown' must not be final: the money may already have moved",
                           "NN-03")
        problems += expect(unknown.get("retry_allowed") is False, "ATTEMPT_UNKNOWN_RETRYABLE",
                           where,
                           "retrying an unknown outcome before resolving it is the standard "
                           "double charge", "NN-03")
        problems += expect(unknown.get("requires_resolution") is True,
                           "ATTEMPT_UNKNOWN_UNRESOLVED", where,
                           "'unknown' must require resolution", "NN-03")
    final = classes.get("failed_final") or {}
    if final:
        problems += expect(final.get("final") is True, "ATTEMPT_KNOWN_OUTCOME_NOT_FINAL",
                           where, "a definitive response ends its attempt", "NN-13")
        problems += expect(final.get("retry_allowed") is False, "ATTEMPT_FINAL_RETRYABLE",
                           where,
                           "a definitive decline must not be retried; the same request gets "
                           "the same answer and the merchant looks like a fraudster", "NN-03")
        problems += expect(final.get("settles_intent") is False,
                           "ATTEMPT_FAILURE_SETTLES_INTENT", where,
                           "a provider's refusal of the current payment method must not "
                           "permanently fail the PaymentIntent", "NN-03")
    retryable = classes.get("failed_retryable") or {}
    if retryable:
        problems += expect(retryable.get("final") is True,
                           "ATTEMPT_KNOWN_OUTCOME_NOT_FINAL", where,
                           "a retryable response ends this attempt; retry opens a new one",
                           "NN-13")
        problems += expect(retryable.get("settles_intent") is False,
                           "ATTEMPT_FAILURE_SETTLES_INTENT", where,
                           "a retryable provider failure cannot settle the intent", "NN-03")
    success = classes.get("succeeded") or {}
    if success:
        problems += expect(success.get("final") is True, "ATTEMPT_SUCCESS_NOT_FINAL", where,
                           "success is final", "NN-03")
        problems += expect(success.get("settles_intent") is True,
                           "ATTEMPT_SUCCESS_NOT_INTENT_FINAL", where,
                           "a verified provider success must settle the intent", "NN-03")
    return classes, problems


def _timeout(model: dict, where: str, classes: dict) -> list[Problem]:
    timeout = model.get("timeout")
    if not isinstance(timeout, dict):
        return [Problem("ATTEMPT_TIMEOUT_IS_FAILURE", where,
                        "without a timeout policy a timed-out call becomes a failure and gets "
                        "retried", "NN-03")]
    problems = list(expect(str(timeout.get("classified_as") or "") == "unknown",
                           "ATTEMPT_TIMEOUT_IS_FAILURE", where,
                           "a timeout is an unknown outcome, not a failure: the charge may "
                           "already exist", "NN-03"))
    problems += expect(timeout.get("retry_before_resolution_allowed") is False,
                       "ATTEMPT_UNKNOWN_RETRYABLE", where,
                       "an unresolved unknown must block the next attempt", "NN-03")
    methods = set(timeout.get("resolution_methods") or [])
    problems += expect(RESOLUTION_METHODS <= methods, "ATTEMPT_NO_RESOLUTION", where,
                       f"resolution must include {sorted(RESOLUTION_METHODS)}", "NN-01")
    hours = int(timeout.get("max_resolution_hours") or 0)
    problems += expect(0 < hours <= MAX_RESOLUTION_HOURS, "ATTEMPT_RESOLUTION_UNBOUNDED",
                       where,
                       f"an unknown must be resolved within {MAX_RESOLUTION_HOURS} hours, got "
                       f"{hours}", "NN-01")
    problems += expect(len(str(timeout.get("notes") or "")) >= 8, "ATTEMPT_TIMEOUT_NOTES",
                       where, "say why this rule matters more than it looks", "NN-14")
    return problems


def _retry(model: dict, where: str) -> list[Problem]:
    retry = model.get("retry")
    if not isinstance(retry, dict):
        return [Problem("ATTEMPT_SHAPE", where, "retry must be an object", "NN-03")]
    problems = list(expect(retry.get("new_attempt_required") is True, "ATTEMPT_REUSED", where,
                           "a retry must open a new attempt", "NN-03"))
    problems += expect(retry.get("reuse_idempotency_key") is True, "ATTEMPT_NEW_KEY_ON_RETRY",
                       where,
                       "a retry must carry the original idempotency key so the provider can "
                       "deduplicate; the new attempt is for us, the same key is for them",
                       "NN-03")
    problems += expect(retry.get("only_for_retryable") is True, "ATTEMPT_FINAL_RETRYABLE",
                       where, "only a retryable outcome may repeat the same request", "NN-03")
    problems += expect(retry.get("replacement_request_allowed_after") == ["failed_final"],
                       "ATTEMPT_REPLACEMENT_SCOPE", where,
                       "a changed funding-source request is allowed only after the current "
                       "request is definitively refused", "NN-03")
    problems += expect(retry.get("replacement_request_requires_new_idempotency_key") is True,
                       "ATTEMPT_REPLACEMENT_REUSES_KEY", where,
                       "a changed request must not reuse the idempotency key of the old "
                       "request", "NN-03")
    problems += expect(retry.get("replacement_request_requires_customer_action") is True,
                       "ATTEMPT_REPLACEMENT_NO_CUSTOMER_ACTION", where,
                       "changing the funding source must be an explicit customer-driven "
                       "request, never an automatic transport retry", "NN-03")
    attempts = int(retry.get("max_attempts_per_intent") or 0)
    problems += expect(0 < attempts <= MAX_ATTEMPTS, "ATTEMPT_RETRY_UNBOUNDED", where,
                       f"attempts must be bounded, got {attempts}", "NN-03")
    backoff = retry.get("backoff_seconds")
    problems += expect(isinstance(backoff, list) and len(backoff) >= attempts - 1
                       and all(isinstance(v, int) and v > 0 for v in backoff)
                       and list(backoff) == sorted(backoff),
                       "ATTEMPT_NO_BACKOFF", where,
                       "every retry needs an increasing, positive backoff", "NN-14")
    problems += expect(len(str(retry.get("notes") or "")) >= 8, "ATTEMPT_RETRY_NOTES", where,
                       "say who the idempotency key is for and who the attempt is for",
                       "NN-14")
    return problems


def _taxonomy(model: dict, root: Path, where: str, classes: dict,
              budget: Budget) -> list[Problem]:
    entries = model.get("error_taxonomy")
    if not isinstance(entries, list) or not entries:
        return [Problem("ATTEMPT_NO_TAXONOMY", where,
                        "without a taxonomy every provider code is interpreted by whoever "
                        "wrote the handler that day", "NN-03")]
    budget.check(str(ACCOUNTS))
    try:
        accounts = load_json(root / ACCOUNTS)
        providers = {str(p.get("id")) for p in (accounts.get("providers") or [])
                     if isinstance(p, dict)}
    except Exception:
        providers = set()
    problems: list[Problem] = []
    seen: set[tuple[str, str, str]] = set()
    covered: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("ATTEMPT_SHAPE", where, "each mapping must be an object",
                                    "NN-12"))
            continue
        provider = str(entry.get("provider") or "")
        namespace = str(entry.get("code_namespace") or "")
        code = str(entry.get("provider_code") or "")
        scope = f"{where}#{provider}/{namespace}/{code}"
        budget.check(scope)
        problems += expect(provider in providers, "ATTEMPT_PROVIDER_UNKNOWN", scope,
                           f"'{provider}' has no binding in B26", "NN-12")
        covered.add(provider)
        problems += expect(bool(code), "ATTEMPT_CODE_MISSING", scope,
                           "a mapping needs a provider code", "NN-12")
        problems += expect(namespace in CODE_NAMESPACES.get(provider, set()),
                           "ATTEMPT_CODE_NAMESPACE", scope,
                           f"'{namespace}' is not a declared code namespace for '{provider}'; "
                           "top-level error codes, decline codes and adapter-normalised codes "
                           "must not be conflated", "NN-12")
        problems += expect((provider, namespace, code) not in seen,
                           "ATTEMPT_CODE_DUPLICATE", scope,
                           f"'{provider}/{namespace}/{code}' is mapped twice; the second mapping is dead "
                           f"and the first may be the wrong one", "NN-12")
        seen.add((provider, namespace, code))
        outcome = str(entry.get("outcome_class") or "")
        problems += expect(outcome in classes, "ATTEMPT_CLASS_UNKNOWN", scope,
                           f"'{provider}/{code}' maps to undeclared class '{outcome}'",
                           "NN-12")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "ATTEMPT_MAPPING_NOTES",
                           scope, f"say why '{code}' is classified that way", "NN-14")
    problems += expect(str(model.get("unmapped_code_class") or "") == "unknown",
                       "ATTEMPT_UNMAPPED_IS_SUCCESS", where,
                       "an unrecognised provider code must be classified unknown: a code we "
                       "have never seen is by definition a result we do not know", "NN-03")
    for provider in sorted(providers - covered):
        problems.append(Problem("ATTEMPT_PROVIDER_UNMAPPED", where,
                                f"'{provider}' has a binding but no error mapping at all, so "
                                f"every one of its responses lands in 'unknown'", "NN-03"))
    return problems


def _finality(model: dict, where: str) -> list[Problem]:
    finality = model.get("finality")
    if not isinstance(finality, dict):
        return [Problem("ATTEMPT_FINAL_OVERWRITTEN", where,
                        "without a finality policy a later event silently rewrites history",
                        "NN-13")]
    problems = list(expect(finality.get("final_attempt_immutable") is True,
                           "ATTEMPT_FINAL_MUTABLE", where,
                           "a final attempt must not change", "NN-13"))
    problems += expect(finality.get("intent_outcome_from_final_attempt") is True,
                       "ATTEMPT_INTENT_UNLINKED", where,
                       "the intent's outcome must come from its final attempt, not from a "
                       "separate flag somebody sets", "NN-01")
    problems += expect(finality.get("failed_attempt_does_not_settle_intent") is True,
                       "ATTEMPT_FAILURE_SETTLES_INTENT", where,
                       "a failed provider request ends that attempt, not the whole intent; "
                       "the customer may replace the funding source", "NN-03")
    problems += expect(finality.get("contradicting_later_event_opens_reconciliation") is True,
                       "ATTEMPT_CONTRADICTION_IGNORED", where,
                       "a later contradicting event must open a reconciliation item", "NN-01")
    problems += expect(finality.get("contradicting_later_event_overwrites") is False,
                       "ATTEMPT_FINAL_OVERWRITTEN", where,
                       "overwriting destroys the record of why we judged as we did", "NN-13")
    problems += expect(len(str(finality.get("notes") or "")) >= 8, "ATTEMPT_FINALITY_NOTES",
                       where, "say what happens to a contradicting event", "NN-14")
    return problems


def _lifecycle(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    lifecycle = model.get("lifecycle")
    if not isinstance(lifecycle, dict):
        return [Problem("ATTEMPT_SHAPE", where, "lifecycle must be an object", "NN-14")]
    budget.check(str(STATES))
    try:
        machines = load_json(root / STATES)
        machine = next((m for m in (machines.get("machines") or [])
                        if isinstance(m, dict) and m.get("entity") == "PaymentAttempt"), {})
        intent_machine = next((m for m in (machines.get("machines") or [])
                               if isinstance(m, dict) and m.get("entity") == "PaymentIntent"),
                              {})
        success = (machines.get("success_states") or {}).get("PaymentAttempt") or []
    except Exception:
        machine, intent_machine, success = {}, {}, []
    problems: list[Problem] = []
    if machine:
        problems += expect(lifecycle.get("states") == machine.get("states"),
                           "ATTEMPT_STATES_DIVERGE", where,
                           "the states must be exactly the B10 payment-attempt machine",
                           "NN-12")
        problems += expect(lifecycle.get("initial") == machine.get("initial"),
                           "ATTEMPT_STATES_DIVERGE", where,
                           f"initial state must be '{machine.get('initial')}' as in B10",
                           "NN-12")
        problems += expect(lifecycle.get("terminal") == machine.get("terminal"),
                           "ATTEMPT_STATES_DIVERGE", where,
                           "terminal states must match B10", "NN-12")
        terminal = set(machine.get("terminal") or [])
        problems += expect("unknown" not in terminal, "ATTEMPT_UNKNOWN_IS_FINAL", where,
                           "'unknown' must not be a terminal state in B10 either", "NN-03")
    if success:
        problems += expect(lifecycle.get("success_states") == success,
                           "ATTEMPT_SUCCESS_DIVERGE", where,
                           f"success states must match B10's {success}", "NN-01")
    decline_guard = {
        "source": "governance/payment-attempt.json#outcome_classes",
        "field": "settles_intent",
        "equals": True,
    }
    decline_transitions = [
        tr for tr in (intent_machine.get("transitions") or [])
        if isinstance(tr, dict) and tr.get("event") == "provider.declined"
        and tr.get("to") == "failed"
    ]
    problems += expect(bool(decline_transitions), "ATTEMPT_INTENT_DECLINE_UNSCOPED", where,
                       "B10 must declare how a provider decline may settle PaymentIntent",
                       "NN-03")
    for transition in decline_transitions:
        problems += expect(transition.get("requires_outcome_property") == decline_guard,
                           "ATTEMPT_INTENT_DECLINE_UNSCOPED", where,
                           "B10 may move PaymentIntent to failed only for a B33 outcome "
                           "explicitly marked settles_intent=true", "NN-03")
    problems += expect(str(lifecycle.get("source") or "").startswith(str(STATES)),
                       "ATTEMPT_LIFECYCLE_UNSOURCED", where,
                       "the lifecycle must name the B10 machine it comes from", "NN-12")
    budget.check(str(INTENT))
    try:
        intent = load_json(root / INTENT)
        confirmation = intent.get("confirmation") or {}
    except Exception:
        confirmation = {}
    problems += expect(confirmation.get("client_return_page_is_evidence") is False,
                       "ATTEMPT_RETURN_PAGE_EVIDENCE", where,
                       "B32 must still refuse the client return page as evidence; an attempt's "
                       "outcome comes from the provider, not the browser", "NN-01")
    problems += expect(len(str(lifecycle.get("notes") or "")) >= 8, "ATTEMPT_LIFECYCLE_NOTES",
                       where, "say why 'unknown' is not terminal", "NN-14")
    return problems


def _audit_binding(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    event_class = str(model.get("audit_event_class") or "")
    budget.check(str(AUDIT))
    try:
        audit = load_json(root / AUDIT)
        classes = {str(c.get("id")) for c in (audit.get("event_classes") or [])
                   if isinstance(c, dict)}
    except Exception:
        classes = set()
    problems = list(expect(event_class in classes, "ATTEMPT_AUDIT_CLASS_UNKNOWN", where,
                           f"attempt events are recorded as '{event_class}', which "
                           f"governance/audit-log.json does not define", "NN-13"))
    problems += expect(event_class == "money.movement", "ATTEMPT_AUDIT_CLASS_TOO_WEAK", where,
                       "a provider call is a money movement", "NN-13")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .attemptgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("ATTEMPT_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("ATTEMPT_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/payment-attempt.json "
                                    f"but does not exist; run scripts/render-attempt.py",
                                    "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("ATTEMPT_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the model generates", "NN-12"))
    return problems
