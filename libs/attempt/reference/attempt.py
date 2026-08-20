"""B33 — an executable attempt log where a timeout is not a failure.

:meth:`Attempts.start` is where the batch lives. Tenant identity is explicit,
and a process-local lock makes the tenant+intent check and append atomic. It
refuses to open a new attempt while a previous one is ``unknown``, because an
unknown outcome means the money may already have moved, and the second call is
how it moves twice. Resolving the unknown — by querying the provider or by
reading the settlement file — is the only way forward.

:meth:`Attempts.classify` maps a provider code through the taxonomy and sends
everything it does not recognise to ``unknown``. That default is the whole point:
a code nobody has mapped is, by definition, a result nobody knows.

:meth:`Attempts.observe_late_event` handles the event that arrives after a final
attempt and contradicts it. It opens a reconciliation item and leaves the
attempt alone, for the same reason B29 keeps the fee estimate: overwriting
destroys the record of why the judgement was made.

Time is an integer second supplied by the caller.
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field

INITIATED = "initiated"
PENDING = "pending"
SUCCEEDED = "succeeded"
FAILED = "failed"
UNKNOWN = "unknown"

SUCCESS = "succeeded"
FAILED_FINAL = "failed_final"
FAILED_RETRYABLE = "failed_retryable"
UNKNOWN_CLASS = "unknown"

UNRESOLVED_UNKNOWN = "UNRESOLVED_UNKNOWN"
ATTEMPT_IS_FINAL = "ATTEMPT_IS_FINAL"
ATTEMPT_IDENTITY_IMMUTABLE = "ATTEMPT_IDENTITY_IMMUTABLE"
NOT_RETRYABLE = "NOT_RETRYABLE"
RETRIES_EXHAUSTED = "RETRIES_EXHAUSTED"
KEY_CHANGED = "KEY_CHANGED"
KEY_REUSED_FOR_REPLACEMENT = "KEY_REUSED_FOR_REPLACEMENT"
REPLACEMENT_NOT_ALLOWED = "REPLACEMENT_NOT_ALLOWED"
PAYLOAD_NOT_STORED = "PAYLOAD_NOT_STORED"
UNKNOWN_PROVIDER = "UNKNOWN_PROVIDER"
PROVIDER_REQUEST_ID_REQUIRED = "PROVIDER_REQUEST_ID_REQUIRED"
PROVIDER_REQUEST_ID_REUSED = "PROVIDER_REQUEST_ID_REUSED"
PROVIDER_TRANSACTION_ID_REUSED = "PROVIDER_TRANSACTION_ID_REUSED"
RESPONSE_NOT_RECORDED = "RESPONSE_NOT_RECORDED"
TENANT_ID_REQUIRED = "TENANT_ID_REQUIRED"
TENANT_MISMATCH = "TENANT_MISMATCH"
ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
RESOLUTION_METHOD_UNKNOWN = "RESOLUTION_METHOD_UNKNOWN"
RESOLUTION_OVERDUE = "RESOLUTION_OVERDUE"
NOT_UNKNOWN = "NOT_UNKNOWN"

TRANSITIONS = {
    (INITIATED, PENDING), (INITIATED, UNKNOWN),
    (PENDING, SUCCEEDED), (PENDING, FAILED), (PENDING, UNKNOWN),
    (UNKNOWN, SUCCEEDED), (UNKNOWN, FAILED),
}
TERMINAL = {SUCCEEDED, FAILED}
CLASS_TO_STATE = {SUCCESS: SUCCEEDED, FAILED_FINAL: FAILED, FAILED_RETRYABLE: FAILED,
                  UNKNOWN_CLASS: UNKNOWN}


class AttemptRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def digest(request: dict, redacted: tuple[str, ...]) -> str:
    """A digest of the request with the dangerous fields removed first."""
    safe = {k: v for k, v in request.items() if k not in redacted}
    canonical = json.dumps(safe, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def normalised_response(*, provider: str, provider_request_id: str,
                        provider_transaction_id: str | None, provider_code: str | None,
                        provider_code_namespace: str | None, outcome_class: str) -> dict:
    """Return the entire response-evidence shape accepted by this store.

    There is intentionally no raw body or headers parameter. Callers can retain
    the identifiers and classification needed for support and reconciliation,
    but cannot accidentally retain credentials or reusable tokens.
    """
    return {
        "provider": provider,
        "provider_request_id": provider_request_id,
        "provider_transaction_id": provider_transaction_id,
        "provider_code_namespace": provider_code_namespace,
        "provider_code": provider_code,
        "outcome_class": outcome_class,
    }


def response_digest(summary: dict) -> str:
    canonical = json.dumps(summary, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class Attempt:
    id: str
    tenant_id: str
    intent_id: str
    provider: str
    sequence: int
    request_digest: str
    provider_request_id: str
    idempotency_key: str
    started_at: int
    state: str = INITIATED
    outcome_class: str | None = None
    provider_code_namespace: str | None = None
    provider_code: str | None = None
    provider_transaction_id: str | None = None
    response_digest: str | None = None
    finished_at: int | None = None
    _sealed: bool = field(default=False, init=False, repr=False, compare=False)

    def __setattr__(self, name: str, value: object) -> None:
        identity = {"id", "tenant_id", "intent_id", "provider", "sequence",
                    "request_digest", "provider_request_id", "idempotency_key", "started_at"}
        if name in identity and name in self.__dict__:
            raise AttemptRefused(ATTEMPT_IDENTITY_IMMUTABLE, f"{self.id}.{name}")
        # Once terminal, this object is historical evidence. Normal assignment
        # cannot rewrite any field, including state, outcome, identifiers or time.
        if getattr(self, "_sealed", False):
            raise AttemptRefused(ATTEMPT_IS_FINAL, f"{self.id}.{name}")
        object.__setattr__(self, name, value)

    def _update(self, **changes: object) -> None:
        if self._sealed:
            raise AttemptRefused(ATTEMPT_IS_FINAL, self.id)
        for name, value in changes.items():
            object.__setattr__(self, name, value)

    def _seal(self) -> None:
        object.__setattr__(self, "_sealed", True)

    @property
    def is_final(self) -> bool:
        return self.state in TERMINAL

    @property
    def is_unknown(self) -> bool:
        return self.state == UNKNOWN


@dataclass(frozen=True)
class Reconciliation:
    tenant_id: str
    intent_id: str
    attempt_id: str
    recorded_outcome: str
    later_event: str
    at: int


@dataclass
class Log:
    attempts: list[Attempt] = field(default_factory=list)
    reconciliations: list[Reconciliation] = field(default_factory=list)


class Attempts:
    def __init__(self, model: dict, providers: set[str]) -> None:
        self.model = model
        self.providers = providers
        self.classes = {c["id"]: c for c in model["outcome_classes"]}
        self.settling_classes = {c["id"] for c in model["outcome_classes"]
                                 if c["settles_intent"]}
        self.taxonomy = {(e["provider"], e["code_namespace"], e["provider_code"]):
                         e["outcome_class"]
                         for e in model["error_taxonomy"]}
        self.namespaces: dict[str, set[str]] = {}
        for entry in model["error_taxonomy"]:
            self.namespaces.setdefault(entry["provider"], set()).add(entry["code_namespace"])
        self.unmapped = model["unmapped_code_class"]
        self.timeout_policy = model["timeout"]
        self.retry_policy = model["retry"]
        self.record_policy = model["request_record"]
        # This reference is deliberately process-local. The governance model
        # marks durable storage and a database uniqueness constraint as absent;
        # production code must replace this lock with an atomic durable write.
        self._log = Log()
        self._lock = threading.RLock()

    # -- opening an attempt -------------------------------------------------
    @staticmethod
    def _require_tenant_id(tenant_id: str) -> None:
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise AttemptRefused(TENANT_ID_REQUIRED)

    def _assert_tenant(self, tenant_id: str, attempt: Attempt) -> None:
        self._require_tenant_id(tenant_id)
        if attempt.tenant_id != tenant_id:
            raise AttemptRefused(TENANT_MISMATCH, attempt.id)

    def outstanding_unknown(self, tenant_id: str, intent_id: str) -> Attempt | None:
        self._require_tenant_id(tenant_id)
        with self._lock:
            for attempt in self._log.attempts:
                if (attempt.tenant_id == tenant_id and attempt.intent_id == intent_id
                        and attempt.is_unknown):
                    return attempt
        return None

    def for_intent(self, tenant_id: str, intent_id: str) -> list[Attempt]:
        self._require_tenant_id(tenant_id)
        with self._lock:
            return [a for a in self._log.attempts
                    if a.tenant_id == tenant_id and a.intent_id == intent_id]

    def reconciliations_for_tenant(self, tenant_id: str) -> tuple[Reconciliation, ...]:
        self._require_tenant_id(tenant_id)
        with self._lock:
            return tuple(r for r in self._log.reconciliations if r.tenant_id == tenant_id)

    def start(self, intent_id: str, *, tenant_id: str, provider: str, request: dict,
              idempotency_key: str, provider_request_id: str | None = None,
              replacement_request: bool = False, now: int) -> Attempt:
        self._require_tenant_id(tenant_id)
        # The check-and-append is one critical section. Without it, two racing
        # callers can both observe an empty intent and both call the provider.
        with self._lock:
            if provider not in self.providers:
                raise AttemptRefused(UNKNOWN_PROVIDER, provider)
            if provider_request_id is None:
                # Generated independently: external/internal/tenant identifiers
                # are not concatenated into one another.
                provider_request_id = f"pr_{uuid.uuid4().hex}"
            if not isinstance(provider_request_id, str) or not provider_request_id.strip():
                raise AttemptRefused(PROVIDER_REQUEST_ID_REQUIRED)
            if any(a.tenant_id == tenant_id and a.provider == provider
                   and a.provider_request_id == provider_request_id
                   for a in self._log.attempts):
                raise AttemptRefused(PROVIDER_REQUEST_ID_REUSED,
                                     f"{provider}/{provider_request_id}")
            outstanding = self.outstanding_unknown(tenant_id, intent_id)
            if outstanding is not None:
                # The whole batch in one branch: we do not know whether the previous
                # call took the money, so we do not make another one.
                raise AttemptRefused(UNRESOLVED_UNKNOWN, outstanding.id)
            existing = self.for_intent(tenant_id, intent_id)
            # An attempt's terminal state is not the intent's terminal state. B10
            # makes `failed` terminal for the *attempt* — that call is over — but a
            # rate-limited failure is still retryable for the *intent*.
            settled = [a for a in existing if a.outcome_class in self.settling_classes]
            if settled:
                raise AttemptRefused(ATTEMPT_IS_FINAL, settled[0].id)
            if existing:
                last = existing[-1]
                replacement_after = set(
                    self.retry_policy["replacement_request_allowed_after"])
                if replacement_request:
                    if last.outcome_class not in replacement_after:
                        raise AttemptRefused(REPLACEMENT_NOT_ALLOWED,
                                             str(last.outcome_class))
                    if (last.idempotency_key == idempotency_key
                            and self.retry_policy[
                                "replacement_request_requires_new_idempotency_key"]):
                        raise AttemptRefused(KEY_REUSED_FOR_REPLACEMENT, idempotency_key)
                else:
                    if last.outcome_class not in (FAILED_RETRYABLE,) \
                            and self.retry_policy["only_for_retryable"]:
                        raise AttemptRefused(NOT_RETRYABLE, str(last.outcome_class))
                    if last.idempotency_key != idempotency_key \
                            and self.retry_policy["reuse_idempotency_key"]:
                        raise AttemptRefused(KEY_CHANGED, idempotency_key)
                if len(existing) >= int(self.retry_policy["max_attempts_per_intent"]):
                    raise AttemptRefused(RETRIES_EXHAUSTED, str(len(existing)))
            attempt = Attempt(
                id=f"pa_{uuid.uuid4().hex}", tenant_id=tenant_id, intent_id=intent_id,
                provider=provider, sequence=len(existing) + 1,
                request_digest=digest(request, tuple(self.record_policy["redacted_fields"])),
                provider_request_id=provider_request_id,
                idempotency_key=idempotency_key, started_at=now)
            self._log.attempts.append(attempt)
            return attempt

    def stored_request(self, attempt: Attempt, *, tenant_id: str) -> dict:
        """There is no stored request. Only its digest."""
        self._assert_tenant(tenant_id, attempt)
        raise AttemptRefused(PAYLOAD_NOT_STORED, attempt.id)

    def stored_response(self, attempt: Attempt, *, tenant_id: str) -> dict:
        """Return only the normalised, non-sensitive response evidence."""
        self._assert_tenant(tenant_id, attempt)
        with self._lock:
            if attempt.response_digest is None or attempt.outcome_class is None:
                raise AttemptRefused(RESPONSE_NOT_RECORDED, attempt.id)
            summary = normalised_response(
                provider=attempt.provider,
                provider_request_id=attempt.provider_request_id,
                provider_transaction_id=attempt.provider_transaction_id,
                provider_code_namespace=attempt.provider_code_namespace,
                provider_code=attempt.provider_code,
                outcome_class=attempt.outcome_class,
            )
            return summary | {"response_digest": attempt.response_digest}

    # -- classifying a response --------------------------------------------
    def code_namespace(self, provider: str, provider_code: str | None,
                       supplied: str | None = None) -> str | None:
        if provider_code is None:
            return None
        if supplied is not None:
            return supplied
        namespaces = self.namespaces.get(provider, set())
        return next(iter(namespaces)) if len(namespaces) == 1 else None

    def classify(self, provider: str, provider_code: str | None,
                 code_namespace: str | None = None) -> str:
        if provider_code is None:
            return self.unmapped
        namespace = self.code_namespace(provider, provider_code, code_namespace)
        return self.taxonomy.get((provider, namespace, provider_code), self.unmapped)

    def transition(self, attempt: Attempt, target: str, *, tenant_id: str) -> Attempt:
        self._assert_tenant(tenant_id, attempt)
        with self._lock:
            if attempt.is_final:
                raise AttemptRefused(ATTEMPT_IS_FINAL, attempt.state)
            if (attempt.state, target) not in TRANSITIONS:
                raise AttemptRefused(ILLEGAL_TRANSITION, f"{attempt.state} -> {target}")
            attempt._update(state=target)
            if target in TERMINAL:
                attempt._seal()
            return attempt

    def _transaction_id_available(self, attempt: Attempt,
                                  provider_transaction_id: str | None) -> None:
        if provider_transaction_id is None:
            return
        if any(a is not attempt and a.tenant_id == attempt.tenant_id
               and a.provider == attempt.provider
               and a.provider_transaction_id == provider_transaction_id
               for a in self._log.attempts):
            raise AttemptRefused(PROVIDER_TRANSACTION_ID_REUSED,
                                 f"{attempt.provider}/{provider_transaction_id}")

    def record(self, attempt: Attempt, *, tenant_id: str, provider_code: str | None,
               code_namespace: str | None = None,
               provider_transaction_id: str | None = None, now: int) -> str:
        self._assert_tenant(tenant_id, attempt)
        with self._lock:
            if attempt.is_unknown:
                raise AttemptRefused(UNRESOLVED_UNKNOWN, attempt.id)
            namespace = self.code_namespace(attempt.provider, provider_code, code_namespace)
            outcome = self.classify(attempt.provider, provider_code, namespace)
            self._transaction_id_available(attempt, provider_transaction_id)
            summary = normalised_response(
                provider=attempt.provider,
                provider_request_id=attempt.provider_request_id,
                provider_transaction_id=provider_transaction_id,
                provider_code_namespace=namespace,
                provider_code=provider_code,
                outcome_class=outcome,
            )
            if attempt.state == INITIATED and CLASS_TO_STATE[outcome] != UNKNOWN:
                self.transition(attempt, PENDING, tenant_id=tenant_id)
            attempt._update(
                outcome_class=outcome,
                provider_code_namespace=namespace,
                provider_code=provider_code,
                provider_transaction_id=provider_transaction_id,
                response_digest=response_digest(summary),
                finished_at=now,
            )
            self.transition(attempt, CLASS_TO_STATE[outcome], tenant_id=tenant_id)
            return outcome

    def timed_out(self, attempt: Attempt, *, tenant_id: str, now: int) -> str:
        """A timeout has an unknown result. It is never a failure."""
        return self.record(attempt, tenant_id=tenant_id, provider_code=None, now=now)

    # -- resolving an unknown ----------------------------------------------
    def resolve(self, attempt: Attempt, *, tenant_id: str, method: str, provider_code: str,
                code_namespace: str | None = None,
                provider_transaction_id: str | None = None, now: int) -> str:
        self._assert_tenant(tenant_id, attempt)
        with self._lock:
            if not attempt.is_unknown:
                raise AttemptRefused(NOT_UNKNOWN, attempt.state)
            if method not in self.timeout_policy["resolution_methods"]:
                raise AttemptRefused(RESOLUTION_METHOD_UNKNOWN, method)
            hours = (now - (attempt.finished_at or attempt.started_at)) // 3600
            if hours > int(self.timeout_policy["max_resolution_hours"]):
                raise AttemptRefused(RESOLUTION_OVERDUE, str(hours))
            namespace = self.code_namespace(attempt.provider, provider_code, code_namespace)
            outcome = self.classify(attempt.provider, provider_code, namespace)
            if outcome == UNKNOWN_CLASS:
                raise AttemptRefused(UNRESOLVED_UNKNOWN, provider_code)
            self._transaction_id_available(attempt, provider_transaction_id)
            summary = normalised_response(
                provider=attempt.provider,
                provider_request_id=attempt.provider_request_id,
                provider_transaction_id=provider_transaction_id,
                provider_code_namespace=namespace,
                provider_code=provider_code,
                outcome_class=outcome,
            )
            attempt._update(
                outcome_class=outcome,
                provider_code_namespace=namespace,
                provider_code=provider_code,
                provider_transaction_id=provider_transaction_id,
                response_digest=response_digest(summary),
                finished_at=now,
            )
            self.transition(attempt, CLASS_TO_STATE[outcome], tenant_id=tenant_id)
            return outcome

    # -- finality -----------------------------------------------------------
    def intent_outcome(self, tenant_id: str, intent_id: str) -> str | None:
        """The intent's outcome, which only a *settled* attempt can decide.

        Both retryable failures and definitive refusals end their provider
        call without permanently failing the intent. A customer may replace a
        declined funding source; only a class marked ``settles_intent`` decides
        the PaymentIntent.
        """
        for attempt in self.for_intent(tenant_id, intent_id):
            if attempt.outcome_class in self.settling_classes:
                return attempt.outcome_class
        return None

    def observe_late_event(self, attempt: Attempt, *, tenant_id: str, later_outcome: str,
                           now: int) -> Reconciliation | None:
        """A contradicting event opens a break. It never rewrites the attempt."""
        self._assert_tenant(tenant_id, attempt)
        with self._lock:
            if not attempt.is_final:
                raise AttemptRefused(NOT_UNKNOWN, attempt.state)
            if later_outcome == attempt.outcome_class:
                return None
            item = Reconciliation(tenant_id=tenant_id, intent_id=attempt.intent_id,
                                  attempt_id=attempt.id,
                                  recorded_outcome=str(attempt.outcome_class),
                                  later_event=later_outcome, at=now)
            self._log.reconciliations.append(item)
            return item
