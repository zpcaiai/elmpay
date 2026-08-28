"""Durable B80-B83/B87 risk decision and operations control plane."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import sqlite3
import threading
from typing import Any, Mapping, Protocol
import urllib.error
import urllib.request

from .common import ValidationError, canonical_json, parse_instant, require_list, require_mapping, require_text


ACTION_ORDER = {"APPROVE": 0, "REVIEW": 1, "BLOCK": 2}
RISK_OPERATIONS = frozenset({
    "PAYMENT_CREATE",
    "PAYMENT_CONFIRM",
    "PAYMENT_CAPTURE",
    "REFUND_REQUEST",
    "CREDENTIAL_CHANGE",
    "PAYMENT_METHOD_ADD",
    "PRIVILEGE_ELEVATION",
})


@dataclass(frozen=True)
class ModelResult:
    available: bool
    version: str
    feature_schema_digest: str
    score: Decimal
    explanation_code: str


class ModelClient(Protocol):
    def score(self, request: Mapping[str, Any], timeout_milliseconds: int) -> ModelResult: ...


class HttpModelClient:
    """Strict finite-value adapter for an independently deployed model server."""

    def __init__(self, endpoint: str, expected_schema_digest: str) -> None:
        if not endpoint.startswith("https://"):
            raise ValidationError("model endpoint must use HTTPS")
        if not __import__("re").fullmatch(r"[0-9a-f]{64}", expected_schema_digest):
            raise ValidationError("model feature schema digest invalid")
        self._endpoint = endpoint
        self._schema = expected_schema_digest

    def score(self, request: Mapping[str, Any], timeout_milliseconds: int) -> ModelResult:
        if timeout_milliseconds < 1:
            raise ValidationError("model timeout must be positive")
        message = urllib.request.Request(
            self._endpoint,
            data=canonical_json(request),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(message, timeout=timeout_milliseconds / 1000) as response:
                if response.status != 200:
                    raise ValidationError("model server returned non-success")
                raw = response.read(65_537)
                if len(raw) > 65_536:
                    raise ValidationError("model response too large")
                document = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(
                    ValidationError(f"model returned non-finite {value}")
                ))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValidationError("model server unavailable or malformed") from exc
        result = require_mapping(document, "model response")
        schema = require_text(result.get("featureSchemaDigest"), "featureSchemaDigest")
        if schema != self._schema:
            raise ValidationError("model feature schema mismatch")
        try:
            score = Decimal(str(result.get("score")))
        except InvalidOperation as exc:
            raise ValidationError("model score invalid") from exc
        if not score.is_finite() or not Decimal(0) <= score <= Decimal(1):
            raise ValidationError("model score outside 0..1")
        explanation = require_text(result.get("explanationCode"), "explanationCode")
        if not __import__("re").fullmatch(r"[A-Z][A-Z0-9_]{2,63}", explanation):
            raise ValidationError("model explanation code invalid")
        return ModelResult(True, require_text(result.get("modelVersion"), "modelVersion"), schema, score, explanation)


@dataclass(frozen=True)
class RiskEvaluation:
    decision_id: str
    tenant_id: str
    request_id: str
    operation: str
    subject_digest: str
    action: str
    reason_codes: tuple[str, ...]
    rule_set_version: str
    rule_set_digest: str
    signal_version: str
    model_version: str
    degraded: bool
    decided_at: datetime


class SQLiteRiskControl:
    """Tenant-scoped rules/signals/decisions/cases with hash-chained audit."""

    def __init__(self, path: str, policy: Mapping[str, Any]) -> None:
        self._policy = policy
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS risk_rule_set(
              tenant_id TEXT NOT NULL, version TEXT NOT NULL, rules_json BLOB NOT NULL,
              content_digest TEXT NOT NULL, proposer TEXT NOT NULL, approver TEXT,
              state TEXT NOT NULL, activate_at TEXT NOT NULL, created_at TEXT NOT NULL,
              PRIMARY KEY(tenant_id,version), UNIQUE(tenant_id,content_digest)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_risk_rule_set
              ON risk_rule_set(tenant_id) WHERE state='ACTIVE';
            CREATE TABLE IF NOT EXISTS risk_signal_snapshot(
              tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, version TEXT NOT NULL,
              collected_at TEXT NOT NULL, expires_at TEXT NOT NULL, values_json BLOB NOT NULL,
              content_digest TEXT NOT NULL, PRIMARY KEY(tenant_id,request_id,version)
            );
            CREATE TABLE IF NOT EXISTS risk_decision(
              tenant_id TEXT NOT NULL, request_id TEXT NOT NULL, request_digest TEXT NOT NULL,
              decision_id TEXT NOT NULL, decision_json BLOB NOT NULL, decided_at TEXT NOT NULL,
              PRIMARY KEY(tenant_id,request_id), UNIQUE(tenant_id,decision_id)
            );
            CREATE TABLE IF NOT EXISTS risk_outbox(
              event_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, event_type TEXT NOT NULL,
              payload_json BLOB NOT NULL, created_at TEXT NOT NULL, published_at TEXT
            );
            CREATE TABLE IF NOT EXISTS risk_operation(
              operation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL,
              subject_digest TEXT NOT NULL, payload_json BLOB NOT NULL, payload_digest TEXT NOT NULL,
              proposer TEXT NOT NULL, approver TEXT, state TEXT NOT NULL,
              expires_at TEXT NOT NULL, created_at TEXT NOT NULL, decided_at TEXT
            );
            CREATE TABLE IF NOT EXISTS risk_list_entry(
              tenant_id TEXT NOT NULL, list_name TEXT NOT NULL, subject_digest TEXT NOT NULL,
              active INTEGER NOT NULL CHECK(active IN(0,1)), changed_by_operation TEXT NOT NULL,
              PRIMARY KEY(tenant_id,list_name,subject_digest)
            );
            CREATE TABLE IF NOT EXISTS risk_case(
              tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, status TEXT NOT NULL,
              subject_digest TEXT NOT NULL, reason TEXT NOT NULL, changed_by_operation TEXT NOT NULL,
              PRIMARY KEY(tenant_id,case_id)
            );
            CREATE TABLE IF NOT EXISTS risk_audit(
              sequence_no INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
              event_type TEXT NOT NULL, payload_digest TEXT NOT NULL, previous_hash TEXT NOT NULL,
              audit_hash TEXT NOT NULL, occurred_at TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._db.close()

    def propose_rule_set(
        self, tenant_id: str, version: str, rules: list[Mapping[str, Any]], proposer: str,
        activate_at: datetime, now: datetime,
    ) -> str:
        require_text(tenant_id, "tenant_id")
        require_text(version, "version")
        require_text(proposer, "proposer")
        normalized = self._validate_rules(rules)
        payload = canonical_json(normalized)
        digest = hashlib.sha256(payload).hexdigest()
        self._db.execute(
            "INSERT INTO risk_rule_set VALUES(?,?,?,?,?,NULL,'PROPOSED',?,?)",
            (tenant_id, version, payload, digest, proposer,
             activate_at.astimezone(timezone.utc).isoformat(), now.astimezone(timezone.utc).isoformat()),
        )
        self._audit(tenant_id, "RISK_RULE_SET_PROPOSED", digest, now)
        return digest

    def approve_rule_set(
        self, tenant_id: str, version: str, approver: str, now: datetime
    ) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT proposer,state,content_digest,activate_at FROM risk_rule_set WHERE tenant_id=? AND version=?",
                    (tenant_id, version),
                ).fetchone()
                if row is None or row[1] != "PROPOSED":
                    raise ValidationError("rule set is not approvable")
                if row[0] == approver:
                    raise ValidationError("rule-set approver must differ from proposer")
                if parse_instant(row[3], "activate_at") > now.astimezone(timezone.utc):
                    state = "APPROVED"
                else:
                    self._db.execute(
                        "UPDATE risk_rule_set SET state='SUPERSEDED' WHERE tenant_id=? AND state='ACTIVE'",
                        (tenant_id,),
                    )
                    state = "ACTIVE"
                self._db.execute(
                    "UPDATE risk_rule_set SET approver=?,state=? WHERE tenant_id=? AND version=? AND state='PROPOSED'",
                    (approver, state, tenant_id, version),
                )
                self._audit(tenant_id, "RISK_RULE_SET_APPROVED", str(row[2]), now)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def activate_due_rule_sets(self, now: datetime) -> int:
        current = now.astimezone(timezone.utc).isoformat()
        tenants = [row[0] for row in self._db.execute(
            "SELECT DISTINCT tenant_id FROM risk_rule_set WHERE state='APPROVED' AND activate_at<=?", (current,)
        )]
        changed = 0
        for tenant in tenants:
            row = self._db.execute(
                "SELECT version FROM risk_rule_set WHERE tenant_id=? AND state='APPROVED' AND activate_at<=? "
                "ORDER BY activate_at DESC LIMIT 1", (tenant, current)
            ).fetchone()
            if row:
                self._db.execute("UPDATE risk_rule_set SET state='SUPERSEDED' WHERE tenant_id=? AND state='ACTIVE'", (tenant,))
                self._db.execute("UPDATE risk_rule_set SET state='ACTIVE' WHERE tenant_id=? AND version=?", (tenant, row[0]))
                changed += 1
        return changed

    def decide(
        self,
        request: Mapping[str, Any],
        signals: Mapping[str, Any],
        model: ModelClient,
        *,
        now: datetime,
    ) -> RiskEvaluation:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = self._decide(request, signals, model, now=now)
                self._db.execute("COMMIT")
                return result
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def _decide(
        self,
        request: Mapping[str, Any],
        signals: Mapping[str, Any],
        model: ModelClient,
        *,
        now: datetime,
    ) -> RiskEvaluation:
        tenant = require_text(request.get("tenantId"), "tenantId")
        request_id = require_text(request.get("requestId"), "requestId")
        operation = require_text(request.get("operation"), "operation")
        allowed_operations = set(self._policy.get("allowedOperations", RISK_OPERATIONS))
        if operation not in RISK_OPERATIONS or operation not in allowed_operations:
            raise ValidationError("risk operation is not supported")
        subject = require_text(request.get("subjectId"), "subjectId")
        subject_digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
        attributes = require_mapping(request.get("attributes", {}), "attributes")
        normalized_attributes: dict[str, str] = {}
        for key, value in attributes.items():
            normalized_key = require_text(key, "attribute name")
            normalized_attributes[normalized_key] = require_text(
                value, f"attribute {normalized_key}"
            )
        amount = request.get("amountMinor")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValidationError("amountMinor must be non-negative integer")
        currency = require_text(request.get("currency"), "currency")
        if not __import__("re").fullmatch(r"[A-Z]{3}", currency):
            raise ValidationError("currency invalid")
        occurred = parse_instant(request.get("occurredAt"), "occurredAt")
        if occurred > now.astimezone(timezone.utc) + timedelta(minutes=5):
            raise ValidationError("request occurredAt is in the future")
        if require_text(signals.get("tenantId"), "signals.tenantId") != tenant:
            raise ValidationError("cross-tenant signal snapshot")
        signal_version = require_text(signals.get("version"), "signals.version")
        collected = parse_instant(signals.get("collectedAt"), "signals.collectedAt")
        expires = parse_instant(signals.get("expiresAt"), "signals.expiresAt")
        values = self._decimal_signals(require_mapping(signals.get("values"), "signals.values"))
        # The product idempotency key binds the semantic mutation payload, not an observation
        # timestamp or a freshly collected signal version. A retried payment must replay the
        # original durable decision while a changed amount/subject/operation remains a conflict.
        request_digest = hashlib.sha256(canonical_json({
            "tenantId": tenant, "requestId": request_id, "operation": operation,
            "subjectId": subject, "amountMinor": amount, "currency": currency,
            "attributes": normalized_attributes,
        })).hexdigest()
        existing = self._db.execute(
            "SELECT request_digest,decision_json FROM risk_decision WHERE tenant_id=? AND request_id=?",
            (tenant, request_id),
        ).fetchone()
        if existing:
            if existing[0] != request_digest:
                raise ValidationError("risk request idempotency conflict")
            return self._decode_decision(bytes(existing[1]))
        stale = (
            collected > now.astimezone(timezone.utc)
            or expires <= now.astimezone(timezone.utc)
            or now.astimezone(timezone.utc) - collected > timedelta(seconds=int(self._policy["maximumSignalAgeSeconds"]))
        )
        rule_row = self._db.execute(
            "SELECT version,rules_json,content_digest FROM risk_rule_set WHERE tenant_id=? AND state='ACTIVE'",
            (tenant,),
        ).fetchone()
        if rule_row is None:
            raise ValidationError("active risk rule set unavailable")
        rules = json.loads(bytes(rule_row[1]))
        signal_payload = canonical_json({**dict(signals), "values": {key: str(value) for key, value in values.items()}})
        signal_digest = hashlib.sha256(signal_payload).hexdigest()
        self._db.execute(
            "INSERT INTO risk_signal_snapshot VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(tenant_id,request_id,version) DO NOTHING",
            (tenant, request_id, signal_version, collected.isoformat(), expires.isoformat(), signal_payload, signal_digest),
        )
        action = "APPROVE"
        reasons: set[str] = set()
        degraded = False
        if stale:
            action = "REVIEW"
            degraded = True
            reasons.add("SIGNALS_STALE")
        else:
            for required_signal in self._policy.get("requiredSignals", []):
                signal_name = require_text(required_signal, "required signal")
                if signal_name not in values:
                    action = self._restrict(action, "REVIEW")
                    degraded = True
                    reasons.add("SIGNAL_MISSING_" + self._reason(signal_name))
            for rule in rules:
                signal_name = str(rule["signal"])
                if signal_name not in values:
                    action = self._restrict(action, "REVIEW")
                    degraded = True
                    reasons.add("SIGNAL_MISSING_" + self._reason(signal_name))
                elif self._matches(values[signal_name], Decimal(str(rule["threshold"])), str(rule["operator"])):
                    action = self._restrict(action, str(rule["action"]))
                    reasons.add(str(rule["reasonCode"]))
        model_version = "unavailable"
        try:
            model_result = model.score({
                "tenantId": tenant, "requestId": request_id, "amountMinor": amount,
                "currency": currency, "operation": operation, "subjectDigest": subject_digest,
                "attributes": normalized_attributes,
                "signals": {key: str(value) for key, value in values.items()},
                "signalVersion": signal_version,
            }, int(self._policy["modelTimeoutMilliseconds"]))
            model_version = model_result.version
            if not model_result.available:
                action = self._restrict(action, "REVIEW")
                degraded = True
                reasons.update(("MODEL_DEGRADED", model_result.explanation_code))
            elif model_result.score >= Decimal(str(self._policy["modelBlockThreshold"])):
                action = "BLOCK"
                reasons.update(("MODEL_BLOCK_THRESHOLD", model_result.explanation_code))
            elif model_result.score >= Decimal(str(self._policy["modelReviewThreshold"])):
                action = self._restrict(action, "REVIEW")
                reasons.update(("MODEL_REVIEW_THRESHOLD", model_result.explanation_code))
        except (ValidationError, RuntimeError, TimeoutError):
            action = self._restrict(action, "REVIEW")
            degraded = True
            reasons.update(("MODEL_DEGRADED", "MODEL_EXECUTION_ERROR"))
        if not reasons:
            reasons.add("NO_RISK_INDICATOR_MATCHED")
        decision_id = hashlib.sha256(canonical_json({
            "tenant": tenant, "request": request_id, "digest": request_digest,
            "signalDigest": signal_digest, "ruleDigest": rule_row[2],
            "modelVersion": model_version, "action": action, "reasons": sorted(reasons),
        })).hexdigest()
        evaluation = RiskEvaluation(decision_id, tenant, request_id, operation, subject_digest,
                                    action, tuple(sorted(reasons)), str(rule_row[0]),
                                    str(rule_row[2]), signal_version, model_version, degraded,
                                    now.astimezone(timezone.utc))
        encoded = self._encode_decision(evaluation)
        self._db.execute(
            "INSERT INTO risk_decision VALUES(?,?,?,?,?,?)",
            (tenant, request_id, request_digest, decision_id, encoded, evaluation.decided_at.isoformat()),
        )
        self._db.execute(
            "INSERT INTO risk_outbox VALUES(?,?,?,?,?,NULL)",
            (decision_id, tenant, "risk.decision.v1", encoded,
             evaluation.decided_at.isoformat()),
        )
        self._audit(tenant, "RISK_DECIDED", decision_id, now)
        return evaluation

    def pending_decision_events(self, limit: int = 100) -> tuple[dict[str, Any], ...]:
        """Return unpublished decision events for an at-least-once outbox publisher."""

        if limit < 1 or limit > 1_000:
            raise ValidationError("outbox limit must be between 1 and 1000")
        rows = self._db.execute(
            "SELECT event_id,tenant_id,event_type,payload_json,created_at FROM risk_outbox "
            "WHERE published_at IS NULL ORDER BY created_at,event_id LIMIT ?", (limit,),
        ).fetchall()
        return tuple({
            "eventId": str(row[0]), "tenantId": str(row[1]), "eventType": str(row[2]),
            "payload": json.loads(bytes(row[3])), "createdAt": str(row[4]),
        } for row in rows)

    def mark_event_published(self, event_id: str, published_at: datetime) -> bool:
        """Idempotently acknowledge one outbox event after broker publication."""

        cursor = self._db.execute(
            "UPDATE risk_outbox SET published_at=? WHERE event_id=? AND published_at IS NULL",
            (published_at.astimezone(timezone.utc).isoformat(),
             require_text(event_id, "event_id")),
        )
        return cursor.rowcount == 1

    def propose_operation(
        self, tenant_id: str, kind: str, subject: str, payload: Mapping[str, Any],
        proposer: str, expires_at: datetime, now: datetime,
    ) -> str:
        if kind not in {"LIST_ADD", "LIST_REMOVE", "CASE_OPEN", "CASE_CLOSE", "CASE_ASSIGN"}:
            raise ValidationError("risk operation kind invalid")
        if expires_at <= now:
            raise ValidationError("risk operation expiry invalid")
        subject_digest = hashlib.sha256(require_text(subject, "subject").encode()).hexdigest()
        document = canonical_json(payload)
        payload_digest = hashlib.sha256(document).hexdigest()
        operation_id = hashlib.sha256(canonical_json({
            "tenant": tenant_id, "kind": kind, "subject": subject_digest,
            "payload": payload_digest, "proposer": proposer,
        })).hexdigest()
        self._db.execute(
            "INSERT INTO risk_operation VALUES(?,?,?,?,?,?,?,NULL,'PROPOSED',?,?,NULL)",
            (operation_id, tenant_id, kind, subject_digest, document, payload_digest, proposer,
             expires_at.astimezone(timezone.utc).isoformat(), now.astimezone(timezone.utc).isoformat()),
        )
        self._audit(tenant_id, "RISK_OPERATION_PROPOSED", payload_digest, now)
        return operation_id

    def approve_operation(self, tenant_id: str, operation_id: str, approver: str, now: datetime) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT kind,subject_digest,payload_json,proposer,state,expires_at,payload_digest "
                    "FROM risk_operation WHERE tenant_id=? AND operation_id=?",
                    (tenant_id, operation_id),
                ).fetchone()
                if row is None or row[4] != "PROPOSED":
                    raise ValidationError("risk operation is not approvable")
                if row[3] == approver:
                    raise ValidationError("risk approver must differ from proposer")
                if parse_instant(row[5], "expires_at") <= now.astimezone(timezone.utc):
                    raise ValidationError("risk operation expired")
                payload = require_mapping(json.loads(bytes(row[2])), "operation payload")
                kind = str(row[0])
                if kind in {"LIST_ADD", "LIST_REMOVE"}:
                    list_name = require_text(payload.get("listName"), "listName")
                    active = 1 if kind == "LIST_ADD" else 0
                    self._db.execute(
                        "INSERT INTO risk_list_entry VALUES(?,?,?,?,?) ON CONFLICT(tenant_id,list_name,subject_digest) "
                        "DO UPDATE SET active=excluded.active,changed_by_operation=excluded.changed_by_operation",
                        (tenant_id, list_name, row[1], active, operation_id),
                    )
                else:
                    case_id = require_text(payload.get("caseId"), "caseId")
                    status = {"CASE_OPEN": "OPEN", "CASE_CLOSE": "CLOSED", "CASE_ASSIGN": "ASSIGNED"}[kind]
                    reason = require_text(payload.get("reason"), "reason")
                    self._db.execute(
                        "INSERT INTO risk_case VALUES(?,?,?,?,?,?) ON CONFLICT(tenant_id,case_id) DO UPDATE SET "
                        "status=excluded.status,reason=excluded.reason,changed_by_operation=excluded.changed_by_operation",
                        (tenant_id, case_id, status, row[1], reason, operation_id),
                    )
                self._db.execute(
                    "UPDATE risk_operation SET approver=?,state='APPROVED',decided_at=? WHERE operation_id=?",
                    (approver, now.astimezone(timezone.utc).isoformat(), operation_id),
                )
                self._audit(tenant_id, "RISK_OPERATION_APPROVED", str(row[6]), now)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def is_listed(self, tenant_id: str, list_name: str, subject: str) -> bool:
        digest = hashlib.sha256(subject.encode()).hexdigest()
        row = self._db.execute(
            "SELECT active FROM risk_list_entry WHERE tenant_id=? AND list_name=? AND subject_digest=?",
            (tenant_id, list_name, digest),
        ).fetchone()
        return bool(row and int(row[0]) == 1)

    def _audit(self, tenant: str, event_type: str, payload_digest: str, now: datetime) -> None:
        previous = self._db.execute(
            "SELECT audit_hash FROM risk_audit ORDER BY sequence_no DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(previous[0]) if previous else "GENESIS"
        audit_hash = hashlib.sha256(canonical_json({
            "tenant": tenant, "event": event_type, "payload": payload_digest,
            "previous": previous_hash, "occurredAt": now.astimezone(timezone.utc).isoformat(),
        })).hexdigest()
        self._db.execute(
            "INSERT INTO risk_audit(tenant_id,event_type,payload_digest,previous_hash,audit_hash,occurred_at) VALUES(?,?,?,?,?,?)",
            (tenant, event_type, payload_digest, previous_hash, audit_hash, now.astimezone(timezone.utc).isoformat()),
        )

    @staticmethod
    def _validate_rules(rules: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        if not rules:
            raise ValidationError("rule set cannot be empty")
        normalized: list[dict[str, Any]] = []
        ids: set[str] = set()
        for raw in rules:
            rule = dict(require_mapping(raw, "rule"))
            identifier = require_text(rule.get("id"), "rule.id")
            if identifier in ids:
                raise ValidationError("duplicate risk rule id")
            ids.add(identifier)
            if rule.get("operator") not in {"GT", "GTE", "LT", "LTE", "EQ"}:
                raise ValidationError("risk rule operator invalid")
            if rule.get("action") not in {"REVIEW", "BLOCK"}:
                raise ValidationError("risk rule cannot auto-approve")
            try:
                threshold = Decimal(str(rule.get("threshold")))
            except InvalidOperation as exc:
                raise ValidationError("risk rule threshold invalid") from exc
            if not threshold.is_finite():
                raise ValidationError("risk rule threshold non-finite")
            require_text(rule.get("signal"), "rule.signal")
            reason = require_text(rule.get("reasonCode"), "rule.reasonCode")
            if not __import__("re").fullmatch(r"[A-Z][A-Z0-9_]{2,63}", reason):
                raise ValidationError("risk rule reason code invalid")
            rule["threshold"] = str(threshold)
            normalized.append(rule)
        return sorted(normalized, key=lambda item: (int(item.get("priority", 0)) * -1, item["id"]))

    @staticmethod
    def _decimal_signals(values: Mapping[str, Any]) -> dict[str, Decimal]:
        result: dict[str, Decimal] = {}
        for key, value in values.items():
            require_text(key, "signal name")
            try:
                decimal = Decimal(str(value))
            except InvalidOperation as exc:
                raise ValidationError("signal value invalid") from exc
            if not decimal.is_finite():
                raise ValidationError("signal value non-finite")
            result[key] = decimal
        return result

    @staticmethod
    def _matches(value: Decimal, threshold: Decimal, operator: str) -> bool:
        return {"GT": value > threshold, "GTE": value >= threshold, "LT": value < threshold,
                "LTE": value <= threshold, "EQ": value == threshold}[operator]

    @staticmethod
    def _restrict(current: str, candidate: str) -> str:
        return candidate if ACTION_ORDER[candidate] > ACTION_ORDER[current] else current

    @staticmethod
    def _reason(value: str) -> str:
        regex = __import__("re")
        words = regex.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
        return regex.sub(r"[^A-Z0-9]+", "_", words.upper()).strip("_")

    @staticmethod
    def _encode_decision(value: RiskEvaluation) -> bytes:
        return canonical_json({
            "decisionId": value.decision_id, "tenantId": value.tenant_id, "requestId": value.request_id,
            "operation": value.operation, "subjectDigest": value.subject_digest,
            "action": value.action, "reasonCodes": value.reason_codes, "ruleSetVersion": value.rule_set_version,
            "ruleSetDigest": value.rule_set_digest, "signalVersion": value.signal_version,
            "modelVersion": value.model_version, "degraded": value.degraded,
            "decidedAt": value.decided_at.isoformat(),
        })

    @staticmethod
    def _decode_decision(value: bytes) -> RiskEvaluation:
        raw = json.loads(value)
        return RiskEvaluation(raw["decisionId"], raw["tenantId"], raw["requestId"], raw["operation"],
                              raw["subjectDigest"], raw["action"], tuple(raw["reasonCodes"]),
                              raw["ruleSetVersion"], raw["ruleSetDigest"],
                              raw["signalVersion"], raw["modelVersion"], bool(raw["degraded"]),
                              parse_instant(raw["decidedAt"], "decidedAt"))
