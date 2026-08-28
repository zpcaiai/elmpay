"""B96-B103 runtime operations: telemetry, SLOs, health and safe admin."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import re
import sqlite3
from typing import Any, Callable, Iterable, Mapping, TypeVar

from .common import GateReport, ValidationError, canonical_json, parse_instant, require_list, require_mapping, require_text


SENSITIVE_KEY = re.compile(
    r"(?i)(?:authorization|cookie|password|secret|api[_-]?key|private[_-]?key|cvv|cvc|card[_-]?number|pan|full[_-]?token)"
)
PAN_LIKE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
ALLOWED_OUTCOMES = {"SUCCEEDED", "FAILED", "DECLINED", "UNKNOWN", "PENDING"}


def _redact(value: Any, *, key: str = "") -> Any:
    if SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(k): _redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(item, key=key) for item in value]
    if isinstance(value, str):
        return PAN_LIKE.sub("[REDACTED]", value)
    return value


def redact_telemetry_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical redacted form used by every telemetry adapter.

    Keeping this boundary public prevents service/export adapters from growing a
    second, subtly different redaction implementation.  Callers receive a fresh
    mapping and cannot mutate the value that is persisted or exported.
    """

    value = _redact(require_mapping(dict(attributes), "telemetry attributes"))
    return dict(require_mapping(value, "redacted telemetry attributes"))


def telemetry_record(
    *,
    tenant_id: str,
    project_id: str,
    trace_id: str,
    correlation_id: str,
    operation: str,
    outcome: str,
    attributes: Mapping[str, Any],
    baggage: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    for value, field in (
        (tenant_id, "tenant_id"), (project_id, "project_id"), (operation, "operation")
    ):
        require_text(value, field)
    if not re.fullmatch(r"[0-9a-f]{32}", trace_id):
        raise ValidationError("trace_id must be 16-byte lowercase hex")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", correlation_id):
        raise ValidationError("correlation_id is invalid")
    if outcome not in ALLOWED_OUTCOMES:
        raise ValidationError("outcome is not a stable payment outcome")
    allowed_baggage = {"region", "provider", "payment_method", "release_id"}
    supplied_baggage = dict(baggage or {})
    if set(supplied_baggage) - allowed_baggage:
        raise ValidationError("baggage contains an unapproved field")
    record = {
        "schemaVersion": 1,
        "tenantId": tenant_id,
        "projectId": project_id,
        "traceId": trace_id,
        "correlationId": correlation_id,
        "operation": operation,
        "outcome": outcome,
        "baggage": supplied_baggage,
        "attributes": redact_telemetry_attributes(attributes),
    }
    encoded = canonical_json(record).decode("utf-8")
    if SENSITIVE_KEY.search(encoded) or PAN_LIKE.search(encoded):
        # Key names may remain in the structured output, but their values cannot.
        for key, value in require_mapping(record["attributes"], "attributes").items():
            if SENSITIVE_KEY.search(key) and value != "[REDACTED]":
                raise ValidationError("telemetry redaction failed")
    return record


def evaluate_slo_samples(policy: Mapping[str, Any], samples: Mapping[str, Any]) -> GateReport:
    reasons: list[str] = []
    checks: list[str] = []
    expected = {require_text(item.get("name"), "slo.name"): item for item in require_list(
        policy.get("services"), "slos.services"
    )}
    if set(samples) != set(expected):
        reasons.append("slo_sample_set_mismatch")
    for name, slo in expected.items():
        raw = samples.get(name)
        if not isinstance(raw, dict):
            reasons.append(f"slo_sample_missing:{name}")
            continue
        good = raw.get("goodEvents")
        total = raw.get("totalEvents")
        if isinstance(good, bool) or isinstance(total, bool) or not isinstance(good, int) or not isinstance(total, int):
            reasons.append(f"slo_count_invalid:{name}")
            continue
        if total <= 0 or good < 0 or good > total:
            reasons.append(f"slo_count_invalid:{name}")
            continue
        achieved = Decimal(good) / Decimal(total)
        objective = Decimal(str(slo["objective"]))
        budget = Decimal(1) - objective
        consumed = (Decimal(1) - achieved) / budget
        if achieved < objective:
            reasons.append(f"slo_objective_missed:{name}")
        observed_burn = Decimal(str(raw.get("maximumBurnRate", "NaN")))
        if not observed_burn.is_finite() or observed_burn < 0:
            reasons.append(f"slo_burn_invalid:{name}")
        else:
            configured = max(Decimal(str(item["threshold"])) for item in slo["burnRates"])
            if observed_burn > configured:
                reasons.append(f"slo_fast_burn:{name}")
        checks.append(f"slo:{name}:budget_consumed={consumed}")
    return GateReport.from_reasons(reasons, checks)


@dataclass(frozen=True)
class FunnelCell:
    dimensions: tuple[tuple[str, str], ...]
    started: int
    authorized: int
    captured: int
    failed: int
    amount_minor: int


def aggregate_funnel(
    events: Iterable[Mapping[str, Any]],
    tenant_id: str,
    policy: Mapping[str, Any] | None = None,
) -> tuple[FunnelCell, ...]:
    configured = policy or {
        "allowedDimensions": [
            "projectId", "provider", "region", "deviceClass", "failureCode", "releaseId"
        ],
        "allowedStages": ["STARTED", "AUTHORIZED", "CAPTURED", "FAILED"],
        "maximumEvents": 100_000,
    }
    dimensions_value = require_list(configured.get("allowedDimensions"), "allowedDimensions")
    permitted_dimensions = {
        "projectId", "provider", "region", "deviceClass", "failureCode", "releaseId"
    }
    if not dimensions_value or len(dimensions_value) != len(set(dimensions_value)):
        raise ValidationError("funnel dimensions must be unique and non-empty")
    if any(not isinstance(item, str) or item not in permitted_dimensions for item in dimensions_value):
        raise ValidationError("funnel policy contains an unsupported dimension")
    allowed_dimensions = tuple(dimensions_value)
    allowed_stages = set(require_list(configured.get("allowedStages"), "allowedStages"))
    if allowed_stages != {"STARTED", "AUTHORIZED", "CAPTURED", "FAILED"}:
        raise ValidationError("funnel stage policy must cover the governed lifecycle")
    maximum_events = configured.get("maximumEvents")
    if isinstance(maximum_events, bool) or not isinstance(maximum_events, int) \
            or maximum_events < 1 or maximum_events > 1_000_000:
        raise ValidationError("funnel maximumEvents is outside the safe bound")
    cells: dict[tuple[tuple[str, str], ...], list[int]] = {}
    seen: set[str] = set()
    for index, raw in enumerate(events):
        if index >= maximum_events:
            raise ValidationError("funnel event input exceeds the governed bound")
        event = require_mapping(raw, "funnel event")
        if require_text(event.get("tenantId"), "tenantId") != tenant_id:
            raise ValidationError("cross-tenant funnel event")
        event_id = require_text(event.get("eventId"), "eventId")
        if event_id in seen:
            continue
        seen.add(event_id)
        stage = event.get("stage")
        if stage not in allowed_stages:
            raise ValidationError("unknown funnel stage")
        amount = event.get("amountMinor", 0)
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValidationError("funnel amount must be non-negative integer minor units")
        dimensions = tuple((key, str(event.get(key, "UNKNOWN"))) for key in allowed_dimensions)
        bucket = cells.setdefault(dimensions, [0, 0, 0, 0, 0])
        bucket[{"STARTED": 0, "AUTHORIZED": 1, "CAPTURED": 2, "FAILED": 3}[stage]] += 1
        if stage == "CAPTURED":
            bucket[4] += amount
    return tuple(FunnelCell(key, *value) for key, value in sorted(cells.items()))


@dataclass(frozen=True)
class SecurityAlert:
    rule_id: str
    severity: str
    actor: str
    responses: tuple[str, ...]


def evaluate_security_events(policy: Mapping[str, Any], events: Iterable[Mapping[str, Any]]) -> tuple[SecurityAlert, ...]:
    rules = {require_text(item.get("id"), "rule.id"): item for item in require_list(policy.get("rules"), "rules")}
    supported = {
        "SIEM-ADMIN-IMPOSSIBLE-TRAVEL",
        "SIEM-FOUR-EYES-BYPASS",
        "SIEM-SECRET-ACCESS-SPIKE",
        "SIEM-GITOPS-DRIFT",
    }
    if set(rules) != supported:
        raise ValidationError("SIEM rule implementation and policy are out of sync")
    countries: dict[str, set[str]] = {}
    alerts: list[SecurityAlert] = []
    for raw in events:
        event = require_mapping(raw, "security event")
        event_type = require_text(event.get("eventType"), "eventType")
        actor = require_text(event.get("actor"), "actor")
        triggered: list[str] = []
        if event_type == "admin.authentication.succeeded":
            countries.setdefault(actor, set()).add(require_text(event.get("country"), "country"))
            if len(countries[actor]) > 1:
                triggered.append("SIEM-ADMIN-IMPOSSIBLE-TRAVEL")
        if event_type == "approval.decided" and (
            event.get("proposerId") == event.get("approverId") or event.get("phishingResistant") is not True
        ):
            triggered.append("SIEM-FOUR-EYES-BYPASS")
        if event_type == "secret.read":
            count = event.get("readsPerActor5m")
            baseline = event.get("baselineP99")
            if not isinstance(count, int) or not isinstance(baseline, int):
                raise ValidationError("secret read counters are required")
            if count > baseline:
                triggered.append("SIEM-SECRET-ACCESS-SPIKE")
        if event_type == "gitops.drift.detected" and int(event.get("ageSeconds", -1)) > 120:
            triggered.append("SIEM-GITOPS-DRIFT")
        for rule_id in triggered:
            rule = rules[rule_id]
            alerts.append(SecurityAlert(rule_id, str(rule["severity"]), actor, tuple(rule["response"])))
    return tuple(alerts)


class SQLiteOperationsStore:
    """Durable provider breaker, four-eyes actions and incident lifecycle."""

    def __init__(self, path: str) -> None:
        self._db = sqlite3.connect(path, timeout=5, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS provider_health (
              tenant_id TEXT NOT NULL, account_id TEXT NOT NULL,
              state TEXT NOT NULL, open_until TEXT, half_open_used INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL, PRIMARY KEY(tenant_id, account_id)
            );
            CREATE TABLE IF NOT EXISTS provider_outcome (
              tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, observed_at TEXT NOT NULL,
              succeeded INTEGER NOT NULL CHECK(succeeded IN (0,1)), latency_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS provider_outcome_window
              ON provider_outcome(tenant_id, account_id, observed_at);
            CREATE TABLE IF NOT EXISTS admin_action (
              action_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, action_type TEXT NOT NULL,
              target TEXT NOT NULL, payload BLOB NOT NULL, payload_digest TEXT NOT NULL,
              proposer TEXT NOT NULL, approver TEXT, state TEXT NOT NULL,
              proposed_at TEXT NOT NULL, approved_at TEXT, execution_receipt TEXT
            );
            CREATE TABLE IF NOT EXISTS incident (
              incident_id TEXT PRIMARY KEY, severity TEXT NOT NULL, service TEXT NOT NULL,
              public_summary TEXT NOT NULL, state TEXT NOT NULL, owner TEXT NOT NULL,
              version INTEGER NOT NULL, opened_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._db.close()

    def provider_before_call(
        self, tenant_id: str, account_id: str, policy: Mapping[str, Any], now: datetime
    ) -> bool:
        current = now.astimezone(timezone.utc)
        row = self._db.execute(
            "SELECT state, open_until, half_open_used FROM provider_health WHERE tenant_id=? AND account_id=?",
            (tenant_id, account_id),
        ).fetchone()
        if row is None:
            return True
        state, open_until, used = row
        if state == "OPEN":
            if parse_instant(open_until, "open_until") > current:
                return False
            self._db.execute(
                "UPDATE provider_health SET state='HALF_OPEN', half_open_used=1, updated_at=? "
                "WHERE tenant_id=? AND account_id=?",
                (current.isoformat(), tenant_id, account_id),
            )
            return True
        if state == "HALF_OPEN":
            maximum = int(require_mapping(policy.get("circuitBreaker"), "circuitBreaker")["halfOpenCalls"])
            if int(used) >= maximum:
                return False
            self._db.execute(
                "UPDATE provider_health SET half_open_used=half_open_used+1, updated_at=? "
                "WHERE tenant_id=? AND account_id=?",
                (current.isoformat(), tenant_id, account_id),
            )
        return True

    def provider_record(
        self,
        tenant_id: str,
        account_id: str,
        succeeded: bool,
        latency_ms: int,
        policy: Mapping[str, Any],
        now: datetime,
    ) -> str:
        if isinstance(latency_ms, bool) or not isinstance(latency_ms, int) or latency_ms < 0:
            raise ValidationError("latency_ms must be non-negative integer")
        breaker = require_mapping(policy.get("circuitBreaker"), "circuitBreaker")
        current = now.astimezone(timezone.utc)
        window_start = current - timedelta(seconds=max(60, int(breaker["openSeconds"]) * 2))
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute(
                "INSERT INTO provider_outcome VALUES (?, ?, ?, ?, ?)",
                (tenant_id, account_id, current.isoformat(), 1 if succeeded else 0, latency_ms),
            )
            self._db.execute("DELETE FROM provider_outcome WHERE observed_at < ?", (window_start.isoformat(),))
            row = self._db.execute(
                "SELECT state,open_until,half_open_used FROM provider_health WHERE tenant_id=? AND account_id=?",
                (tenant_id, account_id),
            ).fetchone()
            state = str(row[0]) if row else "HEALTHY"
            prior_open_until = parse_instant(row[1], "open_until") if row and row[1] else None
            half_open_used = int(row[2]) if row else 0
            count, failures = self._db.execute(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN succeeded=0 THEN 1 ELSE 0 END),0) "
                "FROM provider_outcome WHERE tenant_id=? AND account_id=? AND observed_at>=?",
                (tenant_id, account_id, window_start.isoformat()),
            ).fetchone()
            should_open = (
                int(count) >= int(breaker["minimumCalls"])
                and Decimal(int(failures)) / Decimal(int(count)) >= Decimal(str(breaker["failureRateThreshold"]))
            )
            if state == "HALF_OPEN":
                if succeeded:
                    if half_open_used >= int(breaker["halfOpenCalls"]):
                        state = "HEALTHY"
                        open_until = None
                        half_open_used = 0
                    else:
                        state = "HALF_OPEN"
                        open_until = None
                else:
                    state = "OPEN"
                    open_until = current + timedelta(seconds=int(breaker["openSeconds"]))
                    half_open_used = 0
            elif should_open:
                state = "OPEN"
                open_until = current + timedelta(seconds=int(breaker["openSeconds"]))
                half_open_used = 0
            elif state == "OPEN":
                open_until = prior_open_until
            else:
                open_until = None
            self._db.execute(
                "INSERT INTO provider_health(tenant_id,account_id,state,open_until,half_open_used,updated_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(tenant_id,account_id) DO UPDATE SET "
                "state=excluded.state,open_until=excluded.open_until,half_open_used=excluded.half_open_used,updated_at=excluded.updated_at",
                (tenant_id, account_id, state, open_until.isoformat() if open_until else None, half_open_used, current.isoformat()),
            )
            self._db.execute("COMMIT")
            return state
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def propose_action(
        self,
        *,
        tenant_id: str,
        action_type: str,
        target: str,
        payload: Mapping[str, Any],
        proposer: str,
        now: datetime,
    ) -> str:
        if action_type not in {"WEBHOOK_REPLAY", "PROVIDER_OVERRIDE", "RECONCILIATION_RETRY", "STATE_REPAIR"}:
            raise ValidationError("admin action type is not allowed")
        document = canonical_json(payload)
        digest = hashlib.sha256(document).hexdigest()
        action_id = hashlib.sha256(canonical_json({
            "tenant": tenant_id, "type": action_type, "target": target,
            "digest": digest, "proposer": proposer,
        })).hexdigest()
        try:
            self._db.execute(
                "INSERT INTO admin_action(action_id,tenant_id,action_type,target,payload,payload_digest,proposer,state,proposed_at) "
                "VALUES(?,?,?,?,?,?,?,'PROPOSED',?)",
                (action_id, tenant_id, action_type, target, document, digest, proposer, now.astimezone(timezone.utc).isoformat()),
            )
        except sqlite3.IntegrityError:
            row = self._db.execute(
                "SELECT payload_digest FROM admin_action WHERE action_id=?", (action_id,)
            ).fetchone()
            if row is None or row[0] != digest:
                raise ValidationError("admin action idempotency conflict")
        return action_id

    def approve_action(self, action_id: str, approver: str, now: datetime) -> None:
        row = self._db.execute(
            "SELECT proposer,state FROM admin_action WHERE action_id=?", (action_id,)
        ).fetchone()
        if row is None or row[1] != "PROPOSED":
            raise ValidationError("admin action is not approvable")
        if row[0] == approver:
            raise ValidationError("admin approver must differ from proposer")
        self._db.execute(
            "UPDATE admin_action SET approver=?,state='APPROVED',approved_at=? WHERE action_id=? AND state='PROPOSED'",
            (approver, now.astimezone(timezone.utc).isoformat(), action_id),
        )

    def execute_action(self, action_id: str, executor: Callable[[str, str, str, bytes], str]) -> str:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute(
                "SELECT tenant_id,target,payload,state,execution_receipt FROM admin_action WHERE action_id=?",
                (action_id,),
            ).fetchone()
            if row is None:
                raise ValidationError("admin action not found")
            if row[3] == "EXECUTED":
                self._db.execute("COMMIT")
                return str(row[4])
            if row[3] != "APPROVED":
                raise ValidationError("admin action lacks independent approval or is already executing")
            changed = self._db.execute(
                "UPDATE admin_action SET state='EXECUTING' WHERE action_id=? AND state='APPROVED'",
                (action_id,),
            ).rowcount
            if changed != 1:
                raise ValidationError("admin action execution claim conflict")
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        # The action id is the mandatory downstream idempotency key.  A crash
        # after the call leaves EXECUTING/UNKNOWN for explicit reconciliation.
        receipt = require_text(executor(action_id, str(row[0]), str(row[1]), bytes(row[2])), "execution receipt")
        changed = self._db.execute(
            "UPDATE admin_action SET state='EXECUTED',execution_receipt=? WHERE action_id=? AND state='EXECUTING'",
            (receipt, action_id),
        ).rowcount
        if changed != 1:
            raise ValidationError("admin action receipt conflict")
        return receipt

    def open_incident(
        self, incident_id: str, severity: str, service: str, public_summary: str, owner: str, now: datetime
    ) -> None:
        if severity not in {"SEV0", "SEV1", "SEV2", "SEV3"}:
            raise ValidationError("incident severity invalid")
        if any(token in public_summary.lower() for token in ("tenant_", "api_key", "card number")):
            raise ValidationError("public incident summary contains restricted detail")
        instant = now.astimezone(timezone.utc).isoformat()
        self._db.execute(
            "INSERT INTO incident VALUES(?,?,?,?, 'OPEN', ?,1,?,?)",
            (incident_id, severity, service, public_summary, owner, instant, instant),
        )

    def transition_incident(
        self, incident_id: str, expected_version: int, target: str, now: datetime
    ) -> None:
        allowed = {"OPEN": "MITIGATING", "MITIGATING": "MONITORING", "MONITORING": "RESOLVED"}
        row = self._db.execute(
            "SELECT state,version FROM incident WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None or int(row[1]) != expected_version or allowed.get(str(row[0])) != target:
            raise ValidationError("incident transition conflict")
        changed = self._db.execute(
            "UPDATE incident SET state=?,version=version+1,updated_at=? WHERE incident_id=? AND version=?",
            (target, now.astimezone(timezone.utc).isoformat(), incident_id, expected_version),
        ).rowcount
        if changed != 1:
            raise ValidationError("incident optimistic lock conflict")

    def incident_status(self, incident_id: str) -> dict[str, Any]:
        """Return the deliberately public, PII-free status-page projection."""
        row = self._db.execute(
            "SELECT incident_id,severity,service,public_summary,state,owner,version,opened_at,updated_at "
            "FROM incident WHERE incident_id=?",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise ValidationError("incident not found")
        return {
            "schemaVersion": 1,
            "incidentId": str(row[0]),
            "severity": str(row[1]),
            "service": str(row[2]),
            "summary": str(row[3]),
            "state": str(row[4]),
            "owner": str(row[5]),
            "version": int(row[6]),
            "openedAt": str(row[7]),
            "updatedAt": str(row[8]),
        }


ProviderResult = TypeVar("ProviderResult")


def execute_provider_call(
    store: SQLiteOperationsStore,
    *,
    tenant_id: str,
    account_id: str,
    policy: Mapping[str, Any],
    operation: Callable[[], ProviderResult],
    now: Callable[[], datetime],
    monotonic_ns: Callable[[], int],
) -> ProviderResult:
    """Run one provider call through the durable breaker and record its outcome.

    The wrapper is intentionally generic so connector runtimes cannot forget the
    before-call check or outcome recording.  An open breaker fails before the
    network operation, and failures are re-raised after durable accounting.
    """
    started_at = now().astimezone(timezone.utc)
    if not store.provider_before_call(tenant_id, account_id, policy, started_at):
        raise ValidationError("provider circuit is open")
    started_ns = monotonic_ns()
    try:
        result = operation()
    except Exception:
        elapsed = max(0, (monotonic_ns() - started_ns) // 1_000_000)
        store.provider_record(tenant_id, account_id, False, int(elapsed), policy, now())
        raise
    elapsed = max(0, (monotonic_ns() - started_ns) // 1_000_000)
    store.provider_record(tenant_id, account_id, True, int(elapsed), policy, now())
    return result


def evaluate_capacity_freshness(
    report: GateReport,
    samples: Mapping[str, Any],
    *,
    now: datetime,
    maximum_age: timedelta = timedelta(hours=24),
) -> GateReport:
    reasons = list(report.reasons)
    checks = list(report.checks)
    for resource, raw in samples.items():
        values = require_list(raw, f"samples.{resource}")
        if not values:
            reasons.append(f"capacity_sample_missing:{resource}")
            continue
        latest = max(parse_instant(require_mapping(item, "sample").get("observedAt"), "observedAt") for item in values)
        if latest > now.astimezone(timezone.utc) + timedelta(minutes=5):
            reasons.append(f"capacity_sample_in_future:{resource}")
        elif now.astimezone(timezone.utc) - latest > maximum_age:
            reasons.append(f"capacity_sample_stale:{resource}")
        else:
            checks.append(f"capacity_fresh:{resource}")
    return GateReport.from_reasons(reasons, checks)
