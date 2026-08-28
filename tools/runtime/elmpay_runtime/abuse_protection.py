"""B86 layered abuse decisions with atomic multi-dimensional quotas."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Mapping, Protocol

from .common import ValidationError, canonical_json, read_json, require_mapping, require_text, sha256_json
from .security_store import SecurityStore


LAYERS = ("CDN", "WAF", "API", "IDENTITY")
DIMENSIONS = ("TENANT", "ACCOUNT", "DEVICE", "IP")
REPUTATIONS = frozenset({"TRUSTED", "UNKNOWN", "SUSPICIOUS", "MALICIOUS"})
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _identifier(value: object, field: str) -> str:
    text = require_text(value, field)
    if not IDENTIFIER_RE.fullmatch(text):
        raise ValidationError(f"{field} has an invalid format")
    return text


def _instant(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValidationError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class LayerLimits:
    window_seconds: int
    tenant: int
    account: int
    device: int
    ip: int

    def __post_init__(self) -> None:
        if not 1 <= self.window_seconds <= 3600:
            raise ValidationError("abuse quota window must be between one second and one hour")
        for field in ("tenant", "account", "device", "ip"):
            value = getattr(self, field)
            if not 1 <= value <= 10_000_000:
                raise ValidationError(f"{field} quota is outside the safe range")


@dataclass(frozen=True)
class AbusePolicy:
    version: str
    layers: Mapping[str, LayerLimits]
    bot_challenge_basis_points: int
    bot_block_basis_points: int
    risk_challenge_basis_points: int
    risk_block_basis_points: int
    challenge_ttl_seconds: int
    maximum_event_age_seconds: int

    def __post_init__(self) -> None:
        _identifier(self.version, "policy version")
        if set(self.layers) != set(LAYERS):
            raise ValidationError("abuse policy must explicitly configure CDN, WAF, API and IDENTITY")
        thresholds = (
            self.bot_challenge_basis_points,
            self.bot_block_basis_points,
            self.risk_challenge_basis_points,
            self.risk_block_basis_points,
        )
        if any(not 0 <= value <= 10_000 for value in thresholds):
            raise ValidationError("abuse thresholds must use integer basis points")
        if self.bot_challenge_basis_points >= self.bot_block_basis_points:
            raise ValidationError("bot challenge threshold must be below block threshold")
        if self.risk_challenge_basis_points >= self.risk_block_basis_points:
            raise ValidationError("risk challenge threshold must be below block threshold")
        if not 30 <= self.challenge_ttl_seconds <= 900:
            raise ValidationError("challenge TTL is outside the safe range")
        if not 30 <= self.maximum_event_age_seconds <= 3600:
            raise ValidationError("maximum event age is outside the safe range")


def load_abuse_policy(path: str | Path) -> AbusePolicy:
    value = read_json(Path(path))
    root = require_mapping(value, "abuse policy")
    expected = {
        "schemaVersion", "policyVersion", "layers", "bot", "risk",
        "challengeTtlSeconds", "maximumEventAgeSeconds", "externalEdgeDeployment",
    }
    if set(root) != expected:
        raise ValidationError("abuse policy fields do not match schema version 1")
    if root["schemaVersion"] != 1:
        raise ValidationError("unsupported abuse policy schema")
    external = require_mapping(root["externalEdgeDeployment"], "externalEdgeDeployment")
    if set(external) != {"status", "requiredEvidence"} or external["status"] not in {"BLOCKED", "VERIFIED"}:
        raise ValidationError("external edge deployment status is invalid")
    if not isinstance(external["requiredEvidence"], list) or not external["requiredEvidence"]:
        raise ValidationError("external edge deployment evidence list is required")
    raw_layers = require_mapping(root["layers"], "layers")
    layers: dict[str, LayerLimits] = {}
    for layer in LAYERS:
        item = require_mapping(raw_layers.get(layer), f"layers.{layer}")
        if set(item) != {"windowSeconds", "tenant", "account", "device", "ip"}:
            raise ValidationError(f"layers.{layer} fields are invalid")
        try:
            layers[layer] = LayerLimits(
                int(item["windowSeconds"]), int(item["tenant"]), int(item["account"]),
                int(item["device"]), int(item["ip"]),
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"layers.{layer} limits must be integers") from exc
    bot = require_mapping(root["bot"], "bot")
    risk = require_mapping(root["risk"], "risk")
    if set(bot) != {"challengeBasisPoints", "blockBasisPoints"}:
        raise ValidationError("bot thresholds are invalid")
    if set(risk) != {"challengeBasisPoints", "blockBasisPoints"}:
        raise ValidationError("risk thresholds are invalid")
    try:
        return AbusePolicy(
            version=require_text(root["policyVersion"], "policyVersion"),
            layers=layers,
            bot_challenge_basis_points=int(bot["challengeBasisPoints"]),
            bot_block_basis_points=int(bot["blockBasisPoints"]),
            risk_challenge_basis_points=int(risk["challengeBasisPoints"]),
            risk_block_basis_points=int(risk["blockBasisPoints"]),
            challenge_ttl_seconds=int(root["challengeTtlSeconds"]),
            maximum_event_age_seconds=int(root["maximumEventAgeSeconds"]),
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("abuse policy thresholds must be integers") from exc


class SubjectDigester:
    """Pseudonymizes account/device/IP/session values before durable storage."""

    def __init__(self, secret: bytes) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValidationError("subject digest key must contain at least 256 bits")
        self._secret = bytes(secret)

    def digest(self, tenant_id: str, dimension: str, value: str) -> str:
        if dimension not in {*DIMENSIONS, "SESSION"}:
            raise ValidationError("unsupported subject digest dimension")
        message = canonical_json({"tenantId": tenant_id, "dimension": dimension, "value": value})
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AbuseRequest:
    tenant_id: str
    request_id: str
    layer: str
    route_id: str
    occurred_at: datetime
    source_ip: str
    account_id: str | None = None
    device_id: str | None = None
    session_id: str | None = None
    authentication_succeeded: bool = False
    credential_leak_match: bool = False
    webauthn_verified: bool = False
    new_device: bool = False
    impossible_travel: bool = False
    bot_score_basis_points: int = 0
    source_reputation: str = "UNKNOWN"


@dataclass(frozen=True)
class AbuseDecision:
    allowed: bool
    action: str
    risk_score: int
    reasons: tuple[str, ...]
    policy_version: str
    request_id: str
    challenge_id: str | None = None
    case_id: str | None = None


class ChallengeVerifier(Protocol):
    def verify(self, challenge_type: str, binding_digest: str, proof: bytes) -> bool: ...


class AbuseProtectionService:
    _CASE_TRANSITIONS = {
        "INVESTIGATE": ({"OPEN"}, "INVESTIGATING", False),
        "CONTAIN": ({"OPEN", "INVESTIGATING"}, "CONTAINED", False),
        "RESOLVE": ({"CONTAINED"}, "RESOLVED", True),
        "FALSE_POSITIVE": ({"OPEN", "INVESTIGATING", "CONTAINED"}, "FALSE_POSITIVE", True),
        "REOPEN": ({"RESOLVED", "FALSE_POSITIVE"}, "OPEN", True),
    }

    def __init__(self, store: SecurityStore, policy: AbusePolicy, subjects: SubjectDigester) -> None:
        self.store = store
        self.policy = policy
        self.subjects = subjects

    def evaluate(self, request: AbuseRequest, *, now: datetime | None = None) -> AbuseDecision:
        normalized = self._normalize(request, now=now)
        input_digest = sha256_json(normalized["input"])
        tenant = normalized["tenant"]
        decided_at: datetime = normalized["decided_at"]
        occurred_at: datetime = normalized["occurred_at"]
        layer: str = normalized["layer"]
        subject_digests: Mapping[str, str] = normalized["subject_digests"]
        with self.store.transaction() as connection:
            prior = connection.execute(
                "SELECT * FROM abuse_decision WHERE tenant_id=? AND request_id=?",
                (tenant, request.request_id),
            ).fetchone()
            if prior is not None:
                if prior["input_digest"] != input_digest:
                    raise ValidationError("abuse request idempotency conflict")
                return self._decision_from_row(prior)

            limits = self.policy.layers[layer]
            connection.execute("DELETE FROM abuse_counter WHERE expires_at <= ?", (decided_at.isoformat(),))
            exceeded: list[str] = []
            for dimension, digest in subject_digests.items():
                limit = getattr(limits, dimension.casefold())
                bucket = int(occurred_at.timestamp()) // limits.window_seconds
                connection.execute(
                    "INSERT INTO abuse_counter "
                    "(tenant_id,policy_version,layer,dimension,subject_digest,window_start,used,expires_at) "
                    "VALUES (?,?,?,?,?,?,1,?) ON CONFLICT "
                    "(tenant_id,policy_version,layer,dimension,subject_digest,window_start) "
                    "DO UPDATE SET used=used+1",
                    (
                        tenant, self.policy.version, layer, dimension, digest, bucket,
                        (occurred_at + timedelta(seconds=limits.window_seconds * 2)).isoformat(),
                    ),
                )
                used = int(connection.execute(
                    "SELECT used FROM abuse_counter WHERE tenant_id=? AND policy_version=? "
                    "AND layer=? AND dimension=? AND subject_digest=? AND window_start=?",
                    (tenant, self.policy.version, layer, dimension, digest, bucket),
                ).fetchone()[0])
                if used > limit:
                    exceeded.append(dimension)

            score, reasons = self._score(request, layer, exceeded)
            action = "ALLOW"
            if exceeded or score >= self.policy.risk_block_basis_points or request.bot_score_basis_points >= self.policy.bot_block_basis_points:
                action = "BLOCK"
            elif score >= self.policy.risk_challenge_basis_points or request.bot_score_basis_points >= self.policy.bot_challenge_basis_points:
                action = "CHALLENGE"
            if request.webauthn_verified and action == "CHALLENGE" and "BOT_AUTOMATION_SUSPECTED" not in reasons:
                action = "ALLOW"
                reasons.append("WEBAUTHN_STEP_UP_SATISFIED")

            challenge_id: str | None = None
            case_id: str | None = None
            if action == "CHALLENGE":
                challenge_id = "challenge-" + input_digest[:24]
            if action == "BLOCK":
                case_id = "abuse-" + input_digest[:24]
            reasons_tuple = tuple(sorted(set(reasons)))
            connection.execute(
                "INSERT INTO abuse_decision VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    tenant, request.request_id, input_digest, self.policy.version, layer,
                    action, score, json.dumps(reasons_tuple, separators=(",", ":")),
                    challenge_id, case_id, occurred_at.isoformat(), decided_at.isoformat(),
                ),
            )
            if challenge_id is not None:
                challenge_type = (
                    "BOT_PROOF" if "BOT_AUTOMATION_SUSPECTED" in reasons_tuple else "WEBAUTHN_STEP_UP"
                )
                binding_digest = sha256_json({
                    "tenantId": tenant,
                    "requestId": request.request_id,
                    "challengeId": challenge_id,
                    "challengeType": challenge_type,
                    "subjects": subject_digests,
                    "policyVersion": self.policy.version,
                })
                connection.execute(
                    "INSERT INTO abuse_challenge VALUES (?,?,?,?,?,?,?,?)",
                    (
                        tenant, challenge_id, request.request_id, challenge_type, binding_digest,
                        "PENDING",
                        (decided_at + timedelta(seconds=self.policy.challenge_ttl_seconds)).isoformat(),
                        None,
                    ),
                )
            if case_id is not None:
                case_type = self._case_type(request, layer, exceeded, reasons_tuple)
                severity = "CRITICAL" if request.credential_leak_match or request.impossible_travel else "HIGH"
                subject = subject_digests.get("ACCOUNT") or subject_digests.get("DEVICE") or subject_digests["IP"]
                connection.execute(
                    "INSERT INTO abuse_security_case VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        tenant, case_id, case_type, "OPEN", severity, subject,
                        self.policy.version, decided_at.isoformat(), decided_at.isoformat(),
                    ),
                )
                connection.execute(
                    "INSERT INTO abuse_case_event VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        tenant, case_id, "automatic-open", "OPEN_AUTOMATIC", "abuse-engine", None,
                        ";".join(reasons_tuple), input_digest, decided_at.isoformat(),
                    ),
                )
            if action == "BLOCK" and request.session_id is not None and layer == "IDENTITY":
                session_digest = self.subjects.digest(tenant, "SESSION", request.session_id)
                connection.execute(
                    "INSERT OR IGNORE INTO abuse_session_revocation VALUES (?,?,?,?,?)",
                    (tenant, session_digest, request.request_id, ";".join(reasons_tuple), decided_at.isoformat()),
                )
        return AbuseDecision(
            action == "ALLOW", action, score, reasons_tuple, self.policy.version,
            request.request_id, challenge_id, case_id,
        )

    def evaluate_or_block(self, request: AbuseRequest, *, now: datetime | None = None) -> AbuseDecision:
        """Fail closed at the runtime boundary if durable controls are unavailable."""

        try:
            return self.evaluate(request, now=now)
        except (OSError, sqlite3.Error):
            return AbuseDecision(
                False, "BLOCK", 10_000, ("ABUSE_CONTROL_UNAVAILABLE",),
                self.policy.version, request.request_id,
            )

    def complete_challenge(
        self,
        tenant_id: str,
        challenge_id: str,
        proof: bytes,
        verifier: ChallengeVerifier,
        *,
        now: datetime | None = None,
    ) -> str:
        tenant = _identifier(tenant_id, "tenant_id")
        challenge = _identifier(challenge_id, "challenge_id")
        if not isinstance(proof, bytes) or not proof or len(proof) > 16_384:
            raise ValidationError("challenge proof size is invalid")
        instant = _instant(now or datetime.now(timezone.utc), "now")
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT challenge_type,binding_digest,status,expires_at FROM abuse_challenge "
                "WHERE tenant_id=? AND challenge_id=?",
                (tenant, challenge),
            ).fetchone()
            if row is None:
                raise ValidationError("tenant-scoped challenge not found")
            if row["status"] != "PENDING":
                raise ValidationError("challenge is not pending")
            expires_at = datetime.fromisoformat(str(row["expires_at"]))
            if instant >= expires_at:
                connection.execute(
                    "UPDATE abuse_challenge SET status='EXPIRED' WHERE tenant_id=? AND challenge_id=?",
                    (tenant, challenge),
                )
                return "EXPIRED"
            if not verifier.verify(str(row["challenge_type"]), str(row["binding_digest"]), proof):
                return "REJECTED"
            connection.execute(
                "UPDATE abuse_challenge SET status='PASSED',completed_at=? "
                "WHERE tenant_id=? AND challenge_id=?",
                (instant.isoformat(), tenant, challenge),
            )
            return "PASSED"

    def transition_case(
        self,
        tenant_id: str,
        case_id: str,
        *,
        event_id: str,
        action: str,
        actor: str,
        reviewer: str | None,
        reason: str,
        now: datetime | None = None,
    ) -> str:
        tenant = _identifier(tenant_id, "tenant_id")
        case = _identifier(case_id, "case_id")
        event = _identifier(event_id, "event_id")
        actor_id = _identifier(actor, "actor")
        reviewer_id = _identifier(reviewer, "reviewer") if reviewer is not None else None
        normalized_action = require_text(action, "action").upper()
        if normalized_action not in self._CASE_TRANSITIONS:
            raise ValidationError("unsupported abuse case action")
        before_states, after, independent = self._CASE_TRANSITIONS[normalized_action]
        explanation = require_text(reason, "reason")
        if len(explanation) > 1000:
            raise ValidationError("reason is too long")
        if independent and (reviewer_id is None or reviewer_id == actor_id):
            raise ValidationError("independent reviewer is required")
        payload_digest = sha256_json({
            "action": normalized_action, "actor": actor_id,
            "reviewer": reviewer_id, "reason": explanation,
        })
        instant = _instant(now or datetime.now(timezone.utc), "now").isoformat()
        with self.store.transaction() as connection:
            prior = connection.execute(
                "SELECT payload_digest,action FROM abuse_case_event "
                "WHERE tenant_id=? AND case_id=? AND event_id=?",
                (tenant, case, event),
            ).fetchone()
            if prior is not None:
                if prior["payload_digest"] != payload_digest:
                    raise ValidationError("abuse case event idempotency conflict")
                row = connection.execute(
                    "SELECT status FROM abuse_security_case WHERE tenant_id=? AND case_id=?",
                    (tenant, case),
                ).fetchone()
                return str(row[0])
            row = connection.execute(
                "SELECT status FROM abuse_security_case WHERE tenant_id=? AND case_id=?",
                (tenant, case),
            ).fetchone()
            if row is None:
                raise ValidationError("tenant-scoped abuse case not found")
            before = str(row["status"])
            if before not in before_states:
                raise ValidationError(f"action {normalized_action} is invalid from {before}")
            connection.execute(
                "UPDATE abuse_security_case SET status=?,updated_at=? WHERE tenant_id=? AND case_id=?",
                (after, instant, tenant, case),
            )
            connection.execute(
                "INSERT INTO abuse_case_event VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    tenant, case, event, normalized_action, actor_id, reviewer_id,
                    explanation, payload_digest, instant,
                ),
            )
        return after

    def is_session_revoked(self, tenant_id: str, session_id: str) -> bool:
        tenant = _identifier(tenant_id, "tenant_id")
        session = _identifier(session_id, "session_id")
        digest = self.subjects.digest(tenant, "SESSION", session)
        with self.store.connect() as connection:
            return connection.execute(
                "SELECT 1 FROM abuse_session_revocation WHERE tenant_id=? AND session_digest=?",
                (tenant, digest),
            ).fetchone() is not None

    def _normalize(self, request: AbuseRequest, *, now: datetime | None) -> dict[str, Any]:
        tenant = _identifier(request.tenant_id, "tenant_id")
        _identifier(request.request_id, "request_id")
        _identifier(request.route_id, "route_id")
        layer = require_text(request.layer, "layer").upper()
        if layer not in LAYERS:
            raise ValidationError("unsupported abuse control layer")
        occurred = _instant(request.occurred_at, "occurred_at")
        current = _instant(now or datetime.now(timezone.utc), "now")
        maximum_age = timedelta(seconds=self.policy.maximum_event_age_seconds)
        if current - occurred > maximum_age or occurred > current + timedelta(minutes=1):
            raise ValidationError("abuse signal time is outside the accepted window")
        try:
            source_ip = str(ipaddress.ip_address(request.source_ip))
        except ValueError as exc:
            raise ValidationError("source_ip is invalid") from exc
        account = _identifier(request.account_id, "account_id") if request.account_id is not None else None
        device = _identifier(request.device_id, "device_id") if request.device_id is not None else None
        session = _identifier(request.session_id, "session_id") if request.session_id is not None else None
        if layer == "IDENTITY" and account is None:
            raise ValidationError("identity controls require an account identifier")
        if not isinstance(request.bot_score_basis_points, int) or not 0 <= request.bot_score_basis_points <= 10_000:
            raise ValidationError("bot score must use integer basis points")
        reputation = require_text(request.source_reputation, "source_reputation").upper()
        if reputation not in REPUTATIONS:
            raise ValidationError("source reputation is invalid")
        for name in (
            "authentication_succeeded", "credential_leak_match", "webauthn_verified",
            "new_device", "impossible_travel",
        ):
            if not isinstance(getattr(request, name), bool):
                raise ValidationError(f"{name} must be boolean")
        subjects = {
            "TENANT": self.subjects.digest(tenant, "TENANT", tenant),
            "IP": self.subjects.digest(tenant, "IP", source_ip),
        }
        if account is not None:
            subjects["ACCOUNT"] = self.subjects.digest(tenant, "ACCOUNT", account)
        if device is not None:
            subjects["DEVICE"] = self.subjects.digest(tenant, "DEVICE", device)
        input_value = {
            "tenantId": tenant,
            "requestId": request.request_id,
            "layer": layer,
            "routeId": request.route_id,
            "occurredAt": occurred.isoformat(),
            "sourceIp": source_ip,
            "accountId": account,
            "deviceId": device,
            "sessionId": session,
            "authenticationSucceeded": request.authentication_succeeded,
            "credentialLeakMatch": request.credential_leak_match,
            "webauthnVerified": request.webauthn_verified,
            "newDevice": request.new_device,
            "impossibleTravel": request.impossible_travel,
            "botScoreBasisPoints": request.bot_score_basis_points,
            "sourceReputation": reputation,
            "policyVersion": self.policy.version,
        }
        return {
            "tenant": tenant, "layer": layer, "occurred_at": occurred,
            "decided_at": current, "subject_digests": subjects, "input": input_value,
        }

    def _score(self, request: AbuseRequest, layer: str, exceeded: list[str]) -> tuple[int, list[str]]:
        score = request.bot_score_basis_points
        reasons: list[str] = []
        if request.bot_score_basis_points >= self.policy.bot_challenge_basis_points:
            reasons.append("BOT_AUTOMATION_SUSPECTED")
        reputation = request.source_reputation.upper()
        if reputation == "SUSPICIOUS":
            score += 2000
            reasons.append("SOURCE_REPUTATION_SUSPICIOUS")
        elif reputation == "MALICIOUS":
            score += 6000
            reasons.append("SOURCE_REPUTATION_MALICIOUS")
        if request.credential_leak_match:
            score += 9000
            reasons.append("LEAKED_CREDENTIAL_MATCH")
        if request.impossible_travel:
            score += 7000
            reasons.append("IMPOSSIBLE_TRAVEL")
        if request.new_device:
            score += 1500
            reasons.append("NEW_DEVICE")
        if request.authentication_succeeded and layer == "IDENTITY" and (
            request.new_device or request.impossible_travel or reputation in {"SUSPICIOUS", "MALICIOUS"}
        ):
            reasons.append("ACCOUNT_TAKEOVER_RISK")
            if not request.webauthn_verified:
                score += 2500
        for dimension in exceeded:
            reasons.append(f"{layer}_{dimension}_RATE_EXCEEDED")
        return min(score, 10_000), reasons

    @staticmethod
    def _case_type(
        request: AbuseRequest, layer: str, exceeded: list[str], reasons: tuple[str, ...]
    ) -> str:
        if request.authentication_succeeded and (
            request.impossible_travel or request.credential_leak_match or "ACCOUNT_TAKEOVER_RISK" in reasons
        ):
            return "ATO"
        if layer == "IDENTITY" and (exceeded or request.credential_leak_match):
            return "CREDENTIAL_STUFFING"
        if "BOT_AUTOMATION_SUSPECTED" in reasons:
            return "BOT"
        return "DDOS"

    @staticmethod
    def _decision_from_row(row: sqlite3.Row) -> AbuseDecision:
        action = str(row["action"])
        return AbuseDecision(
            allowed=action == "ALLOW",
            action=action,
            risk_score=int(row["risk_score"]),
            reasons=tuple(json.loads(row["reasons_json"])),
            policy_version=str(row["policy_version"]),
            request_id=str(row["request_id"]),
            challenge_id=row["challenge_id"],
            case_id=row["case_id"],
        )
