"""B84 IDN/homograph monitoring and auditable takedown workflow."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
import sqlite3
import unicodedata
from pathlib import Path
from typing import Any, Mapping

from .common import (
    GateReport,
    ValidationError,
    canonical_json,
    read_json,
    require_mapping,
    require_text,
    sha256_json,
)
from .security_store import SecurityStore


IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SOURCES = frozenset({"CT", "DNS", "REGISTRAR", "AD", "SOCIAL", "CUSTOMER_REPORT"})

# A bounded, reviewed subset of the Unicode confusables that are useful in
# domain abuse.  NFKD and mark removal run first; unknown non-Latin scripts are
# retained, which prevents an unsupported character from becoming a false match.
_CONFUSABLES = str.maketrans({
    "а": "a", "ɑ": "a", "α": "a", "ӓ": "a",
    "Ь": "b", "в": "b", "β": "b",
    "с": "c", "ϲ": "c", "ҫ": "c",
    "ԁ": "d", "ժ": "d",
    "е": "e", "ε": "e", "ё": "e", "ҽ": "e",
    "ғ": "f", "ϝ": "f",
    "ɡ": "g", "ց": "g",
    "һ": "h", "н": "h", "η": "h",
    "і": "i", "ı": "i", "ι": "i", "ї": "i", "ӏ": "i",
    "ј": "j", "ϳ": "j",
    "κ": "k", "к": "k",
    "Ӏ": "l", "ⅼ": "l", "ӏ": "l",
    "м": "m", "μ": "m",
    "ո": "n", "п": "n", "η": "n",
    "о": "o", "ο": "o", "օ": "o", "ө": "o", "0": "o",
    "р": "p", "ρ": "p", "ҏ": "p",
    "ԛ": "q", "զ": "q",
    "г": "r", "ᴦ": "r",
    "ѕ": "s", "ꜱ": "s", "ş": "s",
    "т": "t", "τ": "t",
    "υ": "u", "ս": "u", "ц": "u",
    "ν": "v", "ѵ": "v",
    "ԝ": "w", "ω": "w",
    "х": "x", "χ": "x",
    "у": "y", "γ": "y", "ү": "y",
    "ᴢ": "z", "ζ": "z",
})


def _identifier(value: object, field: str) -> str:
    text = require_text(value, field)
    if not IDENTIFIER_RE.fullmatch(text):
        raise ValidationError(f"{field} has an invalid format")
    return text


def _instant(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValidationError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def normalize_domain(value: object) -> str:
    """Return a canonical IDNA ASCII domain and reject URL-shaped input."""

    raw = require_text(value, "domain").strip().rstrip(".")
    if (
        len(raw) > 253
        or any(character.isspace() for character in raw)
        or any(token in raw for token in ("://", "/", "\\", "@", "*", "?", "#", ":"))
        or raw.startswith(".")
        or ".." in raw
    ):
        raise ValidationError("domain must be a bare canonical hostname")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValidationError("IP addresses are not brand domains")
    try:
        ascii_domain = raw.encode("idna").decode("ascii").lower()
        unicode_domain = ascii_domain.encode("ascii").decode("idna")
        roundtrip = unicode_domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError("domain is not valid IDNA") from exc
    if roundtrip != ascii_domain:
        raise ValidationError("domain is not stable under IDNA round-trip")
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not LABEL_RE.fullmatch(label) for label in labels):
        raise ValidationError("domain labels are invalid")
    return ascii_domain


def unicode_domain(ascii_domain: str) -> str:
    try:
        return ascii_domain.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise ValidationError("stored domain is not valid IDNA") from exc


def confusable_skeleton(value: object) -> str:
    ascii_domain = normalize_domain(value)
    decoded = unicode_domain(ascii_domain)
    decomposed = unicodedata.normalize("NFKD", decoded.casefold())
    without_marks = "".join(
        character for character in decomposed if unicodedata.category(character) != "Mn"
    )
    return without_marks.translate(_CONFUSABLES)


def domain_scripts(value: object) -> tuple[str, ...]:
    decoded = unicode_domain(normalize_domain(value))
    scripts: set[str] = set()
    for character in decoded:
        if character in ".-" or character.isdigit():
            continue
        name = unicodedata.name(character, "")
        for script in ("LATIN", "CYRILLIC", "GREEK", "HEBREW", "ARABIC", "HIRAGANA", "KATAKANA", "HANGUL", "CJK"):
            if script in name:
                scripts.add("HAN" if script == "CJK" else script)
                break
        else:
            scripts.add("OTHER")
    return tuple(sorted(scripts))


def _edit_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for row, left_character in enumerate(left, start=1):
        current = [row]
        for column, right_character in enumerate(right, start=1):
            current.append(min(
                current[-1] + 1,
                previous[column] + 1,
                previous[column - 1] + (left_character != right_character),
            ))
        previous = current
    return previous[-1]


@dataclass(frozen=True)
class BrandPolicy:
    rule_version: str
    official_domains: tuple[str, ...]
    protected_labels: tuple[str, ...]
    allowed_ct_issuers: tuple[str, ...] = ()
    maximum_label_edit_distance: int = 1
    maximum_observation_age: timedelta = timedelta(hours=24)

    def __post_init__(self) -> None:
        _identifier(self.rule_version, "rule_version")
        domains = tuple(sorted({normalize_domain(value) for value in self.official_domains}))
        if not domains:
            raise ValidationError("at least one deployment-bound official domain is required")
        labels: list[str] = []
        for value in self.protected_labels:
            label = require_text(value, "protected_label").casefold()
            if not re.fullmatch(r"[a-z0-9-]{3,63}", label):
                raise ValidationError("protected labels must be lowercase ASCII domain labels")
            labels.append(label)
        if not labels:
            raise ValidationError("at least one protected brand label is required")
        if not 0 <= self.maximum_label_edit_distance <= 2:
            raise ValidationError("maximum label edit distance must be between zero and two")
        if not timedelta(minutes=1) <= self.maximum_observation_age <= timedelta(days=7):
            raise ValidationError("maximum observation age is outside the safe range")
        object.__setattr__(self, "official_domains", domains)
        object.__setattr__(self, "protected_labels", tuple(sorted(set(labels))))
        object.__setattr__(self, "allowed_ct_issuers", tuple(sorted(set(self.allowed_ct_issuers))))


@dataclass(frozen=True)
class DomainObservation:
    tenant_id: str
    source: str
    observation_id: str
    domain: str
    observed_at: datetime
    certificate_issuer: str | None = None


@dataclass(frozen=True)
class BrandAssessment:
    domain_ascii: str
    decision: str
    severity: str
    reasons: tuple[str, ...]
    features: Mapping[str, Any]
    rule_version: str
    decision_digest: str
    case_id: str | None = None


@dataclass(frozen=True)
class DomainControlPosture:
    tenant_id: str
    domain: str
    dnssec: bool
    caa_issuers: tuple[str, ...]
    registry_lock: bool
    transfer_lock: bool
    registrar_hardware_mfa: bool
    dmarc_policy: str
    observed_at: datetime


def load_brand_policy(path: str | Path) -> BrandPolicy:
    value = require_mapping(read_json(Path(path)), "brand policy")
    expected = {
        "schemaVersion", "ruleVersion", "officialDomains", "protectedLabels",
        "allowedCertificateAuthorities", "maximumLabelEditDistance",
        "maximumObservationAgeSeconds", "requiredDomainControls", "externalMonitoring",
    }
    if set(value) != expected or value["schemaVersion"] != 1:
        raise ValidationError("brand policy fields do not match schema version 1")
    external = require_mapping(value["externalMonitoring"], "externalMonitoring")
    if set(external) != {"status", "requiredEvidence"} or external["status"] not in {"BLOCKED", "VERIFIED"}:
        raise ValidationError("external brand-monitoring status is invalid")
    controls = value["requiredDomainControls"]
    if not isinstance(controls, list) or set(controls) != {
        "DNSSEC", "CAA", "REGISTRY_LOCK", "TRANSFER_LOCK", "HARDWARE_MFA", "DMARC_REJECT",
    }:
        raise ValidationError("required domain controls are incomplete")
    try:
        return BrandPolicy(
            rule_version=require_text(value["ruleVersion"], "ruleVersion"),
            official_domains=tuple(value["officialDomains"]),
            protected_labels=tuple(value["protectedLabels"]),
            allowed_ct_issuers=tuple(value["allowedCertificateAuthorities"]),
            maximum_label_edit_distance=int(value["maximumLabelEditDistance"]),
            maximum_observation_age=timedelta(seconds=int(value["maximumObservationAgeSeconds"])),
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("brand policy values are invalid") from exc


def assess_domain(policy: BrandPolicy, observation: DomainObservation, *, now: datetime | None = None) -> BrandAssessment:
    _identifier(observation.tenant_id, "tenant_id")
    _identifier(observation.observation_id, "observation_id")
    source = require_text(observation.source, "source").upper()
    if source not in SOURCES:
        raise ValidationError("unsupported brand observation source")
    observed_at = _instant(observation.observed_at, "observed_at")
    current = _instant(now or datetime.now(timezone.utc), "now")
    domain = normalize_domain(observation.domain)
    candidate_skeleton = confusable_skeleton(domain)
    scripts = domain_scripts(domain)
    official_match = next(
        (official for official in policy.official_domains if domain == official or domain.endswith("." + official)),
        None,
    )
    official_skeletons = {official: confusable_skeleton(official) for official in policy.official_domains}
    unicode_labels = unicode_domain(domain).casefold().split(".")
    label_skeletons = tuple(
        unicodedata.normalize("NFKD", label).translate(_CONFUSABLES) for label in unicode_labels
    )
    label_distances = {
        mark: min(_edit_distance(skeleton, mark) for skeleton in label_skeletons)
        for mark in policy.protected_labels
    }
    nearest_distance = min(label_distances.values())
    skeleton_collision = any(
        candidate_skeleton == skeleton or candidate_skeleton.endswith("." + skeleton)
        for skeleton in official_skeletons.values()
    ) and official_match is None
    label_collision = any(
        skeleton == mark and label != mark
        for label, skeleton in zip(unicode_labels, label_skeletons)
        for mark in policy.protected_labels
    )
    embedded_official = any(
        official in domain and domain != official and not domain.endswith("." + official)
        for official in policy.official_domains
    )
    mixed_scripts = len(scripts) > 1
    punycode = any(label.startswith("xn--") for label in domain.split("."))
    stale = current - observed_at > policy.maximum_observation_age or observed_at > current + timedelta(minutes=5)
    ct_issuer_unapproved = (
        source == "CT"
        and official_match is not None
        and (
            not observation.certificate_issuer
            or observation.certificate_issuer not in policy.allowed_ct_issuers
        )
    )

    reasons: list[str] = []
    if stale:
        reasons.append("OBSERVATION_TIME_UNTRUSTED")
    if ct_issuer_unapproved:
        reasons.append("OFFICIAL_DOMAIN_CT_ISSUER_UNAPPROVED")
    if skeleton_collision or label_collision:
        reasons.append("CONFUSABLE_SKELETON_COLLISION")
    if embedded_official:
        reasons.append("OFFICIAL_DOMAIN_EMBEDDED_IN_UNTRUSTED_HOST")
    if nearest_distance <= policy.maximum_label_edit_distance and official_match is None:
        reasons.append("PROTECTED_LABEL_TYPOSQUAT")
    if mixed_scripts and official_match is None and nearest_distance <= 2:
        reasons.append("MIXED_SCRIPT_BRAND_DOMAIN")
    if punycode and official_match is None and nearest_distance <= 2:
        reasons.append("IDN_BRAND_DOMAIN")

    if official_match is not None and not reasons:
        decision, severity = "ALLOW", "NONE"
    elif "CONFUSABLE_SKELETON_COLLISION" in reasons:
        decision, severity = "TAKEDOWN_CANDIDATE", "CRITICAL"
    elif any(reason in reasons for reason in (
        "OFFICIAL_DOMAIN_CT_ISSUER_UNAPPROVED",
        "OFFICIAL_DOMAIN_EMBEDDED_IN_UNTRUSTED_HOST",
        "MIXED_SCRIPT_BRAND_DOMAIN",
    )):
        decision, severity = "TAKEDOWN_CANDIDATE", "HIGH"
    elif "PROTECTED_LABEL_TYPOSQUAT" in reasons:
        decision, severity = "REVIEW", "MEDIUM"
    elif stale:
        decision, severity = "REVIEW", "LOW"
    else:
        decision, severity = "ALLOW", "NONE"

    features: dict[str, Any] = {
        "candidateSkeleton": candidate_skeleton,
        "scripts": list(scripts),
        "punycode": punycode,
        "officialMatch": official_match,
        "nearestProtectedLabelDistance": nearest_distance,
        "source": source,
        "observedAt": observed_at.isoformat(),
        "certificateIssuer": observation.certificate_issuer,
    }
    reasons_tuple = tuple(sorted(set(reasons)))
    decision_digest = sha256_json({
        "domain": domain,
        "decision": decision,
        "severity": severity,
        "reasons": reasons_tuple,
        "features": features,
        "ruleVersion": policy.rule_version,
    })
    return BrandAssessment(
        domain, decision, severity, reasons_tuple, features, policy.rule_version, decision_digest
    )


def evaluate_domain_posture(
    policy: BrandPolicy,
    posture: DomainControlPosture,
    *,
    now: datetime | None = None,
) -> GateReport:
    _identifier(posture.tenant_id, "tenant_id")
    domain = normalize_domain(posture.domain)
    current = _instant(now or datetime.now(timezone.utc), "now")
    observed = _instant(posture.observed_at, "observed_at")
    reasons: list[str] = []
    if domain not in policy.official_domains:
        reasons.append("DOMAIN_NOT_IN_DEPLOYMENT_POLICY")
    if current - observed > policy.maximum_observation_age or observed > current + timedelta(minutes=5):
        reasons.append("DOMAIN_POSTURE_STALE")
    if not posture.dnssec:
        reasons.append("DNSSEC_DISABLED")
    if not posture.registry_lock:
        reasons.append("REGISTRY_LOCK_DISABLED")
    if not posture.transfer_lock:
        reasons.append("TRANSFER_LOCK_DISABLED")
    if not posture.registrar_hardware_mfa:
        reasons.append("REGISTRAR_HARDWARE_MFA_DISABLED")
    if posture.dmarc_policy.casefold() != "reject":
        reasons.append("DMARC_NOT_REJECT")
    if not posture.caa_issuers:
        reasons.append("CAA_EMPTY")
    elif policy.allowed_ct_issuers and not set(posture.caa_issuers).issubset(policy.allowed_ct_issuers):
        reasons.append("CAA_ISSUER_UNAPPROVED")
    return GateReport.from_reasons(reasons, ("B84_DOMAIN_POSTURE_EVALUATED",))


class BrandProtectionService:
    _TRANSITIONS = {
        "TRIAGE": ({"OPEN"}, "TRIAGED", False),
        "PRESERVE_EVIDENCE": ({"TRIAGED"}, "EVIDENCE_PRESERVED", False),
        "SUBMIT_PROVIDER": ({"EVIDENCE_PRESERVED"}, "PROVIDER_SUBMITTED", True),
        "RESOLVE": ({"PROVIDER_SUBMITTED"}, "RESOLVED", True),
        "DISMISS": ({"OPEN", "TRIAGED", "EVIDENCE_PRESERVED"}, "DISMISSED", True),
        "REOPEN": ({"RESOLVED", "DISMISSED"}, "OPEN", True),
    }

    def __init__(self, store: SecurityStore, policy: BrandPolicy) -> None:
        self.store = store
        self.policy = policy

    def provision_policy(self, tenant_id: str, *, now: datetime | None = None) -> None:
        tenant = _identifier(tenant_id, "tenant_id")
        instant = _instant(now or datetime.now(timezone.utc), "now").isoformat()
        with self.store.transaction() as connection:
            for domain in self.policy.official_domains:
                prior = connection.execute(
                    "SELECT domain_skeleton,policy_version FROM brand_official_domain "
                    "WHERE tenant_id=? AND domain_ascii=?",
                    (tenant, domain),
                ).fetchone()
                expected = (confusable_skeleton(domain), self.policy.rule_version)
                if prior is not None and tuple(prior) != expected:
                    raise ValidationError("official domain binding is immutable; create a new policy version")
                connection.execute(
                    "INSERT OR IGNORE INTO brand_official_domain "
                    "(tenant_id,domain_ascii,domain_skeleton,policy_version,active,created_at) "
                    "VALUES (?,?,?,?,1,?)",
                    (tenant, domain, expected[0], expected[1], instant),
                )

    def observe(self, observation: DomainObservation, *, now: datetime | None = None) -> BrandAssessment:
        tenant = _identifier(observation.tenant_id, "tenant_id")
        source = require_text(observation.source, "source").upper()
        observation_id = _identifier(observation.observation_id, "observation_id")
        recorded_at = _instant(now or datetime.now(timezone.utc), "now")
        assessed = assess_domain(self.policy, observation, now=recorded_at)
        input_value = {
            "tenantId": tenant,
            "source": source,
            "observationId": observation_id,
            "domain": assessed.domain_ascii,
            "observedAt": _instant(observation.observed_at, "observed_at").isoformat(),
            "certificateIssuer": observation.certificate_issuer,
            "ruleVersion": self.policy.rule_version,
        }
        input_digest = sha256_json(input_value)
        case_id = (
            "brand-" + assessed.decision_digest[:24]
            if assessed.decision == "TAKEDOWN_CANDIDATE"
            else None
        )
        with self.store.transaction() as connection:
            prior = connection.execute(
                "SELECT * FROM brand_observation WHERE tenant_id=? AND source=? AND observation_id=?",
                (tenant, source, observation_id),
            ).fetchone()
            if prior is not None:
                if prior["input_digest"] != input_digest:
                    raise ValidationError("brand observation idempotency conflict")
                existing_case = connection.execute(
                    "SELECT case_id FROM brand_takedown_case WHERE tenant_id=? AND observation_digest=?",
                    (tenant, prior["decision_digest"]),
                ).fetchone()
                return self._assessment_from_row(prior, existing_case[0] if existing_case else None)
            connection.execute(
                "INSERT INTO brand_observation VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    tenant,
                    source,
                    observation_id,
                    assessed.domain_ascii,
                    input_digest,
                    assessed.decision_digest,
                    assessed.decision,
                    assessed.severity,
                    json.dumps(assessed.reasons, separators=(",", ":")),
                    canonical_json(dict(assessed.features)).decode("utf-8"),
                    assessed.rule_version,
                    _instant(observation.observed_at, "observed_at").isoformat(),
                    recorded_at.isoformat(),
                ),
            )
            if case_id is not None:
                connection.execute(
                    "INSERT OR IGNORE INTO brand_takedown_case VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        tenant,
                        case_id,
                        assessed.domain_ascii,
                        assessed.decision_digest,
                        "OPEN",
                        assessed.severity,
                        None,
                        recorded_at.isoformat(),
                        recorded_at.isoformat(),
                    ),
                )
                connection.execute(
                    "INSERT OR IGNORE INTO brand_takedown_action VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        tenant,
                        case_id,
                        "automatic-open",
                        "OPEN_AUTOMATIC",
                        "brand-monitor",
                        None,
                        "high-confidence brand abuse signal",
                        "NONE",
                        "OPEN",
                        assessed.decision_digest,
                        None,
                        recorded_at.isoformat(),
                    ),
                )
        return BrandAssessment(**{**assessed.__dict__, "case_id": case_id})

    def transition_case(
        self,
        tenant_id: str,
        case_id: str,
        *,
        action_id: str,
        action: str,
        actor: str,
        reviewer: str | None,
        reason: str,
        external_receipt: str | None = None,
        now: datetime | None = None,
    ) -> str:
        tenant = _identifier(tenant_id, "tenant_id")
        case = _identifier(case_id, "case_id")
        action_identifier = _identifier(action_id, "action_id")
        actor_id = _identifier(actor, "actor")
        review_id = _identifier(reviewer, "reviewer") if reviewer is not None else None
        normalized_action = require_text(action, "action").upper()
        if normalized_action not in self._TRANSITIONS:
            raise ValidationError("unsupported takedown case action")
        allowed_before, after, independent_review = self._TRANSITIONS[normalized_action]
        explanation = require_text(reason, "reason")
        if len(explanation) > 1000:
            raise ValidationError("reason is too long")
        receipt = require_text(external_receipt, "external_receipt") if external_receipt is not None else None
        if normalized_action == "SUBMIT_PROVIDER" and receipt is None:
            raise ValidationError("provider submission requires a real external receipt")
        if independent_review and (review_id is None or review_id == actor_id):
            raise ValidationError("independent reviewer is required for high-risk case actions")
        instant = _instant(now or datetime.now(timezone.utc), "now").isoformat()
        payload = {
            "action": normalized_action,
            "actor": actor_id,
            "reviewer": review_id,
            "reason": explanation,
            "externalReceipt": receipt,
        }
        payload_digest = sha256_json(payload)
        with self.store.transaction() as connection:
            prior_action = connection.execute(
                "SELECT payload_digest,after_status FROM brand_takedown_action "
                "WHERE tenant_id=? AND case_id=? AND action_id=?",
                (tenant, case, action_identifier),
            ).fetchone()
            if prior_action is not None:
                if prior_action["payload_digest"] != payload_digest:
                    raise ValidationError("takedown action idempotency conflict")
                return str(prior_action["after_status"])
            row = connection.execute(
                "SELECT status,external_receipt FROM brand_takedown_case WHERE tenant_id=? AND case_id=?",
                (tenant, case),
            ).fetchone()
            if row is None:
                raise ValidationError("tenant-scoped takedown case not found")
            before = str(row["status"])
            if before not in allowed_before:
                raise ValidationError(f"action {normalized_action} is invalid from {before}")
            if normalized_action == "RESOLVE" and not (receipt or row["external_receipt"]):
                raise ValidationError("resolution requires provider disposition evidence")
            effective_receipt = receipt or row["external_receipt"]
            connection.execute(
                "UPDATE brand_takedown_case SET status=?,external_receipt=?,updated_at=? "
                "WHERE tenant_id=? AND case_id=?",
                (after, effective_receipt, instant, tenant, case),
            )
            connection.execute(
                "INSERT INTO brand_takedown_action VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    tenant,
                    case,
                    action_identifier,
                    normalized_action,
                    actor_id,
                    review_id,
                    explanation,
                    before,
                    after,
                    payload_digest,
                    receipt,
                    instant,
                ),
            )
        return after

    def case_snapshot(self, tenant_id: str, case_id: str) -> Mapping[str, Any]:
        tenant = _identifier(tenant_id, "tenant_id")
        case = _identifier(case_id, "case_id")
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT * FROM brand_takedown_case WHERE tenant_id=? AND case_id=?",
                (tenant, case),
            ).fetchone()
            if row is None:
                raise ValidationError("tenant-scoped takedown case not found")
            actions = connection.execute(
                "SELECT action_id,action,actor,reviewer,reason,before_status,after_status,"
                "payload_digest,external_receipt,occurred_at FROM brand_takedown_action "
                "WHERE tenant_id=? AND case_id=? ORDER BY occurred_at,action_id",
                (tenant, case),
            ).fetchall()
            return {**dict(row), "actions": [dict(action) for action in actions]}

    @staticmethod
    def _assessment_from_row(row: sqlite3.Row, case_id: str | None) -> BrandAssessment:
        return BrandAssessment(
            domain_ascii=str(row["candidate_domain_ascii"]),
            decision=str(row["decision"]),
            severity=str(row["severity"]),
            reasons=tuple(json.loads(row["reasons_json"])),
            features=json.loads(row["features_json"]),
            rule_version=str(row["rule_version"]),
            decision_digest=str(row["decision_digest"]),
            case_id=case_id,
        )
