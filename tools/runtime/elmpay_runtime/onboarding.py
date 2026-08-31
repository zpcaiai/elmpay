"""Durable production-onboarding readiness without fabricating activation (B122)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .attestation import ConnectionNonceStore
from .common import ValidationError, canonical_json, require_mapping, require_text, sha256_json
from .durable import DurableStore
from .external_evidence import validate_external_evidence


REQUIRED_CONTROLS = frozenset({"merchant_account", "domain", "certificate", "webhook", "limits", "alerts", "billing", "emergency_contact"})
REFERENCE = re.compile(r"^(?:kms|vault|secret|directory|billing|alert)://[A-Za-z0-9._/:-]{3,240}$")


def _current(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValidationError("onboarding control time must be timezone-aware")
    return current.astimezone(timezone.utc)


def _now(value: datetime | None = None) -> str:
    return _current(value).isoformat()


class OnboardingControl:
    def __init__(
        self,
        database: str,
        external_evidence_policy: Mapping[str, Any] | None = None,
        external_evidence_trust: Mapping[str, Any] | None = None,
    ) -> None:
        self.store = DurableStore(database)
        self.external_evidence_policy = (
            dict(external_evidence_policy) if external_evidence_policy is not None else None
        )
        self.external_evidence_trust = (
            dict(external_evidence_trust) if external_evidence_trust is not None else None
        )

    def open_case(self, tenant_id: str, case_id: str, provider_id: str, merchant_account_id: str, requester: str, configuration_version: str, *, now: datetime | None = None) -> None:
        values = (tenant_id, case_id, provider_id, merchant_account_id, requester, configuration_version)
        for label, value in zip(("tenant_id", "case_id", "provider_id", "merchant_account_id", "requester", "configuration_version"), values):
            require_text(value, label)
        instant = _now(now)
        with self.store.transaction() as connection:
            prior = connection.execute("SELECT provider_id,merchant_account_id,requester,configuration_version FROM onboarding_case WHERE tenant_id=? AND case_id=?", (tenant_id, case_id)).fetchone()
            intended = (provider_id, merchant_account_id, requester, configuration_version)
            if prior and tuple(prior) != intended:
                raise ValidationError("onboarding case identity is immutable")
            if not prior:
                connection.execute("INSERT INTO onboarding_case VALUES(?,?,?,?,?,?,?,?,?,?)", (tenant_id, case_id, provider_id, merchant_account_id, requester, configuration_version, None, "OPEN", instant, instant))
                self._audit(connection, tenant_id, case_id, "OPEN", sha256_json(intended), instant)

    def verify_control(self, tenant_id: str, case_id: str, control_name: str, details: Mapping[str, Any], *, now: datetime | None = None) -> str:
        if control_name not in REQUIRED_CONTROLS:
            raise ValidationError("unknown onboarding readiness control")
        safe = self._validate_details(control_name, require_mapping(details, "control details"))
        digest = sha256_json(safe)
        instant = _now(now)
        with self.store.transaction() as connection:
            case = connection.execute("SELECT state FROM onboarding_case WHERE tenant_id=? AND case_id=?", (tenant_id, case_id)).fetchone()
            if not case:
                raise ValidationError("tenant-scoped onboarding case not found")
            if case["state"] in {"ACTIVE", "SUSPENDED"}:
                raise ValidationError("active onboarding configuration is immutable")
            prior = connection.execute("SELECT evidence_digest FROM onboarding_control WHERE tenant_id=? AND case_id=? AND control_name=?", (tenant_id, case_id, control_name)).fetchone()
            if prior and prior["evidence_digest"] != digest:
                connection.execute("DELETE FROM onboarding_approval WHERE tenant_id=? AND case_id=?", (tenant_id, case_id))
            connection.execute("INSERT INTO onboarding_control VALUES(?,?,?,?,?,?) ON CONFLICT(tenant_id,case_id,control_name) DO UPDATE SET evidence_digest=excluded.evidence_digest,details_json=excluded.details_json,verified_at=excluded.verified_at", (tenant_id, case_id, control_name, digest, canonical_json(safe).decode(), instant))
            self._refresh_digest(connection, tenant_id, case_id, instant)
            self._audit(connection, tenant_id, case_id, f"VERIFY:{control_name}", digest, instant)
        return digest

    def approve(self, tenant_id: str, case_id: str, approver: str, *, now: datetime | None = None) -> int:
        actor = require_text(approver, "approver")
        instant = _now(now)
        with self.store.transaction() as connection:
            case = connection.execute("SELECT requester,configuration_digest,state FROM onboarding_case WHERE tenant_id=? AND case_id=?", (tenant_id, case_id)).fetchone()
            if not case or case["state"] not in {"READY_FOR_APPROVAL", "READY_FOR_EXTERNAL_ACTIVATION"} or not case["configuration_digest"]:
                raise ValidationError("all onboarding controls must be verified before approval")
            if actor == case["requester"]:
                raise ValidationError("onboarding requester cannot self-approve")
            connection.execute("INSERT INTO onboarding_approval VALUES(?,?,?,?,?) ON CONFLICT(tenant_id,case_id,approver) DO UPDATE SET configuration_digest=excluded.configuration_digest,approved_at=excluded.approved_at", (tenant_id, case_id, actor, case["configuration_digest"], instant))
            count = connection.execute("SELECT count(DISTINCT approver) FROM onboarding_approval WHERE tenant_id=? AND case_id=? AND configuration_digest=?", (tenant_id, case_id, case["configuration_digest"])).fetchone()[0]
            if count >= 2:
                connection.execute("UPDATE onboarding_case SET state='READY_FOR_EXTERNAL_ACTIVATION',updated_at=? WHERE tenant_id=? AND case_id=?", (instant, tenant_id, case_id))
            self._audit(connection, tenant_id, case_id, f"APPROVE:{actor}", case["configuration_digest"], instant)
        return count

    def activate(
        self,
        tenant_id: str,
        case_id: str,
        external_evidence_bundle: Mapping[str, Any],
        adapter: Callable[[Mapping[str, Any]], str],
        *,
        now: datetime | None = None,
    ) -> str:
        current = _current(now)
        started_monotonic = time.monotonic()
        instant = _now(current)
        with self.store.transaction() as connection:
            case = connection.execute("SELECT * FROM onboarding_case WHERE tenant_id=? AND case_id=?", (tenant_id, case_id)).fetchone()
            if not case:
                raise ValidationError("tenant-scoped onboarding case not found")
            if case["state"] == "ACTIVE":
                replay_request = {
                    "tenantId": tenant_id,
                    "caseId": case_id,
                    "providerId": case["provider_id"],
                    "merchantAccountId": case["merchant_account_id"],
                    "configurationVersion": case["configuration_version"],
                    "configurationDigest": case["configuration_digest"],
                    "externalEvidenceDigest": sha256_json(external_evidence_bundle),
                }
                completed = connection.execute(
                    "SELECT binding_digest,request_digest,status "
                    "FROM external_control_operation WHERE tenant_id=? "
                    "AND operation_type='ONBOARDING_ACTIVATION' AND operation_id=?",
                    (tenant_id, case_id),
                ).fetchone()
                if (
                    completed
                    and completed["status"] == "SUCCEEDED"
                    and completed["binding_digest"] == case["configuration_digest"]
                    and completed["request_digest"] == sha256_json(replay_request)
                ):
                    return "ACTIVE"
                raise ValidationError("immutable onboarding activation replay mismatch")
            if case["state"] != "READY_FOR_EXTERNAL_ACTIVATION":
                raise ValidationError("onboarding case is not ready for external activation")
            if self.external_evidence_policy is None or self.external_evidence_trust is None:
                raise ValidationError("external evidence verifier is not configured")
            replay_database = self.external_evidence_trust.get("replayDatabase")
            same_replay_database = replay_database == self.store.database
            if (
                isinstance(replay_database, str)
                and not same_replay_database
                and not replay_database.startswith("file:")
                and not self.store.database.startswith("file:")
            ):
                same_replay_database = Path(replay_database).resolve() == Path(
                    self.store.database
                ).resolve()
            external_evidence = validate_external_evidence(
                self.external_evidence_policy,
                require_mapping(external_evidence_bundle, "external evidence bundle"),
                self.external_evidence_trust,
                now=now,
                expected_binding=case["configuration_digest"],
                expected_tenant_id=tenant_id,
                nonce_store=(
                    ConnectionNonceStore(connection)
                    if same_replay_database else None
                ),
            )
            if not external_evidence.allowed or not any(
                check.startswith("external_evidence:provider_certification:")
                for check in external_evidence.checks
            ):
                raise ValidationError("official provider and production activation evidence is required")
            certified_providers = {
                item.get("attestation", {}).get("providerId")
                for item in external_evidence_bundle.get("evidence", [])
                if isinstance(item, Mapping)
                and item.get("category") == "provider_certification"
                and isinstance(item.get("attestation"), Mapping)
            }
            if case["provider_id"] not in certified_providers:
                raise ValidationError(
                    "onboarding provider is not covered by official certification evidence"
                )
            request = {
                "tenantId": tenant_id,
                "caseId": case_id,
                "providerId": case["provider_id"],
                "merchantAccountId": case["merchant_account_id"],
                "configurationVersion": case["configuration_version"],
                "configurationDigest": case["configuration_digest"],
                "externalEvidenceDigest": sha256_json(external_evidence_bundle),
            }
            request_digest = sha256_json(request)
            operation = connection.execute(
                "SELECT * FROM external_control_operation WHERE tenant_id=? "
                "AND operation_type='ONBOARDING_ACTIVATION' AND operation_id=?",
                (tenant_id, case_id),
            ).fetchone()
            if operation:
                if (
                    operation["binding_digest"] != case["configuration_digest"]
                    or operation["request_digest"] != request_digest
                ):
                    raise ValidationError("immutable onboarding activation request collision")
                if operation["status"] == "SUCCEEDED":
                    raise ValidationError(
                        "onboarding activation durable state is inconsistent"
                    )
                if operation["status"] == "UNKNOWN":
                    raise ValidationError(
                        "onboarding activation outcome is UNKNOWN; reconcile before retry"
                    )
                if datetime.fromisoformat(operation["lease_until"]) > current:
                    raise ValidationError("onboarding activation is already in flight")
                raise ValidationError(
                    "expired onboarding activation has an uncertain outcome; reconcile before retry"
                )
            else:
                fence_token = 1
            lease_owner = f"onboarding:{tenant_id}:{case_id}"
            lease_until = (current + timedelta(minutes=2)).isoformat()
            connection.execute(
                "INSERT INTO external_control_operation VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(tenant_id,operation_type,operation_id) DO UPDATE SET "
                "status='IN_FLIGHT',fence_token=excluded.fence_token,"
                "lease_owner=excluded.lease_owner,lease_until=excluded.lease_until,"
                "updated_at=excluded.updated_at",
                (
                    tenant_id, "ONBOARDING_ACTIVATION", case_id,
                    case["configuration_digest"], request_digest, "IN_FLIGHT",
                    fence_token, lease_owner, lease_until, None, instant,
                ),
            )
        adapter_request = {
            **dict(case),
            **request,
            "idempotencyKey": request_digest,
            "fenceToken": fence_token,
            "mode": "ACTIVATE",
        }
        try:
            result = adapter(adapter_request)
            if result != case["configuration_digest"]:
                raise ValidationError(
                    "activation adapter did not confirm configuration digest"
                )
            completed = current + timedelta(
                seconds=max(0.0, time.monotonic() - started_monotonic)
            )
            completion_instant = completed.isoformat()
            with self.store.transaction() as connection:
                changed = connection.execute(
                    "UPDATE external_control_operation SET status='SUCCEEDED',"
                    "result_digest=?,updated_at=? WHERE tenant_id=? "
                    "AND operation_type='ONBOARDING_ACTIVATION' AND operation_id=? "
                    "AND status='IN_FLIGHT' AND fence_token=? AND lease_owner=? "
                    "AND lease_until>?",
                    (
                        result, completion_instant, tenant_id, case_id, fence_token,
                        lease_owner, completion_instant,
                    ),
                ).rowcount
                activated = connection.execute(
                    "UPDATE onboarding_case SET state='ACTIVE',updated_at=? "
                    "WHERE tenant_id=? AND case_id=? "
                    "AND state='READY_FOR_EXTERNAL_ACTIVATION' "
                    "AND configuration_digest=?",
                    (completion_instant, tenant_id, case_id, case["configuration_digest"]),
                ).rowcount
                if changed != 1 or activated != 1:
                    raise ValidationError("onboarding activation fencing failed")
                self._audit(
                    connection, tenant_id, case_id, "ACTIVATE",
                    case["configuration_digest"], completion_instant,
                )
        except BaseException as exc:
            failed_at = current + timedelta(
                seconds=max(0.0, time.monotonic() - started_monotonic)
            )
            with self.store.transaction() as connection:
                connection.execute(
                    "UPDATE external_control_operation SET status='UNKNOWN',updated_at=? "
                    "WHERE tenant_id=? AND operation_type='ONBOARDING_ACTIVATION' "
                    "AND operation_id=? AND status='IN_FLIGHT' AND fence_token=?",
                    (failed_at.isoformat(), tenant_id, case_id, fence_token),
                )
            raise ValidationError(
                "onboarding activation outcome is UNKNOWN; reconcile before retry"
            ) from exc
        return "ACTIVE"

    def reconcile_activation(
        self,
        tenant_id: str,
        case_id: str,
        adapter: Callable[[Mapping[str, Any]], str],
        *,
        now: datetime | None = None,
    ) -> str:
        """Resolve an UNKNOWN activation through the real idempotency adapter."""

        current = _current(now)
        with self.store.transaction() as connection:
            case = connection.execute(
                "SELECT * FROM onboarding_case WHERE tenant_id=? AND case_id=?",
                (tenant_id, case_id),
            ).fetchone()
            operation = connection.execute(
                "SELECT * FROM external_control_operation WHERE tenant_id=? "
                "AND operation_type='ONBOARDING_ACTIVATION' AND operation_id=?",
                (tenant_id, case_id),
            ).fetchone()
            if not case or not operation:
                raise ValidationError(
                    "onboarding activation has no uncertain outcome to reconcile"
                )
            if case["state"] == "ACTIVE" and operation["status"] == "SUCCEEDED":
                return "ACTIVE"
            if (
                case["state"] != "READY_FOR_EXTERNAL_ACTIVATION"
                or case["configuration_digest"] != operation["binding_digest"]
            ):
                raise ValidationError("onboarding reconciliation binding mismatch")
            if operation["status"] == "SUCCEEDED":
                raise ValidationError("onboarding activation durable state is inconsistent")
            if (
                operation["status"] == "IN_FLIGHT"
                and datetime.fromisoformat(operation["lease_until"]) > current
            ):
                raise ValidationError("onboarding activation dispatch lease is still active")
            if operation["status"] not in {"IN_FLIGHT", "UNKNOWN"}:
                raise ValidationError(
                    "onboarding activation has no uncertain outcome to reconcile"
                )
            fence_token = operation["fence_token"] + 1
            lease_owner = f"onboarding-reconcile:{tenant_id}:{case_id}:{fence_token}"
            lease_until = current + timedelta(minutes=2)
            changed = connection.execute(
                "UPDATE external_control_operation SET status='IN_FLIGHT',fence_token=?,"
                "lease_owner=?,lease_until=?,updated_at=? WHERE tenant_id=? "
                "AND operation_type='ONBOARDING_ACTIVATION' AND operation_id=? "
                "AND request_digest=? AND status IN ('IN_FLIGHT','UNKNOWN') "
                "AND fence_token=?",
                (
                    fence_token, lease_owner, lease_until.isoformat(),
                    current.isoformat(), tenant_id, case_id,
                    operation["request_digest"], operation["fence_token"],
                ),
            ).rowcount
            if changed != 1:
                raise ValidationError("onboarding activation reconciliation lease was lost")

        started_monotonic = time.monotonic()
        try:
            result = adapter({
                **dict(case),
                "tenantId": tenant_id,
                "caseId": case_id,
                "configurationDigest": operation["binding_digest"],
                "idempotencyKey": operation["request_digest"],
                "fenceToken": fence_token,
                "mode": "RECONCILE",
            })
            if result != operation["binding_digest"]:
                raise ValidationError("activation remains UNKNOWN")
            completed = current + timedelta(
                seconds=max(0.0, time.monotonic() - started_monotonic)
            )
            with self.store.transaction() as connection:
                changed = connection.execute(
                    "UPDATE external_control_operation SET status='SUCCEEDED',"
                    "result_digest=?,updated_at=? WHERE tenant_id=? "
                    "AND operation_type='ONBOARDING_ACTIVATION' AND operation_id=? "
                    "AND status='IN_FLIGHT' AND request_digest=? AND fence_token=? "
                    "AND lease_owner=? AND lease_until>?",
                    (
                        result, completed.isoformat(), tenant_id, case_id,
                        operation["request_digest"], fence_token, lease_owner,
                        completed.isoformat(),
                    ),
                ).rowcount
                activated = connection.execute(
                    "UPDATE onboarding_case SET state='ACTIVE',updated_at=? "
                    "WHERE tenant_id=? AND case_id=? "
                    "AND state='READY_FOR_EXTERNAL_ACTIVATION' "
                    "AND configuration_digest=?",
                    (
                        completed.isoformat(), tenant_id, case_id,
                        operation["binding_digest"],
                    ),
                ).rowcount
                if changed != 1 or activated != 1:
                    raise ValidationError(
                        "onboarding activation reconciliation fencing failed"
                    )
                self._audit(
                    connection, tenant_id, case_id, "ACTIVATE_RECONCILED",
                    operation["binding_digest"], completed.isoformat(),
                )
        except BaseException as exc:
            failed_at = current + timedelta(
                seconds=max(0.0, time.monotonic() - started_monotonic)
            )
            with self.store.transaction() as connection:
                connection.execute(
                    "UPDATE external_control_operation SET status='UNKNOWN',updated_at=? "
                    "WHERE tenant_id=? AND operation_type='ONBOARDING_ACTIVATION' "
                    "AND operation_id=? AND status='IN_FLIGHT' AND request_digest=? "
                    "AND fence_token=? AND lease_owner=?",
                    (
                        failed_at.isoformat(), tenant_id, case_id,
                        operation["request_digest"], fence_token, lease_owner,
                    ),
                )
            raise ValidationError("onboarding activation remains UNKNOWN") from exc
        return "ACTIVE"

    def readiness(self, tenant_id: str, case_id: str) -> dict[str, Any]:
        with self.store.connect() as connection:
            case = connection.execute("SELECT state,configuration_digest FROM onboarding_case WHERE tenant_id=? AND case_id=?", (tenant_id, case_id)).fetchone()
            if not case:
                raise ValidationError("tenant-scoped onboarding case not found")
            present = {row[0] for row in connection.execute("SELECT control_name FROM onboarding_control WHERE tenant_id=? AND case_id=?", (tenant_id, case_id))}
        return {"state": case["state"], "configurationDigest": case["configuration_digest"], "missingControls": sorted(REQUIRED_CONTROLS - present), "certificationStatus": "NOT_CERTIFIED", "activationEvidenceStatus": "EXTERNAL_EVIDENCE_VERIFIED" if case["state"] == "ACTIVE" else "PENDING"}

    @staticmethod
    def _validate_details(control: str, details: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(details)
        if control == "merchant_account":
            require_text(value.get("merchantAccountId"), "merchantAccountId")
        elif control == "domain":
            domain = require_text(value.get("domain"), "domain")
            if domain.startswith("*.") or "://" in domain or "." not in domain:
                raise ValidationError("merchant domain must be an exact DNS name")
            value["verified"] = value.get("verified") is True
            if not value["verified"]:
                raise ValidationError("merchant domain verification is incomplete")
        elif control == "certificate":
            reference = require_text(value.get("certificateRef"), "certificateRef")
            if not REFERENCE.fullmatch(reference):
                raise ValidationError("certificate must be an indirect secret reference")
        elif control == "webhook":
            url = urlsplit(require_text(value.get("url"), "webhook.url"))
            if url.scheme != "https" or not url.hostname or url.username or url.password:
                raise ValidationError("webhook must be credential-free HTTPS")
            try:
                address = ipaddress.ip_address(url.hostname)
            except ValueError:
                address = None
            if address is not None and not address.is_global:
                raise ValidationError("webhook address must be globally routable")
            if value.get("signedRoundTripVerified") is not True:
                raise ValidationError("signed webhook round trip is required")
        elif control == "limits":
            limits = require_mapping(value.get("minorUnitLimits"), "minorUnitLimits")
            if not limits or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in limits.values()):
                raise ValidationError("limits must be positive integer minor units")
        elif control in {"alerts", "billing", "emergency_contact"}:
            field = {"alerts": "alertRouteRef", "billing": "billingAccountRef", "emergency_contact": "contactRef"}[control]
            reference = require_text(value.get(field), field)
            if not REFERENCE.fullmatch(reference):
                raise ValidationError(f"{field} must be an indirect reference")
        return value

    def _refresh_digest(self, connection: Any, tenant_id: str, case_id: str, instant: str) -> None:
        rows = connection.execute("SELECT control_name,evidence_digest FROM onboarding_control WHERE tenant_id=? AND case_id=? ORDER BY control_name", (tenant_id, case_id)).fetchall()
        if {row["control_name"] for row in rows} != REQUIRED_CONTROLS:
            connection.execute("UPDATE onboarding_case SET configuration_digest=NULL,state='OPEN',updated_at=? WHERE tenant_id=? AND case_id=?", (instant, tenant_id, case_id))
            return
        digest = sha256_json({row["control_name"]: row["evidence_digest"] for row in rows})
        approvals = connection.execute("SELECT count(DISTINCT approver) FROM onboarding_approval WHERE tenant_id=? AND case_id=? AND configuration_digest=?", (tenant_id, case_id, digest)).fetchone()[0]
        state = "READY_FOR_EXTERNAL_ACTIVATION" if approvals >= 2 else "READY_FOR_APPROVAL"
        connection.execute("UPDATE onboarding_case SET configuration_digest=?,state=?,updated_at=? WHERE tenant_id=? AND case_id=?", (digest, state, instant, tenant_id, case_id))

    @staticmethod
    def _audit(connection: Any, tenant_id: str, case_id: str, action: str, digest: str, instant: str) -> None:
        connection.execute("INSERT INTO onboarding_audit(tenant_id,case_id,action,digest,occurred_at) VALUES(?,?,?,?,?)", (tenant_id, case_id, action, digest, instant))
