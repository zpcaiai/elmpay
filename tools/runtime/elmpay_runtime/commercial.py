"""Persistent metering, invoicing, SLA/support and four-eyes credits (B126)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Mapping

from .common import ValidationError, canonical_json, parse_instant, require_list, require_mapping, require_text, sha256_json
from .downstream_receipt import verify_downstream_receipt
from .durable import DurableStore


def _current(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValidationError("commercial control time must be timezone-aware")
    return current.astimezone(timezone.utc)


def _instant(value: datetime | None = None) -> str:
    return _current(value).isoformat()


class CommercialLedger:
    def __init__(self, database: str) -> None:
        self.store = DurableStore(database)

    @staticmethod
    def _append_audit(
        connection: Any,
        *,
        tenant_id: str,
        event_type: str,
        entity_id: str,
        actor: str,
        payload: Mapping[str, Any],
        occurred_at: datetime,
    ) -> str:
        require_text(tenant_id, "tenant_id")
        require_text(event_type, "event_type")
        require_text(entity_id, "entity_id")
        require_text(actor, "actor")
        if occurred_at.tzinfo is None:
            raise ValidationError("audit event time must be timezone-aware")
        safe_payload = dict(require_mapping(dict(payload), "audit payload"))
        payload_digest = sha256_json(safe_payload)
        previous = connection.execute(
            "SELECT event_digest,occurred_at FROM commercial_audit_event WHERE tenant_id=? "
            "ORDER BY sequence_id DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        if previous and parse_instant(previous["occurred_at"], "prior audit time") \
                > occurred_at.astimezone(timezone.utc):
            raise ValidationError("commercial audit event time cannot move backwards")
        previous_digest = previous["event_digest"] if previous else None
        body = {
            "tenantId": tenant_id,
            "eventType": event_type,
            "entityId": entity_id,
            "actorId": actor,
            "occurredAt": occurred_at.astimezone(timezone.utc).isoformat(),
            "payloadDigest": payload_digest,
            "previousDigest": previous_digest,
        }
        event_digest = sha256_json(body)
        connection.execute(
            "INSERT INTO commercial_audit_event(tenant_id,event_type,entity_id,actor_id,"
            "occurred_at,payload_digest,previous_digest,event_digest,payload_json) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                tenant_id, event_type, entity_id, actor,
                body["occurredAt"], payload_digest, previous_digest, event_digest,
                canonical_json(safe_payload).decode("utf-8"),
            ),
        )
        return event_digest

    @staticmethod
    def _monotonic_audit_time(connection: Any, requested: datetime | None) -> datetime:
        """Keep the append-only audit chain monotonic for backdated commands.

        Commands may carry an event time from an offline worker that predates
        the latest committed audit row.  Persisting that timestamp would break
        the chain (and make a concurrent credit request look like corruption),
        so the audit occurrence is clamped to the latest committed time while
        the command's own created/decided timestamps remain unchanged.
        """
        candidate = _current(requested)
        prior = connection.execute(
            "SELECT occurred_at FROM commercial_audit_event "
            "ORDER BY sequence_id DESC LIMIT 1"
        ).fetchone()
        if prior:
            prior_at = parse_instant(prior["occurred_at"], "prior audit time")
            if prior_at > candidate:
                candidate = prior_at
        return candidate

    def create_pricing(self, tenant_id: str, version: str, policy: Mapping[str, Any], effective_at: datetime, *, actor: str, now: datetime | None = None) -> str:
        require_text(tenant_id, "tenant_id")
        require_text(version, "version")
        if effective_at.tzinfo is None:
            raise ValidationError("pricing effective_at must be timezone-aware")
        document = require_mapping(policy, "pricing policy")
        currency = require_text(document.get("currency"), "pricing.currency")
        meters: set[str] = set()
        for raw in require_list(document.get("meters"), "pricing.meters"):
            meter = require_mapping(raw, "pricing meter")
            name = require_text(meter.get("name"), "meter.name")
            if name in meters:
                raise ValidationError(f"duplicate pricing meter: {name}")
            meters.add(name)
            price = meter.get("unitPriceMinor")
            if isinstance(price, bool) or not isinstance(price, int) or price < 0:
                raise ValidationError("unitPriceMinor must be a non-negative integer")
            require_text(meter.get("deduplicateBy"), "meter.deduplicateBy")
        if not meters:
            raise ValidationError("pricing must declare meters")
        pricing_id = sha256_json({"tenantId": tenant_id, "version": version})
        digest = sha256_json(document)
        encoded = canonical_json(document).decode()
        effective = effective_at.astimezone(timezone.utc).isoformat()
        with self.store.transaction() as connection:
            prior = connection.execute(
                "SELECT tenant_id,currency,effective_at,policy_digest,policy_json "
                "FROM pricing_version WHERE pricing_version_id=?", (pricing_id,)
            ).fetchone()
            intended = (tenant_id, currency, effective, digest, encoded)
            if prior and tuple(prior) != intended:
                raise ValidationError("pricing version is immutable")
            if not prior:
                connection.execute("INSERT INTO pricing_version VALUES(?,?,?,?,?,?,?)", (pricing_id, tenant_id, currency, effective, digest, encoded, _instant(now)))
                self._append_audit(
                    connection, tenant_id=tenant_id, event_type="PRICING_CREATED",
                    entity_id=pricing_id, actor=actor,
                    payload={"version": version, "currency": currency,
                             "effectiveAt": effective_at.astimezone(timezone.utc).isoformat(),
                             "policyDigest": digest},
                    occurred_at=now or datetime.now(timezone.utc),
                )
        return pricing_id

    def meter(self, tenant_id: str, pricing_version_id: str, event: Mapping[str, Any], *, actor: str, now: datetime | None = None) -> bool:
        payload = require_mapping(event, "usage event")
        if payload.get("tenantId") != tenant_id:
            raise ValidationError("cross-tenant usage event is forbidden")
        current = _current(now)
        with self.store.transaction() as connection:
            pricing = connection.execute(
                "SELECT tenant_id,effective_at,policy_json FROM pricing_version "
                "WHERE pricing_version_id=?", (pricing_version_id,)
            ).fetchone()
            if not pricing or pricing["tenant_id"] != tenant_id:
                raise ValidationError("pricing version is not owned by tenant")
            policy = json.loads(pricing["policy_json"])
            meter_name = require_text(payload.get("meter"), "event.meter")
            meter = next((item for item in policy["meters"] if item["name"] == meter_name), None)
            if not meter:
                raise ValidationError("unknown usage meter")
            dedupe_field = meter["deduplicateBy"]
            dedupe_key = require_text(payload.get(dedupe_field), f"event.{dedupe_field}")
            occurred_at = parse_instant(payload.get("occurredAt"), "event.occurredAt")
            if occurred_at > current + timedelta(minutes=5):
                raise ValidationError("usage event cannot be dated in the future")
            occurred = occurred_at.isoformat()
            if datetime.fromisoformat(pricing["effective_at"]) > datetime.fromisoformat(occurred):
                raise ValidationError("pricing version was not effective for usage event")
            active_pricing = connection.execute(
                "SELECT pricing_version_id FROM pricing_version WHERE tenant_id=? "
                "AND effective_at<=? ORDER BY effective_at DESC,pricing_version_id DESC LIMIT 1",
                (tenant_id, occurred),
            ).fetchone()
            if not active_pricing or active_pricing["pricing_version_id"] != pricing_version_id:
                raise ValidationError("usage event must bind the active pricing version")
            digest = sha256_json(payload)
            prior = connection.execute(
                "SELECT payload_digest,pricing_version_id FROM usage_event "
                "WHERE tenant_id=? AND meter=? AND dedupe_key=?",
                (tenant_id, meter_name, dedupe_key),
            ).fetchone()
            if prior:
                if (
                    prior["payload_digest"] != digest
                    or prior["pricing_version_id"] != pricing_version_id
                ):
                    raise ValidationError(
                        "usage dedupe key reused with different payload or pricing version"
                    )
                return False
            connection.execute(
                "INSERT INTO usage_event(tenant_id,meter,dedupe_key,pricing_version_id,"
                "occurred_at,payload_digest) VALUES(?,?,?,?,?,?)",
                (tenant_id, meter_name, dedupe_key, pricing_version_id, occurred, digest),
            )
            self._append_audit(
                connection, tenant_id=tenant_id, event_type="USAGE_METERED",
                entity_id=f"{meter_name}:{dedupe_key}", actor=actor,
                payload={"meter": meter_name, "dedupeKeyDigest": sha256_json(dedupe_key),
                         "occurredAt": occurred, "usagePayloadDigest": digest,
                         "pricingVersionId": pricing_version_id},
                occurred_at=current,
            )
        return True

    def issue_invoice(self, invoice_id: str, tenant_id: str, pricing_version_id: str, period_start: datetime, period_end: datetime, *, actor: str, now: datetime | None = None) -> dict[str, Any]:
        if period_start.tzinfo is None or period_end.tzinfo is None or period_end <= period_start:
            raise ValidationError("invoice period must be increasing and timezone-aware")
        current = _current(now)
        if period_end.astimezone(timezone.utc) > current:
            raise ValidationError("invoice period must be complete before issuance")
        with self.store.transaction() as connection:
            pricing = connection.execute("SELECT tenant_id,currency,effective_at,policy_json FROM pricing_version WHERE pricing_version_id=?", (pricing_version_id,)).fetchone()
            if not pricing or pricing["tenant_id"] != tenant_id:
                raise ValidationError("pricing version is not owned by tenant")
            normalized_period_start = period_start.astimezone(timezone.utc)
            if datetime.fromisoformat(pricing["effective_at"]) > normalized_period_start:
                raise ValidationError("pricing version was not effective at period start")
            active_start_pricing = connection.execute(
                "SELECT pricing_version_id FROM pricing_version WHERE tenant_id=? "
                "AND effective_at<=? ORDER BY effective_at DESC,pricing_version_id DESC LIMIT 1",
                (tenant_id, normalized_period_start.isoformat()),
            ).fetchone()
            if (
                not active_start_pricing
                or active_start_pricing["pricing_version_id"] != pricing_version_id
            ):
                raise ValidationError("invoice must bind the pricing version active at period start")
            policy = json.loads(pricing["policy_json"])
            period_parameters = (
                tenant_id,
                period_start.astimezone(timezone.utc).isoformat(),
                period_end.astimezone(timezone.utc).isoformat(),
            )
            unbound = connection.execute(
                "SELECT count(*) FROM usage_event "
                "WHERE tenant_id=? AND occurred_at>=? AND occurred_at<?",
                period_parameters,
            ).fetchone()[0] - connection.execute(
                "SELECT count(pricing_version_id) FROM usage_event "
                "WHERE tenant_id=? AND occurred_at>=? AND occurred_at<?",
                period_parameters,
            ).fetchone()[0]
            if unbound:
                raise ValidationError("invoice period contains usage without pricing provenance")
            lines: list[dict[str, int | str]] = []
            grouped_usage = connection.execute(
                "SELECT pricing_version_id,meter,count(*) AS quantity FROM usage_event "
                "WHERE tenant_id=? AND occurred_at>=? AND occurred_at<? "
                "GROUP BY pricing_version_id,meter ORDER BY pricing_version_id,meter",
                period_parameters,
            ).fetchall()
            pricing_documents: dict[str, Mapping[str, Any]] = {
                pricing_version_id: policy,
            }
            for usage in grouped_usage:
                event_pricing_id = usage["pricing_version_id"]
                event_policy = pricing_documents.get(event_pricing_id)
                if event_policy is None:
                    event_pricing = connection.execute(
                        "SELECT tenant_id,currency,policy_json FROM pricing_version "
                        "WHERE pricing_version_id=?", (event_pricing_id,)
                    ).fetchone()
                    if not event_pricing or event_pricing["tenant_id"] != tenant_id:
                        raise ValidationError("usage pricing provenance is not owned by tenant")
                    if event_pricing["currency"] != pricing["currency"]:
                        raise ValidationError("invoice period crosses pricing currencies")
                    event_policy = require_mapping(
                        json.loads(event_pricing["policy_json"]), "usage pricing policy"
                    )
                    pricing_documents[event_pricing_id] = event_policy
                meter: Mapping[str, Any] | None = None
                for raw_meter in require_list(
                    event_policy.get("meters"), "usage pricing meters"
                ):
                    candidate_meter = require_mapping(raw_meter, "usage pricing meter")
                    if candidate_meter.get("name") == usage["meter"]:
                        meter = candidate_meter
                        break
                if meter is None:
                    raise ValidationError("usage meter is absent from its pricing version")
                price = meter.get("unitPriceMinor")
                if isinstance(price, bool) or not isinstance(price, int) or price < 0:
                    raise ValidationError("usage pricing unit price is invalid")
                quantity = int(usage["quantity"])
                lines.append({
                    "pricingVersionId": event_pricing_id,
                    "meter": usage["meter"],
                    "quantity": quantity,
                    "unitPriceMinor": price,
                    "totalMinor": quantity * price,
                })
            subtotal = sum(int(line["totalMinor"]) for line in lines)
            body = {"invoiceId": invoice_id, "tenantId": tenant_id, "pricingVersionId": pricing_version_id, "pricingVersionIds": sorted(pricing_documents), "periodStart": period_start.astimezone(timezone.utc).isoformat(), "periodEnd": period_end.astimezone(timezone.utc).isoformat(), "currency": pricing["currency"], "lines": lines, "subtotalMinor": subtotal}
            digest = sha256_json(body)
            prior = connection.execute("SELECT invoice_digest FROM commercial_invoice WHERE invoice_id=?", (invoice_id,)).fetchone()
            if prior:
                if prior["invoice_digest"] != digest:
                    raise ValidationError("invoice id is immutable")
                return {**body, "invoiceDigest": digest, "status": "ISSUED"}
            connection.execute("INSERT INTO commercial_invoice VALUES(?,?,?,?,?,?,?,?,?,?)", (invoice_id, tenant_id, pricing_version_id, body["periodStart"], body["periodEnd"], pricing["currency"], subtotal, "ISSUED", digest, _instant(current)))
            for line in lines:
                connection.execute(
                    "INSERT INTO commercial_invoice_priced_line VALUES(?,?,?,?,?,?)",
                    (invoice_id, line["pricingVersionId"], line["meter"], line["quantity"],
                     line["unitPriceMinor"], line["totalMinor"]),
                )
            self._append_audit(
                connection, tenant_id=tenant_id, event_type="INVOICE_ISSUED",
                entity_id=invoice_id, actor=actor,
                payload={"invoiceDigest": digest, "pricingVersionId": pricing_version_id,
                         "pricingVersionIds": body["pricingVersionIds"],
                         "currency": pricing["currency"], "subtotalMinor": subtotal,
                         "periodStart": body["periodStart"], "periodEnd": body["periodEnd"]},
                occurred_at=current,
            )
        return {**body, "invoiceDigest": digest, "status": "ISSUED"}

    def set_sla(self, tenant_id: str, version: str, effective_at: datetime, response_minutes: int, service_credit_basis_points: int, *, actor: str, now: datetime | None = None) -> str:
        require_text(tenant_id, "tenant_id")
        require_text(version, "version")
        if effective_at.tzinfo is None:
            raise ValidationError("SLA effective_at must be timezone-aware")
        if isinstance(response_minutes, bool) or not isinstance(response_minutes, int) or response_minutes <= 0:
            raise ValidationError("response_minutes must be positive")
        if isinstance(service_credit_basis_points, bool) or not isinstance(service_credit_basis_points, int) or not 0 <= service_credit_basis_points <= 10000:
            raise ValidationError("service credit basis points must be 0..10000")
        body = {"tenantId": tenant_id, "version": version, "effectiveAt": effective_at.astimezone(timezone.utc).isoformat(), "responseMinutes": response_minutes, "serviceCreditBasisPoints": service_credit_basis_points}
        digest = sha256_json(body)
        with self.store.transaction() as connection:
            prior = connection.execute(
                "SELECT effective_at,response_minutes,service_credit_basis_points,"
                "policy_digest FROM support_sla_policy WHERE tenant_id=? AND version=?",
                (tenant_id, version),
            ).fetchone()
            intended = (
                body["effectiveAt"], response_minutes,
                service_credit_basis_points, digest,
            )
            if prior and tuple(prior) != intended:
                raise ValidationError("SLA policy version is immutable")
            if not prior:
                connection.execute("INSERT INTO support_sla_policy VALUES(?,?,?,?,?,?)", (tenant_id, version, body["effectiveAt"], response_minutes, service_credit_basis_points, digest))
                self._append_audit(
                    connection, tenant_id=tenant_id, event_type="SLA_CREATED",
                    entity_id=version, actor=actor, payload={**body, "policyDigest": digest},
                    occurred_at=now or datetime.now(timezone.utc),
                )
        return digest

    def open_ticket(self, ticket_id: str, tenant_id: str, severity: str, *, actor: str, opened_at: datetime | None = None) -> dict[str, Any]:
        current = opened_at or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValidationError("ticket opened_at must be timezone-aware")
        if severity not in {"SEV1", "SEV2", "SEV3", "SEV4"}:
            raise ValidationError("support severity must be SEV1..SEV4")
        opened = current.astimezone(timezone.utc)
        with self.store.transaction() as connection:
            policy = connection.execute(
                "SELECT version,response_minutes FROM support_sla_policy WHERE tenant_id=? AND effective_at<=? ORDER BY effective_at DESC LIMIT 1",
                (tenant_id, opened.isoformat()),
            ).fetchone()
            if not policy:
                raise ValidationError("no effective SLA policy for tenant")
            due = opened + timedelta(minutes=policy["response_minutes"])
            body = {"ticketId": ticket_id, "tenantId": tenant_id, "severity": severity, "policyVersion": policy["version"], "openedAt": opened.isoformat(), "responseDueAt": due.isoformat()}
            digest = sha256_json(body)
            prior = connection.execute("SELECT ticket_digest FROM support_ticket WHERE ticket_id=?", (ticket_id,)).fetchone()
            if prior:
                if prior["ticket_digest"] != digest:
                    raise ValidationError("support ticket id is immutable")
                return {**body, "ticketDigest": digest, "status": "OPEN"}
            connection.execute("INSERT INTO support_ticket VALUES(?,?,?,?,?,?,?,?,?,?,?)", (ticket_id, tenant_id, severity, policy["version"], opened.isoformat(), due.isoformat(), None, None, "OPEN", 0, digest))
            self._append_audit(
                connection, tenant_id=tenant_id, event_type="TICKET_OPENED",
                entity_id=ticket_id, actor=actor,
                payload={**body, "ticketDigest": digest}, occurred_at=opened,
            )
        return {**body, "ticketDigest": digest, "status": "OPEN"}

    def respond_ticket(self, ticket_id: str, tenant_id: str, responder: str, *, responded_at: datetime | None = None) -> dict[str, Any]:
        current = responded_at or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValidationError("ticket responded_at must be timezone-aware")
        responded = current.astimezone(timezone.utc)
        with self.store.transaction() as connection:
            ticket = connection.execute("SELECT * FROM support_ticket WHERE ticket_id=?", (ticket_id,)).fetchone()
            if not ticket or ticket["tenant_id"] != tenant_id:
                raise ValidationError("support ticket is not owned by tenant")
            if ticket["status"] != "OPEN":
                raise ValidationError("support ticket already responded or closed")
            breached = responded > datetime.fromisoformat(ticket["response_due_at"])
            connection.execute("UPDATE support_ticket SET first_response_at=?,responder=?,status='RESPONDED',sla_breached=? WHERE ticket_id=?", (responded.isoformat(), require_text(responder, "responder"), int(breached), ticket_id))
            self._append_audit(
                connection, tenant_id=tenant_id, event_type="TICKET_RESPONDED",
                entity_id=ticket_id, actor=responder,
                payload={"respondedAt": responded.isoformat(), "slaBreached": breached},
                occurred_at=responded,
            )
        return {"ticketId": ticket_id, "respondedAt": responded.isoformat(), "slaBreached": breached}

    def sla_credit_minor(self, tenant_id: str, ticket_id: str, invoice_id: str) -> int:
        with self.store.connect() as connection:
            ticket = connection.execute("SELECT policy_version,sla_breached FROM support_ticket WHERE ticket_id=? AND tenant_id=?", (ticket_id, tenant_id)).fetchone()
            invoice = connection.execute("SELECT subtotal_minor FROM commercial_invoice WHERE invoice_id=? AND tenant_id=?", (invoice_id, tenant_id)).fetchone()
            if not ticket or not invoice:
                raise ValidationError("ticket or invoice is not owned by tenant")
            if not ticket["sla_breached"]:
                return 0
            policy = connection.execute("SELECT service_credit_basis_points FROM support_sla_policy WHERE tenant_id=? AND version=?", (tenant_id, ticket["policy_version"])).fetchone()
        return invoice["subtotal_minor"] * policy["service_credit_basis_points"] // 10000

    def request_credit(self, request_id: str, tenant_id: str, invoice_id: str, requester: str, amount_minor: int, reason: str, *, now: datetime | None = None) -> bool:
        if isinstance(amount_minor, bool) or not isinstance(amount_minor, int) or amount_minor <= 0:
            raise ValidationError("credit amount must be positive integer minor units")
        with self.store.transaction() as connection:
            actor = require_text(requester, "requester")
            explanation = require_text(reason, "reason")
            prior_request = connection.execute(
                "SELECT tenant_id,invoice_id,requester,amount_minor,reason "
                "FROM credit_request WHERE request_id=?", (request_id,),
            ).fetchone()
            intended_request = (
                tenant_id, invoice_id, actor, amount_minor, explanation,
            )
            if prior_request:
                if tuple(prior_request) != intended_request:
                    raise ValidationError("credit request id is immutable")
                return False
            invoice = connection.execute(
                "SELECT tenant_id,subtotal_minor,pricing_version_id,status "
                "FROM commercial_invoice WHERE invoice_id=?", (invoice_id,)
            ).fetchone()
            if not invoice or invoice["tenant_id"] != tenant_id:
                raise ValidationError("invoice is not owned by tenant")
            if invoice["status"] != "ISSUED":
                raise ValidationError("credits require an issued invoice")
            credit_limit = self._credit_limit_minor(connection, invoice)
            reserved = connection.execute(
                "SELECT coalesce(sum(amount_minor),0) FROM credit_request "
                "WHERE tenant_id=? AND invoice_id=? AND status IN ('PENDING','APPROVED')",
                (tenant_id, invoice_id),
            ).fetchone()[0]
            if reserved + amount_minor > credit_limit:
                raise ValidationError("aggregate credits exceed invoice credit limit")
            connection.execute("INSERT INTO credit_request VALUES(?,?,?,?,?,?,?,?,?,?)", (request_id, tenant_id, invoice_id, actor, amount_minor, explanation, "PENDING", None, _instant(now), None))
            self._append_audit(
                connection, tenant_id=tenant_id, event_type="CREDIT_REQUESTED",
                entity_id=request_id, actor=requester,
                payload={"invoiceId": invoice_id, "amountMinor": amount_minor,
                         "reasonDigest": sha256_json(reason)},
                occurred_at=self._monotonic_audit_time(connection, now),
            )
        return True

    def approve_credit(self, request_id: str, tenant_id: str, approver: str, *, now: datetime | None = None) -> dict[str, Any]:
        instant = _instant(now)
        with self.store.transaction() as connection:
            request = connection.execute("SELECT * FROM credit_request WHERE request_id=?", (request_id,)).fetchone()
            actor = require_text(approver, "approver")
            if not request or request["tenant_id"] != require_text(tenant_id, "tenant_id"):
                raise ValidationError("credit request is not pending")
            if request["status"] == "APPROVED":
                if request["approver"] != actor:
                    raise ValidationError("credit request was approved by another actor")
                memo = connection.execute(
                    "SELECT memo_id,tenant_id,invoice_id,amount_minor,issued_at,memo_digest "
                    "FROM credit_memo WHERE request_id=?", (request_id,),
                ).fetchone()
                if not memo:
                    raise ValidationError("approved credit memo is missing")
                body = {
                    "memoId": memo["memo_id"], "requestId": request_id,
                    "tenantId": memo["tenant_id"], "invoiceId": memo["invoice_id"],
                    "amountMinor": memo["amount_minor"], "issuedAt": memo["issued_at"],
                }
                if sha256_json(body) != memo["memo_digest"]:
                    raise ValidationError("approved credit memo is corrupt")
                return {**body, "memoDigest": memo["memo_digest"], "approver": actor}
            if request["status"] != "PENDING":
                raise ValidationError("credit request is not pending")
            if actor == request["requester"]:
                raise ValidationError("credit requester and approver must be distinct")
            invoice = connection.execute(
                "SELECT tenant_id,subtotal_minor,pricing_version_id,status "
                "FROM commercial_invoice WHERE invoice_id=?",
                (request["invoice_id"],),
            ).fetchone()
            if not invoice or invoice["tenant_id"] != request["tenant_id"]:
                raise ValidationError("credit invoice ownership is invalid")
            if invoice["status"] != "ISSUED":
                raise ValidationError("credits require an issued invoice")
            approved = connection.execute(
                "SELECT coalesce(sum(amount_minor),0) FROM credit_memo "
                "WHERE tenant_id=? AND invoice_id=?",
                (request["tenant_id"], request["invoice_id"]),
            ).fetchone()[0]
            if approved + request["amount_minor"] > self._credit_limit_minor(connection, invoice):
                raise ValidationError("approved credits exceed invoice credit limit")
            memo_id = sha256_json({"requestId": request_id, "approver": actor})
            body = {"memoId": memo_id, "requestId": request_id, "tenantId": request["tenant_id"], "invoiceId": request["invoice_id"], "amountMinor": request["amount_minor"], "issuedAt": instant}
            digest = sha256_json(body)
            connection.execute("UPDATE credit_request SET status='APPROVED',approver=?,decided_at=? WHERE request_id=?", (actor, instant, request_id))
            connection.execute("INSERT INTO credit_memo VALUES(?,?,?,?,?,?,?)", (memo_id, request_id, request["tenant_id"], request["invoice_id"], request["amount_minor"], instant, digest))
            self._append_audit(
                connection, tenant_id=request["tenant_id"], event_type="CREDIT_APPROVED",
                entity_id=request_id, actor=actor,
                payload={"memoId": memo_id, "invoiceId": request["invoice_id"],
                         "amountMinor": request["amount_minor"], "memoDigest": digest},
                occurred_at=self._monotonic_audit_time(connection, now),
            )
        return {**body, "memoDigest": digest, "approver": actor}

    def net_invoice_minor(self, tenant_id: str, invoice_id: str) -> int:
        with self.store.connect() as connection:
            invoice = connection.execute("SELECT tenant_id,subtotal_minor FROM commercial_invoice WHERE invoice_id=?", (invoice_id,)).fetchone()
            if not invoice or invoice["tenant_id"] != tenant_id:
                raise ValidationError("invoice is not owned by tenant")
            credits = connection.execute("SELECT coalesce(sum(amount_minor),0) FROM credit_memo WHERE tenant_id=? AND invoice_id=?", (tenant_id, invoice_id)).fetchone()[0]
        net = invoice["subtotal_minor"] - credits
        if net < 0:
            raise ValidationError("approved credits exceed invoice subtotal")
        return net

    @staticmethod
    def _credit_limit_minor(connection: Any, invoice: Any) -> int:
        pricing = connection.execute(
            "SELECT policy_json FROM pricing_version WHERE pricing_version_id=?",
            (invoice["pricing_version_id"],),
        ).fetchone()
        if not pricing:
            raise ValidationError("invoice pricing policy is missing")
        policy = require_mapping(json.loads(pricing["policy_json"]), "pricing policy")
        credits = require_mapping(policy.get("credits"), "pricing.credits")
        maximum_percent = credits.get("maximumPercentOfInvoice")
        if (
            isinstance(maximum_percent, bool)
            or not isinstance(maximum_percent, int)
            or not 0 <= maximum_percent <= 100
        ):
            raise ValidationError("pricing credit limit must be 0..100 percent")
        return invoice["subtotal_minor"] * maximum_percent // 100

    @staticmethod
    def _build_audit_manifest(
        connection: Any, tenant_id: str, start: str, end: str
    ) -> dict[str, Any]:
        rows = connection.execute(
            "SELECT sequence_id,event_type,entity_id,actor_id,occurred_at,payload_digest,"
            "previous_digest,event_digest,payload_json FROM commercial_audit_event "
            "WHERE tenant_id=? AND occurred_at>=? AND occurred_at<? ORDER BY sequence_id",
            (tenant_id, start, end),
        ).fetchall()
        predecessor = connection.execute(
            "SELECT event_digest FROM commercial_audit_event WHERE tenant_id=? "
            "AND occurred_at<? ORDER BY sequence_id DESC LIMIT 1",
            (tenant_id, start),
        ).fetchone()
        predecessor_digest = predecessor["event_digest"] if predecessor else None
        events: list[dict[str, Any]] = []
        previous_in_window: str | None = None
        starting_previous: str | None = None
        for index, row in enumerate(rows):
            try:
                payload = require_mapping(json.loads(row["payload_json"]), "audit payload")
            except (json.JSONDecodeError, TypeError, ValidationError) as exc:
                raise ValidationError("commercial audit payload is corrupt") from exc
            if sha256_json(payload) != row["payload_digest"]:
                raise ValidationError("commercial audit payload digest mismatch")
            body = {
                "tenantId": tenant_id, "eventType": row["event_type"],
                "entityId": row["entity_id"], "actorId": row["actor_id"],
                "occurredAt": row["occurred_at"], "payloadDigest": row["payload_digest"],
                "previousDigest": row["previous_digest"],
            }
            if sha256_json(body) != row["event_digest"]:
                raise ValidationError("commercial audit event digest mismatch")
            if index == 0:
                starting_previous = row["previous_digest"]
                if starting_previous != predecessor_digest:
                    raise ValidationError("commercial audit chain predecessor is invalid")
            elif row["previous_digest"] != previous_in_window:
                raise ValidationError("commercial audit chain is discontinuous")
            previous_in_window = row["event_digest"]
            events.append({
                "sequenceId": row["sequence_id"], **body,
                "eventDigest": row["event_digest"], "payload": dict(payload),
            })
        manifest = {
            "schemaVersion": 1,
            "tenantId": tenant_id,
            "periodStart": start,
            "periodEnd": end,
            "eventCount": len(events),
            "startingPreviousDigest": starting_previous,
            "endingDigest": previous_in_window,
            "events": events,
        }
        return {**manifest, "manifestDigest": sha256_json(manifest)}

    def build_audit_manifest(
        self,
        tenant_id: str,
        period_start: datetime,
        period_end: datetime,
    ) -> dict[str, Any]:
        """Build and verify a tenant-scoped commercial audit-chain export."""

        require_text(tenant_id, "tenant_id")
        if period_start.tzinfo is None or period_end.tzinfo is None or period_end <= period_start:
            raise ValidationError("audit export period must be increasing and timezone-aware")
        start = period_start.astimezone(timezone.utc).isoformat()
        end = period_end.astimezone(timezone.utc).isoformat()
        with self.store.connect() as connection:
            return self._build_audit_manifest(connection, tenant_id, start, end)

    def finalize_audit_export(
        self,
        *,
        export_id: str,
        tenant_id: str,
        period_start: datetime,
        period_end: datetime,
        receipt: Mapping[str, Any],
        trust: Mapping[str, Any],
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Verify a KMS/audit signer receipt and persist the export record."""

        require_text(export_id, "export_id")
        current = _current(now)
        if (
            period_start.tzinfo is None
            or period_end.tzinfo is None
            or period_end <= period_start
        ):
            raise ValidationError(
                "audit export period must be increasing and timezone-aware"
            )
        normalized_start = period_start.astimezone(timezone.utc).isoformat()
        normalized_end = period_end.astimezone(timezone.utc).isoformat()
        if period_end.astimezone(timezone.utc) > current:
            raise ValidationError("audit export period must be complete before signing")
        receipt_document = require_mapping(receipt, "commercial audit export receipt")
        receipt_encoded = canonical_json(receipt_document).decode("utf-8")

        with self.store.connect() as connection:
            prior = connection.execute(
                "SELECT tenant_id,period_start,period_end,event_count,ending_digest,"
                "manifest_digest,signer_identity,receipt_digest,manifest_json,"
                "receipt_json,created_at FROM commercial_audit_export WHERE export_id=?",
                (export_id,),
            ).fetchone()
        if prior:
            if (
                prior["tenant_id"] != tenant_id
                or prior["period_start"] != normalized_start
                or prior["period_end"] != normalized_end
                or not prior["manifest_json"]
                or not prior["receipt_json"]
                or prior["receipt_json"] != receipt_encoded
                or prior["receipt_digest"] != sha256_json(receipt_document)
            ):
                raise ValidationError("commercial audit export id is immutable")
            try:
                manifest = require_mapping(
                    json.loads(prior["manifest_json"]), "stored audit manifest"
                )
            except (json.JSONDecodeError, TypeError) as exc:
                raise ValidationError("stored commercial audit manifest is corrupt") from exc
            unsigned_manifest = {
                key: value for key, value in manifest.items()
                if key != "manifestDigest"
            }
            if (
                manifest.get("manifestDigest") != sha256_json(unsigned_manifest)
                or manifest.get("manifestDigest") != prior["manifest_digest"]
                or manifest.get("eventCount") != prior["event_count"]
                or manifest.get("endingDigest") != prior["ending_digest"]
            ):
                raise ValidationError("stored commercial audit manifest is corrupt")
            fields = {
                "exportId": export_id,
                "tenantId": tenant_id,
                "periodStart": normalized_start,
                "periodEnd": normalized_end,
                "manifestDigest": prior["manifest_digest"],
                "eventCount": prior["event_count"],
                "endingDigest": prior["ending_digest"],
            }
            receipt_digest, signer = verify_downstream_receipt(
                receipt_document,
                trust,
                receipt_type="COMMERCIAL_AUDIT_EXPORT",
                outcome="SIGNED",
                fields=fields,
                required_role="audit_export_signer",
                now=parse_instant(prior["created_at"], "audit export created_at"),
            )
            if (
                receipt_digest != prior["receipt_digest"]
                or signer.identity != prior["signer_identity"]
            ):
                raise ValidationError("commercial audit export signer binding changed")
            return {
                "exportId": export_id,
                "createdAt": prior["created_at"],
                "signerIdentity": signer.identity,
                "receiptDigest": receipt_digest,
                "manifest": dict(manifest),
            }

        manifest = self.build_audit_manifest(tenant_id, period_start, period_end)
        fields = {
            "exportId": export_id,
            "tenantId": tenant_id,
            "periodStart": manifest["periodStart"],
            "periodEnd": manifest["periodEnd"],
            "manifestDigest": manifest["manifestDigest"],
            "eventCount": manifest["eventCount"],
            "endingDigest": manifest["endingDigest"],
        }
        receipt_digest, signer = verify_downstream_receipt(
            receipt_document,
            trust,
            receipt_type="COMMERCIAL_AUDIT_EXPORT",
            outcome="SIGNED",
            fields=fields,
            required_role="audit_export_signer",
            now=current,
        )
        created_at = current.isoformat()
        manifest_encoded = canonical_json(manifest).decode("utf-8")
        with self.store.transaction() as connection:
            current_manifest = self._build_audit_manifest(
                connection, tenant_id, normalized_start, normalized_end
            )
            if current_manifest != manifest:
                raise ValidationError(
                    "commercial audit manifest changed before durable finalization"
                )
            prior = connection.execute(
                "SELECT tenant_id,period_start,period_end,event_count,ending_digest,"
                "manifest_digest,signer_identity,receipt_digest,manifest_json,"
                "receipt_json,created_at "
                "FROM commercial_audit_export WHERE export_id=?",
                (export_id,),
            ).fetchone()
            expected = (
                tenant_id, manifest["periodStart"], manifest["periodEnd"],
                manifest["eventCount"], manifest["endingDigest"], manifest["manifestDigest"],
                signer.identity, receipt_digest,
            )
            if prior:
                actual = tuple(prior[key] for key in (
                    "tenant_id", "period_start", "period_end", "event_count",
                    "ending_digest", "manifest_digest", "signer_identity", "receipt_digest",
                ))
                if (
                    actual != expected
                    or prior["manifest_json"] != manifest_encoded
                    or prior["receipt_json"] != receipt_encoded
                ):
                    raise ValidationError("commercial audit export id is immutable")
                created_at = prior["created_at"]
            else:
                connection.execute(
                    "INSERT INTO commercial_audit_export VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        export_id, *expected, manifest_encoded,
                        receipt_encoded, created_at,
                    ),
                )
                self._append_audit(
                    connection, tenant_id=tenant_id, event_type="AUDIT_EXPORTED",
                    entity_id=export_id, actor=signer.identity,
                    payload={"manifestDigest": manifest["manifestDigest"],
                             "receiptDigest": receipt_digest,
                             "eventCount": manifest["eventCount"]},
                    occurred_at=current,
                )
        return {
            "exportId": export_id,
            "createdAt": created_at,
            "signerIdentity": signer.identity,
            "receiptDigest": receipt_digest,
            "manifest": manifest,
        }
