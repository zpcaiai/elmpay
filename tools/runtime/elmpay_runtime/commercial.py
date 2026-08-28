"""Persistent metering, invoicing, SLA/support and four-eyes credits (B126)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Mapping

from .common import ValidationError, canonical_json, parse_instant, require_list, require_mapping, require_text, sha256_json
from .downstream_receipt import verify_downstream_receipt
from .durable import DurableStore


def _instant(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


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
        with self.store.transaction() as connection:
            prior = connection.execute("SELECT policy_digest,policy_json FROM pricing_version WHERE pricing_version_id=?", (pricing_id,)).fetchone()
            if prior and (prior["policy_digest"], prior["policy_json"]) != (digest, encoded):
                raise ValidationError("pricing version is immutable")
            if not prior:
                connection.execute("INSERT INTO pricing_version VALUES(?,?,?,?,?,?,?)", (pricing_id, tenant_id, currency, effective_at.astimezone(timezone.utc).isoformat(), digest, encoded, _instant(now)))
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
        with self.store.transaction() as connection:
            pricing = connection.execute("SELECT tenant_id,policy_json FROM pricing_version WHERE pricing_version_id=?", (pricing_version_id,)).fetchone()
            if not pricing or pricing["tenant_id"] != tenant_id:
                raise ValidationError("pricing version is not owned by tenant")
            policy = json.loads(pricing["policy_json"])
            meter_name = require_text(payload.get("meter"), "event.meter")
            meter = next((item for item in policy["meters"] if item["name"] == meter_name), None)
            if not meter:
                raise ValidationError("unknown usage meter")
            dedupe_field = meter["deduplicateBy"]
            dedupe_key = require_text(payload.get(dedupe_field), f"event.{dedupe_field}")
            occurred = parse_instant(payload.get("occurredAt"), "event.occurredAt").isoformat()
            digest = sha256_json(payload)
            prior = connection.execute("SELECT payload_digest FROM usage_event WHERE tenant_id=? AND meter=? AND dedupe_key=?", (tenant_id, meter_name, dedupe_key)).fetchone()
            if prior:
                if prior["payload_digest"] != digest:
                    raise ValidationError("usage dedupe key reused with different payload")
                return False
            connection.execute("INSERT INTO usage_event VALUES(?,?,?,?,?)", (tenant_id, meter_name, dedupe_key, occurred, digest))
            self._append_audit(
                connection, tenant_id=tenant_id, event_type="USAGE_METERED",
                entity_id=f"{meter_name}:{dedupe_key}", actor=actor,
                payload={"meter": meter_name, "dedupeKeyDigest": sha256_json(dedupe_key),
                         "occurredAt": occurred, "usagePayloadDigest": digest,
                         "pricingVersionId": pricing_version_id},
                occurred_at=now or datetime.now(timezone.utc),
            )
        return True

    def issue_invoice(self, invoice_id: str, tenant_id: str, pricing_version_id: str, period_start: datetime, period_end: datetime, *, actor: str, now: datetime | None = None) -> dict[str, Any]:
        if period_start.tzinfo is None or period_end.tzinfo is None or period_end <= period_start:
            raise ValidationError("invoice period must be increasing and timezone-aware")
        with self.store.transaction() as connection:
            pricing = connection.execute("SELECT tenant_id,currency,effective_at,policy_json FROM pricing_version WHERE pricing_version_id=?", (pricing_version_id,)).fetchone()
            if not pricing or pricing["tenant_id"] != tenant_id:
                raise ValidationError("pricing version is not owned by tenant")
            if datetime.fromisoformat(pricing["effective_at"]) > period_start.astimezone(timezone.utc):
                raise ValidationError("pricing version was not effective at period start")
            policy = json.loads(pricing["policy_json"])
            lines: list[dict[str, int | str]] = []
            for meter in sorted(policy["meters"], key=lambda item: item["name"]):
                quantity = connection.execute("SELECT count(*) FROM usage_event WHERE tenant_id=? AND meter=? AND occurred_at>=? AND occurred_at<?", (tenant_id, meter["name"], period_start.astimezone(timezone.utc).isoformat(), period_end.astimezone(timezone.utc).isoformat())).fetchone()[0]
                if quantity:
                    price = int(meter["unitPriceMinor"])
                    lines.append({"meter": meter["name"], "quantity": quantity, "unitPriceMinor": price, "totalMinor": quantity * price})
            subtotal = sum(int(line["totalMinor"]) for line in lines)
            body = {"invoiceId": invoice_id, "tenantId": tenant_id, "pricingVersionId": pricing_version_id, "periodStart": period_start.astimezone(timezone.utc).isoformat(), "periodEnd": period_end.astimezone(timezone.utc).isoformat(), "currency": pricing["currency"], "lines": lines, "subtotalMinor": subtotal}
            digest = sha256_json(body)
            prior = connection.execute("SELECT invoice_digest FROM commercial_invoice WHERE invoice_id=?", (invoice_id,)).fetchone()
            if prior:
                if prior["invoice_digest"] != digest:
                    raise ValidationError("invoice id is immutable")
                return {**body, "invoiceDigest": digest, "status": "ISSUED"}
            connection.execute("INSERT INTO commercial_invoice VALUES(?,?,?,?,?,?,?,?,?,?)", (invoice_id, tenant_id, pricing_version_id, body["periodStart"], body["periodEnd"], pricing["currency"], subtotal, "ISSUED", digest, _instant(now)))
            for line in lines:
                connection.execute("INSERT INTO commercial_invoice_line VALUES(?,?,?,?,?)", (invoice_id, line["meter"], line["quantity"], line["unitPriceMinor"], line["totalMinor"]))
            self._append_audit(
                connection, tenant_id=tenant_id, event_type="INVOICE_ISSUED",
                entity_id=invoice_id, actor=actor,
                payload={"invoiceDigest": digest, "pricingVersionId": pricing_version_id,
                         "currency": pricing["currency"], "subtotalMinor": subtotal,
                         "periodStart": body["periodStart"], "periodEnd": body["periodEnd"]},
                occurred_at=now or datetime.now(timezone.utc),
            )
        return {**body, "invoiceDigest": digest, "status": "ISSUED"}

    def set_sla(self, tenant_id: str, version: str, effective_at: datetime, response_minutes: int, service_credit_basis_points: int, *, actor: str, now: datetime | None = None) -> str:
        if effective_at.tzinfo is None:
            raise ValidationError("SLA effective_at must be timezone-aware")
        if isinstance(response_minutes, bool) or not isinstance(response_minutes, int) or response_minutes <= 0:
            raise ValidationError("response_minutes must be positive")
        if isinstance(service_credit_basis_points, bool) or not isinstance(service_credit_basis_points, int) or not 0 <= service_credit_basis_points <= 10000:
            raise ValidationError("service credit basis points must be 0..10000")
        body = {"tenantId": tenant_id, "version": version, "effectiveAt": effective_at.astimezone(timezone.utc).isoformat(), "responseMinutes": response_minutes, "serviceCreditBasisPoints": service_credit_basis_points}
        digest = sha256_json(body)
        with self.store.transaction() as connection:
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

    def request_credit(self, request_id: str, tenant_id: str, invoice_id: str, requester: str, amount_minor: int, reason: str, *, now: datetime | None = None) -> None:
        if isinstance(amount_minor, bool) or not isinstance(amount_minor, int) or amount_minor <= 0:
            raise ValidationError("credit amount must be positive integer minor units")
        with self.store.transaction() as connection:
            invoice = connection.execute("SELECT tenant_id,subtotal_minor FROM commercial_invoice WHERE invoice_id=?", (invoice_id,)).fetchone()
            if not invoice or invoice["tenant_id"] != tenant_id:
                raise ValidationError("invoice is not owned by tenant")
            if amount_minor > invoice["subtotal_minor"]:
                raise ValidationError("credit exceeds invoice subtotal")
            connection.execute("INSERT INTO credit_request VALUES(?,?,?,?,?,?,?,?,?,?)", (request_id, tenant_id, invoice_id, require_text(requester, "requester"), amount_minor, require_text(reason, "reason"), "PENDING", None, _instant(now), None))
            self._append_audit(
                connection, tenant_id=tenant_id, event_type="CREDIT_REQUESTED",
                entity_id=request_id, actor=requester,
                payload={"invoiceId": invoice_id, "amountMinor": amount_minor,
                         "reasonDigest": sha256_json(reason)},
                occurred_at=now or datetime.now(timezone.utc),
            )

    def approve_credit(self, request_id: str, approver: str, *, now: datetime | None = None) -> dict[str, Any]:
        instant = _instant(now)
        with self.store.transaction() as connection:
            request = connection.execute("SELECT * FROM credit_request WHERE request_id=?", (request_id,)).fetchone()
            if not request or request["status"] != "PENDING":
                raise ValidationError("credit request is not pending")
            actor = require_text(approver, "approver")
            if actor == request["requester"]:
                raise ValidationError("credit requester and approver must be distinct")
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
                occurred_at=now or datetime.now(timezone.utc),
            )
        return {**body, "memoDigest": digest, "approver": actor}

    def net_invoice_minor(self, tenant_id: str, invoice_id: str) -> int:
        with self.store.connect() as connection:
            invoice = connection.execute("SELECT tenant_id,subtotal_minor FROM commercial_invoice WHERE invoice_id=?", (invoice_id,)).fetchone()
            if not invoice or invoice["tenant_id"] != tenant_id:
                raise ValidationError("invoice is not owned by tenant")
            credits = connection.execute("SELECT coalesce(sum(amount_minor),0) FROM credit_memo WHERE tenant_id=? AND invoice_id=?", (tenant_id, invoice_id)).fetchone()[0]
        return invoice["subtotal_minor"] - credits

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
            rows = connection.execute(
                "SELECT sequence_id,event_type,entity_id,actor_id,occurred_at,payload_digest,"
                "previous_digest,event_digest,payload_json FROM commercial_audit_event "
                "WHERE tenant_id=? AND occurred_at>=? AND occurred_at<? ORDER BY sequence_id",
                (tenant_id, start, end),
            ).fetchall()
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
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValidationError("audit export time must be timezone-aware")
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
            receipt,
            trust,
            receipt_type="COMMERCIAL_AUDIT_EXPORT",
            outcome="SIGNED",
            fields=fields,
            required_role="audit_export_signer",
            now=current,
        )
        created_at = current.astimezone(timezone.utc).isoformat()
        with self.store.transaction() as connection:
            prior = connection.execute(
                "SELECT tenant_id,period_start,period_end,event_count,ending_digest,"
                "manifest_digest,signer_identity,receipt_digest,created_at "
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
                if actual != expected:
                    raise ValidationError("commercial audit export id is immutable")
                created_at = prior["created_at"]
            else:
                connection.execute(
                    "INSERT INTO commercial_audit_export VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (export_id, *expected, created_at),
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
