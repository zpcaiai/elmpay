"""B25 — an executable merchant onboarding / KYB model.

Everything here follows from one sentence in the brief: the platform manages
merchant records **but does not replace a licensed verifier**. So the single
most important thing this module refuses to do is set its own status to
"verified". :meth:`Onboarding.decide` will not produce a ``VERIFIED`` merchant
unless it is handed an external authority's decision — issuer, reference,
decision date and an expiry. A status a platform can award itself is a status
that means nothing the day a regulator or a defrauded payer asks who checked.

Two more behaviours are deliberately counter-intuitive and both are enforced:

* a **sanctions hit neither approves nor rejects**. Auto-approval is obviously
  wrong; auto-rejection is quietly worse, because screening lists match on
  names and would strand large numbers of innocent merchants with no route
  back. A hit moves the file to ``MANUAL_REVIEW`` and nowhere else;
* a **payout-account change holds settlement but does not stop payments**.
  Freezing the whole merchant would strand payers whose money has already left;
  holding only the outbound leg keeps the money on the platform until the new
  account has been re-verified. This is the exact shape of an account-takeover,
  so the hold is not optional and cannot be lifted by the person who requested
  the change.

Time is an integer day number supplied by the caller. Nothing here reads the
clock, so every expiry test is reproducible.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DRAFT = "draft"
PENDING_REVIEW = "pending_review"
MANUAL_REVIEW = "manual_review"
VERIFIED = "verified"
REJECTED = "rejected"

DENY_UNKNOWN = "DENY_UNKNOWN"
DENY_SELF_VERIFIED = "DENY_SELF_VERIFIED"
DENY_AUTHORITY_INCOMPLETE = "DENY_AUTHORITY_INCOMPLETE"
DENY_AUTHORITY_EXPIRED = "DENY_AUTHORITY_EXPIRED"
DENY_VALIDITY_TOO_LONG = "DENY_VALIDITY_TOO_LONG"
DENY_NOT_ATTESTABLE = "DENY_NOT_ATTESTABLE"
DENY_DOCUMENT_MISSING = "DENY_DOCUMENT_MISSING"
DENY_DOCUMENT_EXPIRED = "DENY_DOCUMENT_EXPIRED"
DENY_UBO_INCOMPLETE = "DENY_UBO_INCOMPLETE"
DENY_UBO_DEPTH = "DENY_UBO_DEPTH"
DENY_SCREENING_STALE = "DENY_SCREENING_STALE"
DENY_SCREENING_HIT = "DENY_SCREENING_HIT"
DENY_PROHIBITED_CATEGORY = "DENY_PROHIBITED_CATEGORY"
DENY_CURRENCY = "DENY_CURRENCY"
DENY_LIMIT = "DENY_LIMIT"
DENY_APPROVERS = "DENY_APPROVERS"
DENY_SELF_APPROVAL = "DENY_SELF_APPROVAL"
DENY_PERMISSION = "DENY_PERMISSION"
DENY_SETTLEMENT_HELD = "DENY_SETTLEMENT_HELD"
DENY_REVERIFICATION_REQUIRED = "DENY_REVERIFICATION_REQUIRED"
DENY_NO_REASONS = "DENY_NO_REASONS"


class ProfileRefused(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Document:
    """A piece of KYB evidence. ``issued_on`` is a day number."""

    id: str
    issued_on: int
    issuer: str


@dataclass(frozen=True)
class Authority:
    """An external licensed verifier's decision. The platform cannot mint one."""

    authority: str
    decision_reference: str
    decided_at: int
    valid_until: int


@dataclass(frozen=True)
class Owner:
    id: str
    percent: float
    depth: int
    has_identity_document: bool = True
    screened_on: int | None = None
    screening_hit: bool = False


@dataclass
class Merchant:
    id: str
    entity_kind: str
    category: str
    region: str
    risk: str = "low"
    status: str = DRAFT
    documents: dict[str, Document] = field(default_factory=dict)
    owners: tuple[Owner, ...] = ()
    authority: Authority | None = None
    settlement_held: bool = False
    settlement_hold_requested_by: str | None = None
    pending_reverification: tuple[str, ...] = ()
    attested: dict[str, str] = field(default_factory=dict)
    decided_by: str | None = None
    reasons: tuple[str, ...] = ()
    history: list[dict] = field(default_factory=list)


class Onboarding:
    """The merchant file as the platform would enforce it, minus the storage."""

    def __init__(self, model: dict) -> None:
        self.model = model
        self.verification = model["verification"]
        self.entity_kinds = {e["id"]: e for e in model["entity_kinds"]}
        self.documents = {d["id"]: d for d in model["documents"]}
        self.ubo = model["ubo"]
        self.screening = model["screening"]
        self.categories = {c["code"]: c for c in model["business_categories"]}
        self.regions = {r["code"]: r for r in model["operating_regions"]}
        self.risk_levels = {r["id"]: r for r in model["risk_levels"]}
        self.changes = {c["id"]: c for c in model["material_changes"]}
        self.merchants: dict[str, Merchant] = {}
        self.daily_used: dict[tuple[str, int], int] = {}

    # -- registration -----------------------------------------------------
    def register(self, merchant_id: str, *, entity_kind: str, category: str,
                 region: str, risk: str = "low") -> Merchant:
        if entity_kind not in self.entity_kinds:
            raise ProfileRefused(DENY_UNKNOWN, f"entity kind {entity_kind}")
        if region not in self.regions:
            raise ProfileRefused(DENY_UNKNOWN, f"region {region}")
        if risk not in self.risk_levels:
            raise ProfileRefused(DENY_UNKNOWN, f"risk {risk}")
        entry = self.categories.get(category)
        if entry is None:
            raise ProfileRefused(DENY_UNKNOWN, f"category {category}")
        if not entry["allowed"]:
            raise ProfileRefused(DENY_PROHIBITED_CATEGORY, category)
        merchant = Merchant(id=merchant_id, entity_kind=entity_kind, category=category,
                            region=region, risk=risk)
        self.merchants[merchant_id] = merchant
        return merchant

    def get(self, merchant_id: str) -> Merchant:
        merchant = self.merchants.get(merchant_id)
        if merchant is None:
            raise ProfileRefused(DENY_UNKNOWN, merchant_id)
        return merchant

    # -- evidence ---------------------------------------------------------
    def attach(self, merchant_id: str, document: Document) -> Merchant:
        merchant = self.get(merchant_id)
        if document.id not in self.documents:
            raise ProfileRefused(DENY_UNKNOWN, f"document {document.id}")
        merchant.documents[document.id] = document
        return merchant

    def attest(self, merchant_id: str, field_name: str, value: str) -> Merchant:
        """Merchant-supplied facts. Only harmless display fields are allowed."""
        merchant = self.get(merchant_id)
        if field_name not in self.verification["self_attestation_allowed_for"]:
            raise ProfileRefused(DENY_NOT_ATTESTABLE, field_name)
        merchant.attested[field_name] = value
        return merchant

    def document_expiry(self, document: Document) -> int:
        return document.issued_on + self.documents[document.id]["expires_days"]

    def document_fresh(self, document: Document, today: int) -> bool:
        return today < self.document_expiry(document)

    def missing_documents(self, merchant_id: str,
                          today: int) -> tuple[tuple[str, ...], tuple[str, ...]]:
        merchant = self.get(merchant_id)
        required = self.entity_kinds[merchant.entity_kind]["required_documents"]
        missing = [d for d in required if d not in merchant.documents]
        stale = [d for d in required
                 if d in merchant.documents
                 and not self.document_fresh(merchant.documents[d], today)]
        return tuple(sorted(missing)), tuple(sorted(stale))

    def require_documents(self, merchant_id: str, today: int) -> str:
        missing, stale = self.missing_documents(merchant_id, today)
        if missing:
            raise ProfileRefused(DENY_DOCUMENT_MISSING, ",".join(missing))
        if stale:
            # An expired document is not weaker evidence, it is no evidence.
            raise ProfileRefused(DENY_DOCUMENT_EXPIRED, ",".join(stale))
        return "OK"

    # -- ownership --------------------------------------------------------
    def set_owners(self, merchant_id: str, owners: tuple[Owner, ...]) -> Merchant:
        merchant = self.get(merchant_id)
        merchant.owners = owners
        return merchant

    def beneficial_owners(self, merchant_id: str) -> tuple[Owner, ...]:
        merchant = self.get(merchant_id)
        threshold = self.ubo["ownership_threshold_percent"]
        return tuple(o for o in merchant.owners if o.percent >= threshold)

    def require_ownership(self, merchant_id: str, today: int) -> str:
        merchant = self.get(merchant_id)
        if "ubo_declaration" not in self.entity_kinds[merchant.entity_kind][
                "required_documents"]:
            return "OK"          # sole traders and individuals have no share cap table
        for owner in merchant.owners:
            if owner.depth > self.ubo["max_ownership_depth"]:
                raise ProfileRefused(DENY_UBO_DEPTH,
                                     f"{owner.id} sits at depth {owner.depth}")
        controllers = self.beneficial_owners(merchant_id)
        if not controllers:
            raise ProfileRefused(DENY_UBO_INCOMPLETE, "no owner reaches the threshold")
        for owner in controllers:
            if self.ubo["requires_identity_document"] and not owner.has_identity_document:
                raise ProfileRefused(DENY_UBO_INCOMPLETE, f"{owner.id} has no identity document")
            if self.ubo["screening_required"]:
                self.require_screening(owner, today)
        return "OK"

    # -- screening --------------------------------------------------------
    def require_screening(self, owner: Owner, today: int) -> str:
        if owner.screened_on is None:
            raise ProfileRefused(DENY_SCREENING_STALE, f"{owner.id} was never screened")
        if today - owner.screened_on > self.screening["rescreen_interval_days"]:
            raise ProfileRefused(DENY_SCREENING_STALE,
                                 f"{owner.id} last screened on day {owner.screened_on}")
        if owner.screening_hit:
            # Neither approve nor reject: a name match is not a finding.
            raise ProfileRefused(DENY_SCREENING_HIT, owner.id)
        return "OK"

    def screen(self, merchant_id: str, today: int) -> str:
        """Run the periodic re-screen. A hit parks the file for a human."""
        merchant = self.get(merchant_id)
        for owner in self.beneficial_owners(merchant_id):
            if owner.screening_hit:
                if self.screening["auto_approve_on_hit"]:      # pragma: no cover - model says false
                    raise ProfileRefused(DENY_SCREENING_HIT, "model would auto-approve")
                merchant.status = MANUAL_REVIEW
                merchant.history.append({"event": "screening_hit", "owner": owner.id,
                                         "day": today})
                return MANUAL_REVIEW
        return merchant.status

    # -- the decision -----------------------------------------------------
    def submit(self, merchant_id: str, today: int) -> Merchant:
        """Hand the file to a reviewer. Refuses to queue an incomplete file."""
        merchant = self.get(merchant_id)
        self.require_documents(merchant_id, today)
        merchant.status = PENDING_REVIEW
        merchant.history.append({"event": "submitted", "day": today})
        return merchant

    def mark_verified(self, merchant_id: str) -> Merchant:
        """The tempting shortcut. It does not exist."""
        raise ProfileRefused(DENY_SELF_VERIFIED,
                             "the platform is not a licensed verifier; "
                             "use decide() with an external authority record")

    def decide(self, merchant_id: str, *, today: int, authority: Authority | None,
               decider: str, approvers: tuple[str, ...] = ()) -> Merchant:
        merchant = self.get(merchant_id)
        if authority is None:
            raise ProfileRefused(DENY_SELF_VERIFIED, merchant_id)
        for name in self.verification["authority_fields"]:
            value = getattr(authority, name, None)
            if value is None or value == "":
                raise ProfileRefused(DENY_AUTHORITY_INCOMPLETE, name)
        if authority.valid_until - authority.decided_at > self.verification["max_validity_days"]:
            raise ProfileRefused(DENY_VALIDITY_TOO_LONG,
                                 f"{authority.valid_until - authority.decided_at} days")
        if authority.valid_until <= today:
            raise ProfileRefused(DENY_AUTHORITY_EXPIRED, str(authority.valid_until))
        self.require_documents(merchant_id, today)
        self.require_ownership(merchant_id, today)
        if decider in approvers:
            # Checked before the count: "you approved yourself" is a different
            # problem from "you are one approver short", and the operator needs
            # to be told which one they have.
            raise ProfileRefused(DENY_SELF_APPROVAL, decider)
        required = self.risk_levels[merchant.risk]["approvers_required"]
        distinct = set(approvers)
        if len(distinct) < required:
            raise ProfileRefused(DENY_APPROVERS,
                                 f"{merchant.risk} needs {required}, got {len(distinct)}")
        merchant.authority = authority
        merchant.status = VERIFIED
        merchant.decided_by = decider
        merchant.settlement_held = False
        merchant.settlement_hold_requested_by = None
        merchant.pending_reverification = ()
        merchant.history.append({"event": "verified", "authority": authority.authority,
                                 "reference": authority.decision_reference, "day": today})
        return merchant

    def reject(self, merchant_id: str, *, decider: str, reasons: tuple[str, ...],
               today: int) -> Merchant:
        merchant = self.get(merchant_id)
        if self.model["appeal"]["decision_must_state_reasons"] and not reasons:
            raise ProfileRefused(DENY_NO_REASONS, merchant_id)
        merchant.status = REJECTED
        merchant.decided_by = decider
        merchant.reasons = tuple(reasons)
        merchant.history.append({"event": "rejected", "day": today})
        return merchant

    def appeal(self, merchant_id: str, *, reviewer: str, today: int) -> Merchant:
        merchant = self.get(merchant_id)
        if self.model["appeal"]["reviewer_must_differ_from_decider"] \
                and reviewer == merchant.decided_by:
            raise ProfileRefused(DENY_SELF_APPROVAL, reviewer)
        merchant.status = MANUAL_REVIEW
        merchant.history.append({"event": "appealed", "reviewer": reviewer, "day": today})
        return merchant

    def verification_current(self, merchant_id: str, today: int) -> bool:
        merchant = self.get(merchant_id)
        return (merchant.status == VERIFIED and merchant.authority is not None
                and merchant.authority.valid_until > today)

    # -- change of circumstance -------------------------------------------
    def apply_change(self, merchant_id: str, change_id: str, *, actor: str,
                     permissions: set[str], today: int) -> Merchant:
        merchant = self.get(merchant_id)
        change = self.changes.get(change_id)
        if change is None:
            raise ProfileRefused(DENY_UNKNOWN, f"change {change_id}")
        if change["permission"] not in permissions:
            raise ProfileRefused(DENY_PERMISSION, change["permission"])
        if change["requires_reverification"]:
            # Deliberately *not* `status = PENDING_REVIEW`. The external
            # authority's decision about who this merchant is has not expired
            # and has not been withdrawn; what is now unproven is the change.
            # Un-verifying the whole file would stop incoming payments too, and
            # a merchant who cannot take payments cannot deliver the orders its
            # payers have already paid for. The pending re-verification is
            # recorded, and the settlement hold below is what actually protects
            # the money.
            merchant.pending_reverification = tuple(
                sorted(set(merchant.pending_reverification) | {change_id}))
        if change["holds_settlement"]:
            merchant.settlement_held = True
            merchant.settlement_hold_requested_by = actor
        merchant.history.append({"event": "material_change", "change": change_id,
                                 "actor": actor, "day": today})
        return merchant

    def reverification_pending(self, merchant_id: str) -> tuple[str, ...]:
        return self.get(merchant_id).pending_reverification

    def release_hold(self, merchant_id: str, *, actor: str, today: int) -> Merchant:
        """A hold is lifted by re-verification, never by the requester."""
        merchant = self.get(merchant_id)
        if actor == merchant.settlement_hold_requested_by:
            raise ProfileRefused(DENY_SELF_APPROVAL, actor)
        if merchant.pending_reverification:
            raise ProfileRefused(DENY_REVERIFICATION_REQUIRED,
                                 ",".join(merchant.pending_reverification))
        if not self.verification_current(merchant_id, today):
            raise ProfileRefused(DENY_REVERIFICATION_REQUIRED, merchant_id)
        merchant.settlement_held = False
        merchant.settlement_hold_requested_by = None
        return merchant

    # -- money ------------------------------------------------------------
    def limits(self, merchant_id: str) -> dict:
        return self.risk_levels[self.get(merchant_id).risk]

    def accept_payment(self, merchant_id: str, amount_minor: int, *, today: int) -> int:
        """Payments keep flowing while settlement is held — that is the point."""
        merchant = self.get(merchant_id)
        if merchant.status != VERIFIED:
            raise ProfileRefused(DENY_REVERIFICATION_REQUIRED, merchant.status)
        limits = self.limits(merchant_id)
        if amount_minor > limits["single_limit_minor"]:
            raise ProfileRefused(DENY_LIMIT, f"single {amount_minor}")
        used = self.daily_used.get((merchant_id, today), 0) + amount_minor
        if used > limits["daily_limit_minor"]:
            raise ProfileRefused(DENY_LIMIT, f"daily {used}")
        self.daily_used[(merchant_id, today)] = used
        return used

    def settle(self, merchant_id: str, currency: str, *, today: int) -> int:
        merchant = self.get(merchant_id)
        if merchant.settlement_held:
            raise ProfileRefused(DENY_SETTLEMENT_HELD, merchant_id)
        if not self.verification_current(merchant_id, today):
            raise ProfileRefused(DENY_REVERIFICATION_REQUIRED, merchant.status)
        if currency not in self.regions[merchant.region]["settlement_currencies"]:
            raise ProfileRefused(DENY_CURRENCY, f"{currency} not settled in {merchant.region}")
        return today + self.limits(merchant_id)["settlement_delay_days"]

    # -- retention --------------------------------------------------------
    def purge_day(self, offboarded_on: int) -> int:
        return offboarded_on + self.model["retention"]["after_offboarding_days"]
