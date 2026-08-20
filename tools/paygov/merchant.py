"""B25 — merchant profile and KYB metadata.

The batch brief contains the sentence this whole file is built around: the
platform manages business data **but does not replace a licensed verifier**.
So the first rule is a rule about honesty, not about data:
``MERCHANT_SELF_VERIFIED`` refuses any arrangement where our own record can say
"verified" without naming the licensed authority, its decision reference and an
expiry date. A status field a platform can set for itself is a status field that
means nothing in a dispute.

The rest are the things this domain gets wrong in practice:

* ``MERCHANT_DOC_NO_EXPIRY`` — KYB is a continuing state, not an event at
  signup. A licence can be revoked, an ID expires, and a bank account proof from
  three years ago proves nothing about today;
* ``MERCHANT_CHANGE_NO_REVERIFY`` — changing the payout account and changing the
  beneficial owner are the two steps of taking over a merchant. Both must
  re-open verification, and the first must hold settlement while it is open;
* ``MERCHANT_HIGH_RISK_SINGLE_APPROVER`` — onboarding a high-risk merchant is a
  commercial decision with a fraud loss attached; one person should not be able
  to make it alone;
* ``MERCHANT_SANCTIONS_AUTO`` — a sanctions hit may never be auto-approved, and
  auto-*rejection* is not the safe default either: name collisions are common
  enough that automatic rejection just moves the harm onto the innocent.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

MERCHANT = Path("governance/merchant-profile.json")
CURRENCY = Path("governance/currency-metadata.json")
AUTHZ = Path("governance/authorization.json")
AUDIT = Path("governance/audit-log.json")
TENANTS = Path("governance/tenant-registry.json")
DATA = Path("governance/data-architecture.json")

CODE = re.compile(r"^[a-z][a-z0-9_]*$")
REGION = re.compile(r"^[A-Z]{2}$")
RISK_ORDER = ["low", "medium", "high"]
SCREENING_LISTS = {"sanctions", "pep", "adverse_media"}
# The two changes that constitute a merchant takeover.
TAKEOVER_CHANGES = {"payout_account_change", "ubo_change"}
REGULATORY_RETENTION_DAYS = 1825


VALIDATOR = ("merchant-profile", "B25")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(MERCHANT)
    budget.check(where)
    try:
        model = load_json(root / MERCHANT)
    except Exception as exc:
        return [Problem("MERCHANT_UNREADABLE", where,
                        f"cannot read the merchant profile model: {exc}", "NN-14")]
    if not isinstance(model, dict):
        return [Problem("MERCHANT_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "MERCHANT_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "MERCHANT_PRINCIPLE", where,
                       "say what this platform is and is not allowed to claim", "NN-14")
    problems += _verification(model, where)
    documents, problems_ = _documents(model, where, budget)
    problems += problems_
    problems += _entity_kinds(model, where, documents, budget)
    problems += _ubo(model, where)
    problems += _screening(model, where)
    problems += _categories(model, where, budget)
    problems += _regions(model, root, where, budget)
    problems += _risk_levels(model, where, budget)
    problems += _changes(model, root, where, budget)
    problems += _retention(model, root, where, budget)
    problems += _appeal(model, where)
    problems += _audit_binding(model, root, where, budget)
    problems += _generated(root, budget)
    return problems


def _verification(model: dict, where: str) -> list[Problem]:
    verification = model.get("verification")
    if not isinstance(verification, dict):
        return [Problem("MERCHANT_SHAPE", where, "verification must be an object", "NN-14")]
    problems = list(expect(verification.get("platform_is_licensed_verifier") is False,
                           "MERCHANT_SELF_VERIFIED", where,
                           "this platform is not a licensed verifier and must not model itself "
                           "as one", "NN-14"))
    problems += expect(verification.get("authority_required") is True, "MERCHANT_SELF_VERIFIED",
                       where,
                       "a verification status must reference an external authority; a status a "
                       "platform can set for itself proves nothing in a dispute", "NN-14")
    fields = set(verification.get("authority_fields") or [])
    required = {"authority", "decision_reference", "decided_at", "valid_until"}
    problems += expect(required <= fields, "MERCHANT_AUTHORITY_INCOMPLETE", where,
                       f"the authority record is missing {sorted(required - fields)}; without a "
                       f"reference and an expiry it cannot be checked or re-checked", "NN-14")
    days = int(verification.get("max_validity_days") or 0)
    problems += expect(0 < days <= 1095, "MERCHANT_VERIFICATION_FOREVER", where,
                       f"a verification decision must expire, got {days} days", "NN-14")
    attestable = set(verification.get("self_attestation_allowed_for") or [])
    forbidden = {"legal_name", "ubo", "payout_account", "business_category", "country"}
    problems += expect(not (attestable & forbidden), "MERCHANT_SELF_ATTESTED_FACT", where,
                       f"self-attestation may not cover {sorted(attestable & forbidden)}; mixing "
                       f"'they told us' with 'it was verified' in one field is the standard way "
                       f"this gets faked", "NN-14")
    return problems


def _documents(model: dict, where: str, budget: Budget) -> tuple[dict, list[Problem]]:
    entries = model.get("documents")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("MERCHANT_SHAPE", where, "documents must be a non-empty list",
                            "NN-14")]
    problems: list[Problem] = []
    documents: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("MERCHANT_SHAPE", where, "each document must be an object",
                                    "NN-12"))
            continue
        did = str(entry.get("id") or "")
        scope = f"{where}#{did or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(CODE.match(did)), "MERCHANT_DOC_ID", scope,
                           f"document id '{did}' must be snake_case", "NN-12")
        problems += expect(did not in documents, "MERCHANT_DOC_DUPLICATE", scope,
                           f"document '{did}' is declared twice", "NN-12")
        problems += expect(len(str(entry.get("verifies") or "")) >= 4, "MERCHANT_DOC_PURPOSE",
                           scope,
                           "every document must say which claim it verifies; a document "
                           "collected 'because we always do' is data we cannot justify holding",
                           "NN-06")
        problems += expect(bool(entry.get("issuer")), "MERCHANT_DOC_ISSUER", scope,
                           "a document needs an issuer; who issued it decides how much it is "
                           "worth", "NN-14")
        problems += expect(isinstance(entry.get("contains_pii"), bool), "MERCHANT_DOC_PII_FLAG",
                           scope, "contains_pii must be an explicit boolean", "NN-06")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "MERCHANT_DOC_NOTES", scope,
                           "say why this document and this expiry", "NN-14")
        expires = int(entry.get("expires_days") or 0)
        problems += expect(0 < expires <= 1095, "MERCHANT_DOC_NO_EXPIRY", scope,
                           f"'{did}' must expire; KYB is a continuing state, not an event at "
                           f"signup", "NN-14")
        if did:
            documents[did] = entry

    proof = documents.get("bank_account_proof")
    if proof is not None:
        others = [int(d.get("expires_days") or 0) for did, d in documents.items()
                  if did != "bank_account_proof"]
        problems += expect(int(proof.get("expires_days") or 0) <= min(others or [10 ** 6]),
                           "MERCHANT_ACCOUNT_PROOF_STALE", where,
                           "the bank account proof must expire at least as fast as every other "
                           "document: it is the destination of the money and the first thing "
                           "changed after a takeover", "NN-14")
    return documents, problems


def _entity_kinds(model: dict, where: str, documents: dict, budget: Budget) -> list[Problem]:
    entries = model.get("entity_kinds")
    if not isinstance(entries, list) or not entries:
        return [Problem("MERCHANT_SHAPE", where, "entity_kinds must be a non-empty list",
                        "NN-14")]
    problems: list[Problem] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("MERCHANT_SHAPE", where, "each entity kind must be an object",
                                    "NN-12"))
            continue
        kid = str(entry.get("id") or "")
        scope = f"{where}#{kid}"
        budget.check(scope)
        problems += expect(kid not in seen, "MERCHANT_ENTITY_DUPLICATE", scope,
                           f"entity kind '{kid}' is declared twice", "NN-12")
        seen.add(kid)
        required = entry.get("required_documents")
        problems += expect(isinstance(required, list) and bool(required),
                           "MERCHANT_ENTITY_NO_DOCUMENTS", scope,
                           f"'{kid}' requires no documents at all", "NN-14")
        for did in required or []:
            problems += expect(did in documents, "MERCHANT_ENTITY_DOC_UNKNOWN", scope,
                               f"'{kid}' requires unknown document '{did}'", "NN-12")
        problems += expect("bank_account_proof" in (required or []),
                           "MERCHANT_ENTITY_NO_ACCOUNT_PROOF", scope,
                           f"'{kid}' does not require proof that the payout account belongs to "
                           f"it", "NN-14")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "MERCHANT_ENTITY_NOTES",
                           scope, "say what this entity kind changes", "NN-14")
    company = next((e for e in entries if isinstance(e, dict) and e.get("id") == "company"), None)
    if company is not None:
        problems += expect("ubo_declaration" in (company.get("required_documents") or []),
                           "MERCHANT_COMPANY_NO_UBO", where,
                           "a company must declare its beneficial owners", "NN-14")
    return problems


def _ubo(model: dict, where: str) -> list[Problem]:
    ubo = model.get("ubo")
    if not isinstance(ubo, dict):
        return [Problem("MERCHANT_SHAPE", where, "ubo must be an object", "NN-14")]
    threshold = float(ubo.get("ownership_threshold_percent") or 0)
    problems = list(expect(0 < threshold <= 25, "MERCHANT_UBO_THRESHOLD", where,
                           f"the beneficial-owner threshold must be at most 25%, got "
                           f"{threshold}%", "NN-14"))
    depth = int(ubo.get("max_ownership_depth") or 0)
    problems += expect(depth >= 3, "MERCHANT_UBO_DEPTH", where,
                       f"ownership must be traced at least three layers, got {depth}; looking "
                       f"only at the first shareholder lets anyone hide behind one shell",
                       "NN-14")
    problems += expect(ubo.get("requires_identity_document") is True, "MERCHANT_UBO_NO_ID", where,
                       "a declared beneficial owner must be identified", "NN-14")
    problems += expect(ubo.get("screening_required") is True, "MERCHANT_UBO_NO_SCREENING", where,
                       "beneficial owners must be screened", "NN-14")
    return problems


def _screening(model: dict, where: str) -> list[Problem]:
    screening = model.get("screening")
    if not isinstance(screening, dict):
        return [Problem("MERCHANT_SHAPE", where, "screening must be an object", "NN-14")]
    lists = set(screening.get("lists") or [])
    problems = list(expect(SCREENING_LISTS <= lists, "MERCHANT_SCREENING_INCOMPLETE", where,
                           f"screening must cover {sorted(SCREENING_LISTS - lists)}", "NN-14"))
    interval = int(screening.get("rescreen_interval_days") or 0)
    problems += expect(0 < interval <= 365, "MERCHANT_SCREENING_ONCE", where,
                       f"screening must repeat; a list checked only at signup is a list checked "
                       f"before the merchant did anything, got {interval} days", "NN-14")
    problems += expect(screening.get("auto_approve_on_hit") is False, "MERCHANT_SANCTIONS_AUTO",
                       where, "a screening hit may never be auto-approved", "NN-14")
    problems += expect(screening.get("hit_requires_human_review") is True,
                       "MERCHANT_SANCTIONS_AUTO", where,
                       "a screening hit must go to a human: automatic rejection is not the safe "
                       "default either, because name collisions are common and the harm lands on "
                       "the innocent", "NN-14")
    return problems


def _categories(model: dict, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("business_categories")
    if not isinstance(entries, list) or not entries:
        return [Problem("MERCHANT_SHAPE", where, "business_categories must be a non-empty list",
                        "NN-14")]
    problems: list[Problem] = []
    seen: set[str] = set()
    prohibited = 0
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("MERCHANT_SHAPE", where, "each category must be an object",
                                    "NN-12"))
            continue
        code = str(entry.get("code") or "")
        scope = f"{where}#{code}"
        budget.check(scope)
        problems += expect(bool(CODE.match(code)), "MERCHANT_CATEGORY_CODE", scope,
                           f"category code '{code}' must be snake_case", "NN-12")
        problems += expect(code not in seen, "MERCHANT_CATEGORY_DUPLICATE", scope,
                           f"category '{code}' is declared twice", "NN-12")
        seen.add(code)
        risk = entry.get("risk")
        problems += expect(risk in set(RISK_ORDER) | {"prohibited"}, "MERCHANT_CATEGORY_RISK",
                           scope, f"risk must be one of {RISK_ORDER + ['prohibited']}", "NN-14")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "MERCHANT_CATEGORY_NOTES",
                           scope, "say why this category sits where it does", "NN-14")
        if risk == "prohibited":
            prohibited += 1
            problems += expect(entry.get("allowed") is False,
                               "MERCHANT_PROHIBITED_CATEGORY_ALLOWED", scope,
                               f"'{code}' is marked prohibited but still allowed", "NN-14")
    problems += expect(prohibited > 0, "MERCHANT_NO_PROHIBITED_LIST", where,
                       "a platform that prohibits no category has not decided what it will not "
                       "process, and will discover it during an incident", "NN-14")
    return problems


def _regions(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("operating_regions")
    if not isinstance(entries, list) or not entries:
        return [Problem("MERCHANT_SHAPE", where, "operating_regions must be a non-empty list",
                        "NN-14")]
    budget.check(str(CURRENCY))
    try:
        currency = load_json(root / CURRENCY)
        known = {str(c.get("code")) for c in (currency.get("currencies") or [])
                 if isinstance(c, dict)}
    except Exception:
        known = set()
    problems: list[Problem] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("MERCHANT_SHAPE", where, "each region must be an object",
                                    "NN-12"))
            continue
        code = str(entry.get("code") or "")
        scope = f"{where}#{code}"
        budget.check(scope)
        problems += expect(bool(REGION.match(code)), "MERCHANT_REGION_CODE", scope,
                           f"region code '{code}' must be a two-letter uppercase code", "NN-12")
        problems += expect(code not in seen, "MERCHANT_REGION_DUPLICATE", scope,
                           f"region '{code}' is declared twice", "NN-12")
        seen.add(code)
        currencies = entry.get("settlement_currencies")
        problems += expect(isinstance(currencies, list) and bool(currencies),
                           "MERCHANT_REGION_NO_CURRENCY", scope,
                           f"'{code}' has no settlement currency", "NN-05")
        for item in currencies or []:
            problems += expect(item in known, "MERCHANT_CURRENCY_UNKNOWN", scope,
                               f"settlement currency '{item}' is not in the versioned currency "
                               f"metadata; an unknown currency has no minor-unit exponent and "
                               f"therefore no defined amount", "NN-05")
        problems += expect(isinstance(entry.get("requires_local_entity"), bool),
                           "MERCHANT_REGION_ENTITY_RULE", scope,
                           "say explicitly whether a local entity is required", "NN-14")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "MERCHANT_REGION_NOTES",
                           scope, "say what is special about this region", "NN-14")
    return problems


def _risk_levels(model: dict, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("risk_levels")
    if not isinstance(entries, list) or not entries:
        return [Problem("MERCHANT_SHAPE", where, "risk_levels must be a non-empty list",
                        "NN-14")]
    problems: list[Problem] = []
    by_id: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("MERCHANT_SHAPE", where, "each risk level must be an object",
                                    "NN-12"))
            continue
        rid = str(entry.get("id") or "")
        scope = f"{where}#{rid}"
        budget.check(scope)
        problems += expect(rid in RISK_ORDER, "MERCHANT_RISK_LEVEL", scope,
                           f"risk level must be one of {RISK_ORDER}", "NN-14")
        for field in ("daily_limit_minor", "single_limit_minor"):
            value = entry.get(field)
            problems += expect(isinstance(value, int) and value > 0, "MERCHANT_RISK_NO_LIMIT",
                               scope, f"'{rid}' needs a positive integer {field} in minor units",
                               "NN-05")
        problems += expect(int(entry.get("settlement_delay_days") or -1) >= 0,
                           "MERCHANT_RISK_NO_DELAY", scope,
                           f"'{rid}' needs a settlement delay", "NN-14")
        approvers = int(entry.get("approvers_required") or 0)
        problems += expect(approvers >= 1, "MERCHANT_RISK_NO_APPROVER", scope,
                           f"'{rid}' needs at least one approver", "NN-03")
        if rid == "high":
            problems += expect(approvers >= 2, "MERCHANT_HIGH_RISK_SINGLE_APPROVER", scope,
                               "onboarding a high-risk merchant is a commercial decision with a "
                               "fraud loss attached; one person must not make it alone", "NN-03")
        problems += expect(len(str(entry.get("notes") or "")) >= 4, "MERCHANT_RISK_NOTES", scope,
                           "say what this level changes", "NN-14")
        if rid:
            by_id[rid] = entry

    present = [r for r in RISK_ORDER if r in by_id]
    for lower, higher in zip(present, present[1:]):
        problems += expect(int(by_id[lower].get("daily_limit_minor") or 0)
                           >= int(by_id[higher].get("daily_limit_minor") or 0),
                           "MERCHANT_RISK_LIMITS_INVERTED", where,
                           f"'{higher}' risk allows more per day than '{lower}'", "NN-14")
        problems += expect(int(by_id[lower].get("settlement_delay_days") or 0)
                           <= int(by_id[higher].get("settlement_delay_days") or 0),
                           "MERCHANT_RISK_DELAY_INVERTED", where,
                           f"'{higher}' risk settles sooner than '{lower}'", "NN-14")
    for level in RISK_ORDER:
        problems += expect(level in by_id, "MERCHANT_RISK_LEVEL", where,
                           f"risk level '{level}' is not defined", "NN-14")
    return problems


def _changes(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    entries = model.get("material_changes")
    if not isinstance(entries, list) or not entries:
        return [Problem("MERCHANT_NO_CHANGE_TRIGGERS", where,
                        "without material-change triggers, verification is a one-off event and "
                        "a merchant takeover never re-opens it", "NN-14")]
    budget.check(str(AUTHZ))
    try:
        authz = load_json(root / AUTHZ)
        permissions = {str(p.get("id")): p for p in (authz.get("permissions") or [])
                       if isinstance(p, dict)}
    except Exception:
        permissions = {}
    problems: list[Problem] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("MERCHANT_SHAPE", where, "each change must be an object",
                                    "NN-12"))
            continue
        cid = str(entry.get("id") or "")
        scope = f"{where}#{cid}"
        budget.check(scope)
        problems += expect(cid not in seen, "MERCHANT_CHANGE_DUPLICATE", scope,
                           f"change '{cid}' is declared twice", "NN-12")
        seen.add(cid)
        problems += expect(entry.get("requires_reverification") is True,
                           "MERCHANT_CHANGE_NO_REVERIFY", scope,
                           f"'{cid}' is a material change and must re-open verification",
                           "NN-14")
        permission = str(entry.get("permission") or "")
        problems += expect(permission in permissions, "MERCHANT_CHANGE_PERMISSION_UNKNOWN", scope,
                           f"'{cid}' is guarded by unknown permission '{permission}'", "NN-12")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "MERCHANT_CHANGE_NOTES",
                           scope, "say why this change matters", "NN-14")
        if cid == "payout_account_change":
            problems += expect(entry.get("holds_settlement") is True,
                               "MERCHANT_ACCOUNT_CHANGE_NO_HOLD", scope,
                               "changing the payout account must hold settlement until "
                               "verification passes; otherwise the first payout after a takeover "
                               "goes to the attacker", "NN-01")
            entry_permission = permissions.get(permission) or {}
            problems += expect(entry_permission.get("dual_control") is True,
                               "MERCHANT_ACCOUNT_CHANGE_SINGLE_PERSON", scope,
                               f"'{permission}' must be dual control in B19", "NN-03")
    for change in sorted(TAKEOVER_CHANGES):
        problems += expect(change in seen, "MERCHANT_CHANGE_MISSING", where,
                           f"'{change}' is one of the two steps of a merchant takeover and has "
                           f"no trigger here", "NN-14")
    return problems


def _retention(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    retention = model.get("retention")
    if not isinstance(retention, dict):
        return [Problem("MERCHANT_SHAPE", where, "retention must be an object", "NN-06")]
    days = int(retention.get("after_offboarding_days") or 0)
    problems = list(expect(days >= REGULATORY_RETENTION_DAYS, "MERCHANT_RETENTION_SHORT", where,
                           f"KYB records must survive offboarding for at least "
                           f"{REGULATORY_RETENTION_DAYS} days, got {days}", "NN-13"))
    problems += expect(retention.get("documents_encrypted") is True, "MERCHANT_DOCS_PLAINTEXT",
                       where, "KYB documents must be stored encrypted", "NN-04")
    problems += expect(retention.get("minimise_to_declared_purpose") is True,
                       "MERCHANT_NO_MINIMISATION", where,
                       "collection must be limited to the declared purpose", "NN-06")

    budget.check(str(DATA))
    try:
        data = load_json(root / DATA)
        floors = [int((t.get("retention") or {}).get("cold_days") or 0)
                  for t in (data.get("tables") or []) if isinstance(t, dict)]
    except Exception:
        floors = []
    if floors:
        problems += expect(days <= max(floors), "MERCHANT_RETENTION_BEYOND_DATA", where,
                           f"KYB retention ({days} days) exceeds the longest retention the data "
                           f"model defines ({max(floors)}); data kept beyond its declared "
                           f"lifetime is data nobody planned to protect", "NN-06")

    budget.check(str(TENANTS))
    try:
        tenants = load_json(root / TENANTS)
        offboarding = tenants.get("offboarding") or {}
    except Exception:
        offboarding = {}
    problems += expect(offboarding.get("kek_destruction_required") is True,
                       "MERCHANT_RETENTION_UNSHREDDABLE", where,
                       "B24 must still destroy the tenant key at closure; KYB retention is a "
                       "reason to keep records, not a reason to keep them readable", "NN-06")
    return problems


def _appeal(model: dict, where: str) -> list[Problem]:
    appeal = model.get("appeal")
    if not isinstance(appeal, dict):
        return [Problem("MERCHANT_NO_APPEAL", where,
                        "a rejection that cannot be appealed is not defensible commercially or "
                        "to a regulator", "NN-15")]
    problems = list(expect(appeal.get("available") is True, "MERCHANT_NO_APPEAL", where,
                           "an appeal path must exist", "NN-15"))
    problems += expect(appeal.get("decision_must_state_reasons") is True,
                       "MERCHANT_DECISION_UNEXPLAINED", where,
                       "a decision must state its reasons; an unexplained rejection cannot be "
                       "appealed even in principle", "NN-15")
    problems += expect(appeal.get("reviewer_must_differ_from_decider") is True,
                       "MERCHANT_APPEAL_SELF_REVIEW", where,
                       "the appeal reviewer must not be the original decider", "NN-03")
    days = int(appeal.get("response_days") or 0)
    problems += expect(0 < days <= 60, "MERCHANT_APPEAL_UNBOUNDED", where,
                       f"an appeal needs a bounded response time, got {days} days", "NN-15")
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
    return list(expect(event_class in classes, "MERCHANT_AUDIT_CLASS_UNKNOWN", where,
                       f"profile decisions are recorded as '{event_class}', which "
                       f"governance/audit-log.json does not define", "NN-13"))


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .merchantgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("MERCHANT_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("MERCHANT_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/merchant-profile.json "
                                    f"but does not exist; run scripts/render-merchant.py",
                                    "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("MERCHANT_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the model generates", "NN-12"))
    return problems
