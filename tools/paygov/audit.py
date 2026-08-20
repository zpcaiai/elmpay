"""B23 — non-repudiation: tamper-evident audit logging.

An audit log's worth is not that it recorded something, it is that **nobody can
change it afterwards**. A record that can be edited is, in a dispute, the same
as no record at all.

Three layers, and each has a rule here because each is quietly droppable:

* ``AUDIT_NO_CHAIN`` — hashing each record over its sequence number and its
  predecessor's hash is what makes an edit, a deletion or a reordering visible;
* ``AUDIT_NO_ANCHOR`` — a hash chain **cannot detect its own tail being cut
  off**. Remove the last N records and the remainder still verifies perfectly.
  Only an external, signed checkpoint closes that hole, and the anchoring
  interval is exactly the size of the window that stays deniable;
* ``AUDIT_NO_SHREDDING`` — without payload-level crypto-shredding, "immutable"
  and "erase my personal data" are contradictory requirements, and the one that
  loses is always immutability.

The cross-checks bind this to the batches it depends on: every dual-control
money action B19 defines must be audited, the anchor signing key must exist in
B20, and the reader role must be the non-elevatable auditor B19 declares.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

AUDIT = Path("governance/audit-log.json")
AUTHZ = Path("governance/authorization.json")
KEYS = Path("governance/key-management.json")
DATA = Path("governance/data-architecture.json")

CLASS_ID = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")
STRONG_HASHES = {"SHA-256", "SHA-384", "SHA-512", "BLAKE2b"}
# Five Ws plus the two fields that make a decision explainable a year later.
MINIMUM_FIELDS = {"event_id", "occurred_at", "tenant_id", "actor", "action", "decision",
                  "rule_version"}
NEVER_LOGGED = {"card_pan", "card_cvv", "password", "authorization_header"}


VALIDATOR = ("audit-log", "B23")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(AUDIT)
    budget.check(where)
    try:
        model = load_json(root / AUDIT)
    except Exception as exc:
        return [Problem("AUDIT_UNREADABLE", where, f"cannot read the audit policy: {exc}",
                        "NN-13")]
    if not isinstance(model, dict):
        return [Problem("AUDIT_SHAPE", where, "the audit policy must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "AUDIT_VERSION_FIELD", where, "schema_version must be semver",
                           "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "AUDIT_PRINCIPLE", where,
                       "say what makes this log worth anything in a dispute", "NN-13")
    problems += _chain(model, where)
    problems += _anchoring(model, root, where, budget)
    problems += _records(model, where)
    classes, problems_ = _event_classes(model, where, budget)
    problems += problems_
    problems += _storage(model, where)
    problems += _redaction(model, where, classes)
    problems += _clock(model, where)
    problems += _access(model, root, where, budget)
    problems += _verification(model, where)
    problems += _audited_actions(model, root, where, budget)
    problems += _retention(model, root, where, classes, budget)
    problems += _generated(root, budget)
    return problems


def _chain(model: dict, where: str) -> list[Problem]:
    chain = model.get("hash_chain")
    if not isinstance(chain, dict):
        return [Problem("AUDIT_NO_CHAIN", where,
                        "there is no hash chain; an audit log without one is a table somebody "
                        "can UPDATE", "NN-13")]
    problems = list(expect(chain.get("algorithm") in STRONG_HASHES, "AUDIT_WEAK_HASH", where,
                           f"the chain hash must be one of {sorted(STRONG_HASHES)}", "NN-07"))
    problems += expect(chain.get("includes_previous_hash") is True, "AUDIT_NO_CHAIN", where,
                       "each record must hash its predecessor, or the records are merely a list",
                       "NN-13")
    problems += expect(chain.get("includes_sequence") is True, "AUDIT_NO_SEQUENCE", where,
                       "each record must hash its sequence number, otherwise a deletion leaves "
                       "no hole to find", "NN-13")
    problems += expect(chain.get("per_tenant_chain") is True, "AUDIT_SHARED_CHAIN", where,
                       "chains must be per tenant; one global chain leaks the volume and timing "
                       "of every tenant's activity to anyone who may verify it", "NN-06")
    problems += expect(bool(chain.get("canonical_serialisation")), "AUDIT_NO_CANONICAL_FORM",
                       where,
                       "a canonical serialisation is required; the same record serialised two "
                       "ways has two hashes, and then the chain proves nothing", "NN-13")
    return problems


def _anchoring(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    anchoring = model.get("anchoring")
    if not isinstance(anchoring, dict):
        return [Problem("AUDIT_NO_ANCHOR", where,
                        "there is no anchoring policy; a hash chain cannot detect its own tail "
                        "being cut off", "NN-13")]
    problems = list(expect(anchoring.get("required") is True, "AUDIT_NO_ANCHOR", where,
                           "anchoring must be required", "NN-13"))
    minutes = int(anchoring.get("interval_minutes") or 0)
    problems += expect(0 < minutes <= 1440, "AUDIT_ANCHOR_INTERVAL", where,
                       f"the anchoring interval is the size of the window in which records can "
                       f"still be denied; {minutes} minutes is not a bounded window", "NN-13")
    problems += expect(bool(anchoring.get("witness")), "AUDIT_NO_WITNESS", where,
                       "an anchor nobody else holds is a promise we make to ourselves", "NN-13")
    problems += expect(int(anchoring.get("anchor_retention_days") or 0) >= 365,
                       "AUDIT_ANCHOR_RETENTION", where,
                       "anchors must outlive the records they cover", "NN-13")

    key_id = str(anchoring.get("signed_by_key") or "")
    problems += expect(bool(key_id), "AUDIT_ANCHOR_UNSIGNED", where,
                       "anchors must be signed, or anyone can publish one", "NN-07")
    budget.check(str(KEYS))
    try:
        keys = load_json(root / KEYS)
        known = {str(k.get("id")) for k in (keys.get("keys") or []) if isinstance(k, dict)}
    except Exception:
        known = set()
    problems += expect(key_id in known, "AUDIT_ANCHOR_KEY_UNMANAGED", where,
                       f"the anchor signing key '{key_id}' is not managed in "
                       f"governance/key-management.json", "NN-07")
    return problems


def _records(model: dict, where: str) -> list[Problem]:
    records = model.get("records")
    if not isinstance(records, dict):
        return [Problem("AUDIT_SHAPE", where, "records must be an object", "NN-13")]
    required = set(records.get("required_fields") or [])
    problems = list(expect(MINIMUM_FIELDS <= required, "AUDIT_MISSING_FIELD", where,
                           f"required fields are missing {sorted(MINIMUM_FIELDS - required)}; "
                           f"without the rule version, 'why was this allowed at the time' is "
                           f"unanswerable", "NN-13"))
    forbidden = set(records.get("forbidden_fields") or [])
    problems += expect(NEVER_LOGGED <= forbidden, "AUDIT_FORBIDDEN_FIELD", where,
                       f"the audit log must forbid {sorted(NEVER_LOGGED - forbidden)}; an "
                       f"immutable log is the worst possible place to put a card number",
                       "NN-04")
    problems += expect(records.get("records_denials") is True, "AUDIT_NO_DENIALS", where,
                       "denials must be recorded; the refused attempts are the signal", "NN-13")
    problems += expect(records.get("actor_must_be_resolvable") is True, "AUDIT_ANONYMOUS_ACTOR",
                       where, "every record must name a resolvable actor; 'system' is not a "
                              "person and cannot be asked what happened", "NN-13")
    return problems


def _event_classes(model: dict, where: str, budget: Budget) -> tuple[dict, list[Problem]]:
    problems: list[Problem] = []
    classes: dict[str, dict] = {}
    entries = model.get("event_classes")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("AUDIT_SHAPE", where, "event_classes must be a non-empty list",
                            "NN-13")]
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("AUDIT_SHAPE", where, "each event class must be an object",
                                    "NN-12"))
            continue
        cid = str(entry.get("id") or "")
        scope = f"{where}#{cid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(CLASS_ID.match(cid)), "AUDIT_CLASS_ID", scope,
                           f"event class '{cid}' must look like 'domain.event'", "NN-12")
        problems += expect(cid not in classes, "AUDIT_CLASS_DUPLICATE", scope,
                           f"event class '{cid}' is declared twice", "NN-12")
        problems += expect(bool(entry.get("source")), "AUDIT_CLASS_SOURCE", scope,
                           "an event class needs the system that produces it", "NN-13")
        problems += expect(isinstance(entry.get("contains_pii"), bool), "AUDIT_PII_FLAG", scope,
                           "contains_pii must be an explicit boolean; it decides whether the "
                           "payload needs to be shreddable", "NN-06")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "AUDIT_CLASS_NOTES", scope,
                           "say what this class covers", "NN-13")
        days = int(entry.get("retention_days") or 0)
        problems += expect(days >= 365, "AUDIT_RETENTION_SHORT", scope,
                           f"'{cid}' keeps records for {days} days; a dispute rarely arrives "
                           f"within the first year", "NN-13")
        if cid:
            classes[cid] = entry
    return classes, problems


def _storage(model: dict, where: str) -> list[Problem]:
    storage = model.get("storage")
    if not isinstance(storage, dict):
        return [Problem("AUDIT_SHAPE", where, "storage must be an object", "NN-13")]
    problems = list(expect(storage.get("append_only") is True, "AUDIT_MUTABLE_STORAGE", where,
                           "storage must be append-only", "NN-13"))
    problems += expect(storage.get("worm_backend") is True, "AUDIT_NO_WORM", where,
                       "the backing store must be write-once; a hash chain on mutable storage "
                       "detects tampering but does not prevent it", "NN-13")
    problems += expect(storage.get("separate_credentials_from_application") is True,
                       "AUDIT_SHARED_CREDENTIALS", where,
                       "the application's credentials must not be able to delete audit records; "
                       "whoever can delete the log must not be the party the log is about",
                       "NN-03")
    problems += expect(storage.get("delete_requires_key_destruction") is True,
                       "AUDIT_DELETABLE", where,
                       "deletion must go through key destruction rather than DELETE", "NN-06")
    return problems


def _redaction(model: dict, where: str, classes: dict) -> list[Problem]:
    redaction = model.get("redaction")
    if not isinstance(redaction, dict):
        return [Problem("AUDIT_SHAPE", where, "redaction must be an object", "NN-06")]
    pii_classes = [cid for cid, entry in classes.items() if entry.get("contains_pii")]
    problems = list(expect(redaction.get("payload_crypto_shredding") is True,
                           "AUDIT_NO_SHREDDING", where,
                           "payloads must be crypto-shreddable; without it 'immutable' and "
                           "'erase my data' cannot both be satisfied, and immutability is the "
                           "one that gets dropped", "NN-06"))
    problems += expect(redaction.get("content_hash_retained") is True, "AUDIT_SHRED_LOSES_PROOF",
                       where,
                       "the content hash must survive shredding, or erasing the payload also "
                       "erases the proof that the record was never altered", "NN-13")
    problems += expect(redaction.get("shredding_preserves_chain") is True,
                       "AUDIT_SHRED_BREAKS_CHAIN", where,
                       "shredding must not break the chain", "NN-13")
    problems += expect(not pii_classes or redaction.get("payload_crypto_shredding") is True,
                       "AUDIT_PII_UNSHREDDABLE", where,
                       f"classes {sorted(pii_classes)} carry personal data but the policy has no "
                       f"way to erase it", "NN-06")
    return problems


def _clock(model: dict, where: str) -> list[Problem]:
    clock = model.get("clock")
    if not isinstance(clock, dict):
        return [Problem("AUDIT_SHAPE", where, "clock must be an object", "NN-13")]
    problems = list(expect(bool(clock.get("source")), "AUDIT_CLOCK_SOURCE", where,
                           "the time source must be named", "NN-13"))
    skew = int(clock.get("max_skew_seconds") or 0)
    problems += expect(0 < skew <= 300, "AUDIT_CLOCK_SKEW", where,
                       f"a bounded clock skew is required, got {skew}s", "NN-13")
    problems += expect(clock.get("monotonic_sequence_required") is True, "AUDIT_NO_SEQUENCE",
                       where,
                       "sequence numbers must be monotonic; order must not depend on a clock "
                       "that can move backwards", "NN-13")
    return problems


def _access(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    access = model.get("access")
    if not isinstance(access, dict):
        return [Problem("AUDIT_SHAPE", where, "access must be an object", "NN-03")]
    reader = str(access.get("reader_role") or "")
    problems = list(expect(access.get("reader_cannot_write") is True, "AUDIT_READER_WRITES",
                           where, "the audit reader must not be able to write", "NN-03"))
    problems += expect(access.get("reader_cannot_be_elevated") is True, "AUDIT_READER_ELEVATABLE",
                       where,
                       "the audit reader must not be elevatable; an auditor who can change what "
                       "they audit is not an auditor", "NN-03")
    problems += expect(access.get("access_is_itself_audited") is True, "AUDIT_ACCESS_UNLOGGED",
                       where, "reading the audit log must itself be audited", "NN-13")

    budget.check(str(AUTHZ))
    try:
        authz = load_json(root / AUTHZ)
        roles = {str(r.get("id")): r for r in (authz.get("roles") or []) if isinstance(r, dict)}
        non_elevatable = set((authz.get("elevation") or {}).get("non_elevatable_roles") or [])
    except Exception:
        roles, non_elevatable = {}, set()
    problems += expect(reader in roles, "AUDIT_READER_UNKNOWN", where,
                       f"the audit reader role '{reader}' is not a role B19 defines", "NN-12")
    problems += expect(reader in non_elevatable, "AUDIT_READER_ELEVATABLE", where,
                       f"'{reader}' is not in B19's non-elevatable roles, so the reader can be "
                       f"elevated into someone who writes", "NN-03")
    return problems


def _verification(model: dict, where: str) -> list[Problem]:
    verification = model.get("verification")
    if not isinstance(verification, dict):
        return [Problem("AUDIT_SHAPE", where, "verification must be an object", "NN-13")]
    problems = list(expect(verification.get("rehearsed") is True, "AUDIT_UNREHEARSED", where,
                           "chain verification must be rehearsed; a verifier nobody has run is "
                           "a verifier nobody can trust on the day it matters", "NN-13"))
    interval = int(verification.get("rehearsal_interval_days") or 0)
    problems += expect(0 < interval <= 365, "AUDIT_REHEARSAL_INTERVAL", where,
                       f"verification must be rehearsed at least yearly, got {interval} days",
                       "NN-13")
    problems += expect(verification.get("independent_verifier") is True,
                       "AUDIT_NO_INDEPENDENT_VERIFIER", where,
                       "the verifier must be runnable by an independent party; a chain only we "
                       "can check convinces nobody in a dispute", "NN-13")
    return problems


def _audited_actions(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    """Every action B19 says needs two people must leave a record."""
    problems: list[Problem] = []
    audited = set(model.get("audited_actions") or [])
    budget.check(str(AUTHZ))
    try:
        authz = load_json(root / AUTHZ)
        permissions = [p for p in (authz.get("permissions") or []) if isinstance(p, dict)]
    except Exception:
        permissions = []
    for permission in permissions:
        pid = str(permission.get("id"))
        if permission.get("dual_control") is True or permission.get("elevation_required") is True:
            problems += expect(pid in audited, "AUDIT_ACTION_UNLOGGED", where,
                               f"'{pid}' requires two people or an elevation but is not in "
                               f"audited_actions; the actions worth arguing about later are "
                               f"exactly these", "NN-13")
    known = {str(p.get("id")) for p in permissions}
    if known:
        for action in sorted(audited):
            problems += expect(action in known, "AUDIT_ACTION_UNKNOWN", where,
                               f"audited action '{action}' is not a permission B19 defines",
                               "NN-12")
    return problems


def _retention(model: dict, root: Path, where: str, classes: dict,
               budget: Budget) -> list[Problem]:
    """Audit retention must not undercut the data model's own floor."""
    problems: list[Problem] = []
    budget.check(str(DATA))
    try:
        data = load_json(root / DATA)
    except Exception:
        return problems
    floors = [int((t.get("retention") or {}).get("cold_days") or 0)
              for t in (data.get("tables") or [])
              if isinstance(t, dict) and t.get("mutability") == "append_only"]
    if not floors:
        return problems
    longest = max(floors)
    money = classes.get("money.movement") or {}
    problems += expect(int(money.get("retention_days") or 0) >= longest,
                       "AUDIT_RETENTION_BELOW_DATA", where,
                       f"money movement audit records are kept {money.get('retention_days')} "
                       f"days but append-only data is kept up to {longest}; the record of who "
                       f"did it must outlive the thing they did", "NN-13")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .auditgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("AUDIT_GENERATED", rel, f"cannot generate {rel}: {exc}",
                                    "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("AUDIT_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/audit-log.json but does "
                                    f"not exist; run scripts/render-audit.py", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("AUDIT_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the audit policy generates",
                                    "NN-12"))
    return problems
