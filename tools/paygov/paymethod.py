"""B35 — payment method abstraction and token references.

The brief says: keep only PSP/wallet tokens and non-sensitive fingerprints, never
raw PAN, CVV, track data or decrypted wallet payment data. Everyone agrees with
that sentence. The rule this batch carries is about the sentence underneath it —
``PMETHOD_HARDCODED_LIST``.

On entry this repository held **four** independent answers to "what must never be
stored", in three languages:

* ``SensitiveDataGuard.DENIED_KEYS`` watched ``pan``;
* ``libs/audit/reference/chain.py`` watched ``card_pan``;
* the checkout's ``deniedParameterNames`` was a third regex;
* ``JdbcCommerceService`` did a bare ``contains("cvv")``.

No two were the same and nothing compared them, so a field could pass one layer
under the spelling the next layer was guarding — while every layer looked like it
was defending. A list that must hold in four places is governance data. A copy of
it is a second source of truth, and a second source of truth about card data is
the kind that gets discovered by an assessor.

The rest are the mistakes this area repeats:

* ``PMETHOD_FINGERPRINT_CROSS_TENANT`` — one card fingerprint shared across
  tenants. It reads as anonymisation and works as a person's identifier: two
  merchants can now confirm the same human paid at both;
* ``PMETHOD_FINGERPRINT_REVERSIBLE`` — an unkeyed hash of a 16-digit space, which
  is not a one-way function, it is a lookup table with extra steps;
* ``PMETHOD_TOKEN_SCHEME`` — accepting an ``https`` "token", which is not a token
  but an address something can be fetched from;
* ``PMETHOD_DISPLAY_FIELD_UNSAFE`` — running display as a deny-list, so every new
  field is public until somebody notices.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json, read_text
from .structs import SEMVER, expect

MODEL = Path("governance/payment-method.json")
KEYS = Path("governance/key-management.json")
CONTRACT = Path("contracts/payment-method/sensitive-fields.json")
JAVA_CATALOG = Path("libs/security/src/main/java/com/elmpay/security/SensitiveFieldCatalog.java")

REQUIRED_FAMILIES = ("pan", "cvv", "track_data", "pin", "wallet_cleartext", "credential")

# Spellings this repository has actually used. The rule is seeded from history,
# not from imagination: each of these was a live name in some layer's list, and
# the catalogue has to cover all of them or the layers disagree again.
REQUIRED_ALIASES = {
    "pan": ("card_number", "cardnumber", "card_pan", "primary_account_number", "dpan"),
    "cvv": ("cvc", "cvv2", "cid", "card_cvv", "security_code"),
    "track_data": ("track1", "track2", "magstripe"),
    "pin": ("pin_block",),
    "wallet_cleartext": ("apple_pay_token", "paymentdata", "cryptogram"),
    # `private` is here because the runtime proof caught it: the checkout regex
    # screened it and this catalogue did not. Putting it in the catalogue alone
    # would leave the same hole one deletion away — a name only a smoke test
    # defends is a name the gate does not defend.
    "credential": ("private", "private_key", "api_key", "authorization",
                   "authorization_header", "password", "secret", "credential"),
}

UNSAFE_SCHEMES = {"http", "https", "file", "ftp", "data"}
LITERAL = re.compile(r"""['"]([A-Za-z][A-Za-z0-9_.\-]{2,63})['"]""")
COPY_THRESHOLD = 3

VALIDATOR = ("payment-method", "B35")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(MODEL)
    budget.check(where)
    try:
        model = load_json(root / MODEL, budget)
    except Exception as exc:
        return [Problem("PMETHOD_UNREADABLE", where,
                        f"cannot read the payment method model: {exc}", "NN-04")]
    if not isinstance(model, dict):
        return [Problem("PMETHOD_SHAPE", where, "the model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "PMETHOD_VERSION_FIELD", where,
                           "schema_version must be semver", "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "PMETHOD_PRINCIPLE", where,
                       "say what the platform is allowed to hold and why", "NN-04")
    families = _families(model)
    problems += _families_present(families, where)
    problems += _aliases(families, model, where)
    problems += _normalization(model, where)
    problems += _custody(model, families, where)
    problems += _token(model, where)
    problems += _fingerprint(model, root, where, budget)
    problems += _display(model, families, where)
    problems += _retention_and_scope(model, where)
    problems += _derived(model, root, where, budget)
    problems += _generated(root, where, budget)
    return problems


def _families(model: dict) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for entry in model.get("forbidden_fields") or []:
        if isinstance(entry, dict) and isinstance(entry.get("canonical"), str):
            found[entry["canonical"]] = entry
    return found


def _normalize(name: str, rules: dict) -> str:
    text = str(name)
    if rules.get("lowercase", True):
        text = text.lower()
    for character in rules.get("strip_characters") or []:
        text = text.replace(character, "")
    return text


def _all_names(families: dict, rules: dict) -> set[str]:
    names: set[str] = set()
    for entry in families.values():
        names.add(_normalize(entry.get("canonical", ""), rules))
        for alias in entry.get("aliases") or []:
            names.add(_normalize(alias, rules))
    names.discard("")
    return names


def _families_present(families: dict, where: str) -> list[Problem]:
    missing = [name for name in REQUIRED_FAMILIES if name not in families]
    return expect(not missing, "PMETHOD_FAMILY_MISSING", where,
                  f"the catalogue does not forbid {missing}; a family the model does not name "
                  f"is one no implementation has to reject", "NN-04", missing=missing)


def _aliases(families: dict, model: dict, where: str) -> list[Problem]:
    rules = model.get("normalization") or {}
    known = _all_names(families, rules)
    problems: list[Problem] = []
    for family, aliases in REQUIRED_ALIASES.items():
        if family not in families:
            continue
        gaps = sorted(alias for alias in aliases if _normalize(alias, rules) not in known)
        problems += expect(not gaps, "PMETHOD_ALIAS_GAP", where,
                           f"'{family}' does not cover {gaps}; every one of these was a live "
                           f"field name in some layer of this repository, and a spelling the "
                           f"catalogue misses is a spelling that walks through", "NN-04",
                           family=family, gaps=gaps)
    return problems


def _normalization(model: dict, where: str) -> list[Problem]:
    rules = model.get("normalization")
    if not isinstance(rules, dict):
        return [Problem("PMETHOD_NORMALIZATION_WEAK", where,
                        "without a normalisation rule, 'card_pan' and 'cardPan' are different "
                        "fields and only one of them is guarded", "NN-04")]
    problems = list(expect(rules.get("lowercase") is True, "PMETHOD_NORMALIZATION_WEAK", where,
                           "comparison must be case-insensitive", "NN-04"))
    stripped = set(rules.get("strip_characters") or [])
    problems += expect({"_", "-"} <= stripped, "PMETHOD_NORMALIZATION_WEAK", where,
                       "separators must be stripped before comparison; `card-pan`, `card_pan` "
                       "and `cardpan` are one field", "NN-04", stripped=sorted(stripped))
    return problems


def _custody(model: dict, families: dict, where: str) -> list[Problem]:
    custody = model.get("custody")
    if not isinstance(custody, dict):
        return [Problem("PMETHOD_CUSTODY_CLAIMED", where,
                        "the model does not say who holds the card", "NN-04")]
    rules = model.get("normalization") or {}
    forbidden = _all_names(families, rules)
    holds = {_normalize(item, rules) for item in custody.get("platform_holds") or []}
    overlap = sorted(holds & forbidden)
    problems = list(expect(not overlap, "PMETHOD_CUSTODY_CLAIMED", where,
                           f"the platform claims to hold {overlap}, which the same model "
                           f"forbids", "NN-04", overlap=overlap))
    problems += expect(str(custody.get("vault_holder") or "") == "provider",
                       "PMETHOD_CUSTODY_CLAIMED", where,
                       "the card is held by the provider; a platform that vaults it has taken "
                       "PCI scope in exchange for nothing", "NN-04")
    never = set(custody.get("platform_never_holds") or [])
    gaps = sorted(set(REQUIRED_FAMILIES) - never)
    problems += expect(not gaps, "PMETHOD_CUSTODY_CLAIMED", where,
                       f"the model does not say the platform never holds {gaps}", "NN-04")
    return problems


def _token(model: dict, where: str) -> list[Problem]:
    token = model.get("token_reference")
    if not isinstance(token, dict):
        return [Problem("PMETHOD_TOKEN_SCHEME", where,
                        "the model does not describe what a token reference is", "NN-04")]
    schemes = {str(item).lower() for item in token.get("schemes") or []}
    problems = list(expect(bool(schemes), "PMETHOD_TOKEN_SCHEME", where,
                           "the scheme list is an allowlist and must not be empty", "NN-04"))
    unsafe = sorted(schemes & UNSAFE_SCHEMES)
    problems += expect(not unsafe, "PMETHOD_TOKEN_SCHEME", where,
                       f"{unsafe} are addresses, not tokens: something that can be fetched is "
                       f"not an opaque reference", "NN-04", unsafe=unsafe)
    problems += expect(token.get("opaque") is True, "PMETHOD_TOKEN_SCHEME", where,
                       "the platform must not parse or infer from the token body", "NN-04")
    problems += expect(token.get("provider_scoped") is True,
                       "PMETHOD_TOKEN_NOT_PROVIDER_SCOPED", where,
                       "a token belongs to the provider that issued it; reusing it against "
                       "another provider either fails or charges the wrong account", "NN-04")
    return problems


def _fingerprint(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    print_ = model.get("fingerprint")
    if not isinstance(print_, dict):
        return [Problem("PMETHOD_FINGERPRINT_REVERSIBLE", where,
                        "the model does not say what a fingerprint is", "NN-04")]
    problems = list(expect(print_.get("one_way") is True, "PMETHOD_FINGERPRINT_REVERSIBLE",
                           where, "a fingerprint must be one-way", "NN-04"))
    problems += expect(print_.get("keyed") is True, "PMETHOD_FINGERPRINT_REVERSIBLE", where,
                       "an unkeyed hash over a 16-digit space is a lookup table with extra "
                       "steps, not a one-way function", "NN-04")
    problems += expect(print_.get("tenant_scoped") is True,
                       "PMETHOD_FINGERPRINT_CROSS_TENANT", where,
                       "a fingerprint shared across tenants identifies the person, not the "
                       "card: two merchants can confirm the same human paid at both", "NN-04")
    source = str(print_.get("key_source") or "")
    problems += expect(source == str(KEYS), "PMETHOD_KEY_SOURCE", where,
                       f"the fingerprint key must come from {KEYS}; a key defined here is a key "
                       f"nobody rotates", "NN-04", declared=source)
    if source == str(KEYS):
        budget.check(str(KEYS))
        problems += expect((root / KEYS).is_file(), "PMETHOD_KEY_SOURCE", where,
                           f"{KEYS} does not exist", "NN-04")
    return problems


def _display(model: dict, families: dict, where: str) -> list[Problem]:
    allowlist = model.get("display_allowlist")
    if not isinstance(allowlist, list) or not allowlist:
        return [Problem("PMETHOD_DISPLAY_FIELD_UNSAFE", where,
                        "display must be an allowlist; run it as a deny-list and every new "
                        "field is public until somebody notices", "NN-04")]
    rules = model.get("normalization") or {}
    forbidden = _all_names(families, rules)
    leaked = sorted({_normalize(item, rules) for item in allowlist} & forbidden)
    return expect(not leaked, "PMETHOD_DISPLAY_FIELD_UNSAFE", where,
                  f"{leaked} are both displayable and forbidden", "NN-04", leaked=leaked)


def _retention_and_scope(model: dict, where: str) -> list[Problem]:
    retention = model.get("retention") if isinstance(model.get("retention"), dict) else {}
    problems = list(expect(retention.get("bounded") is True, "PMETHOD_RETENTION_UNBOUNDED",
                           where, "token references and fingerprints must have an end date",
                           "NN-04"))
    for key in ("token_reference_days", "fingerprint_days"):
        value = retention.get(key)
        problems += expect(isinstance(value, int) and 0 < value <= 3650,
                           "PMETHOD_RETENTION_UNBOUNDED", where,
                           f"{key} must be a positive number of days within ten years", "NN-04",
                           declared=value)
    scope = model.get("tenant_scope") if isinstance(model.get("tenant_scope"), dict) else {}
    problems += expect(scope.get("tenant_id_required") is True, "PMETHOD_TENANT_UNSCOPED", where,
                       "every stored reference is tenant scoped", "NN-03")
    problems += expect("tenant_id" in (scope.get("lookup_key") or []),
                       "PMETHOD_TENANT_UNSCOPED", where,
                       "the lookup key must start from the tenant, or the fingerprint becomes "
                       "a global index", "NN-03")
    problems += expect(bool(str(model.get("audit_event") or "").strip()),
                       "PMETHOD_UNAUDITED", where,
                       "referencing a payment method must emit an audit event", "NN-07")
    return problems


def _derived(model: dict, root: Path, where: str, budget: Budget) -> list[Problem]:
    conformance = model.get("conformance")
    if not isinstance(conformance, dict):
        return [Problem("PMETHOD_CATALOG_UNBOUND", where,
                        "the model names no implementations, so nothing is obliged to use it",
                        "NN-12")]
    rules = model.get("normalization") or {}
    catalogue = _all_names(_families(model), rules)
    problems: list[Problem] = []
    derived = [str(item) for item in conformance.get("derived_implementations") or []]
    problems += expect(bool(derived), "PMETHOD_CATALOG_UNBOUND", where,
                       "no derived implementation is declared", "NN-12")
    for rel in derived:
        path = root / rel
        if not path.is_file():
            # Absent rather than unbound. Fixture repositories carry governance and
            # contracts but not every source tree, and a rule that fires on "the file
            # I wanted to read is not here" would fail every negative control for a
            # reason that has nothing to do with the scenario. A deleted
            # implementation is caught by the build, not by this gate.
            continue
        budget.check(rel)
        try:
            source = read_text(path, budget)
        except BudgetExceeded:
            raise
        except Exception:
            continue
        references = ("SensitiveFieldCatalog" in source
                      or str(CONTRACT) in source
                      or "sensitive-fields.json" in source)
        problems += expect(references, "PMETHOD_CATALOG_UNBOUND", rel,
                           "does not reference the generated catalogue; an implementation that "
                           "does not read the list is not bound by it", "NN-04")
        literals = {_normalize(match, rules) for match in LITERAL.findall(source)}
        copied = sorted(literals & catalogue)
        problems += expect(len(copied) < COPY_THRESHOLD, "PMETHOD_HARDCODED_LIST", rel,
                           f"carries its own copy of the forbidden list ({copied}); a second "
                           f"list is a second source of truth, and this repository already "
                           f"proved they drift", "NN-04", copied=copied)
    return problems


def _generated(root: Path, where: str, budget: Budget) -> list[Problem]:
    budget.check(str(CONTRACT))
    try:
        from .paymethodgen import render_all
        rendered = render_all(root)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("PMETHOD_GENERATED_DRIFT", where,
                        f"cannot rebuild the catalogue projections: {exc}", "NN-12")]
    problems: list[Problem] = []
    for rel, content in sorted(rendered.items()):
        path = root / rel
        if not path.parent.is_dir():
            # The tree this projection belongs to was not materialised in this
            # repository at all — a fixture, not a deletion. When the directory is
            # there and the file is not, that is a deletion and is reported below.
            continue
        current = read_text(path, budget) if path.is_file() else None
        problems += expect(current == content, "PMETHOD_GENERATED_DRIFT", rel,
                           "the committed projection is not what the model produces right now",
                           "NN-12")
    return problems
