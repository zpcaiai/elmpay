"""B21 — key, certificate and domain lifecycle.

Almost nothing in this area fails because someone broke the cryptography. It
fails because a certificate expired on a Sunday, because a rotation could not be
performed without downtime so it was never performed, or because a revocation
was issued and nothing checked it. So the rules here are about *time*:

* ``CERT_RENEW_MARGIN`` — the warning must arrive early enough that a human can
  still act after two automated renewals have already failed. A 90-day
  certificate with a 2-day margin is a certificate that will expire;
* ``CERT_NO_OVERLAP`` — a rotation with no window where both the old and the new
  material are accepted is a rotation that requires an outage, and a rotation
  that requires an outage is one nobody runs;
* ``CERT_MANUAL_SHORT_LIVED`` — seven-day certificates renewed by hand are a
  weekly gamble on somebody remembering;
* ``DOMAIN_NO_LOCK`` / ``DOMAIN_NO_CAA`` — if the domain can be taken, an
  attacker gets a *valid* certificate and TLS stops proving anything at all.

The cross-checks tie this to B20 (every material must name a managed key) and to
B17 (a provider whose signing key is rotated here must exist there).
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

CERTS = Path("governance/certificates.json")
KEYS = Path("governance/key-management.json")
IDENTITY = Path("governance/identity.json")

MATERIAL_ID = re.compile(r"^[a-z][a-z0-9-]*$")
DOMAIN = re.compile(r"^[a-z0-9.-]+$")
KINDS = {"tls_certificate", "signing_key", "verification_key", "ca_certificate"}
STAGES = ["generate", "distribute", "activate", "overlap", "rotate", "revoke", "recover"]
# Anything renewed this often cannot depend on a person remembering.
SHORT_LIVED_DAYS = 30
# Beyond two months of warning, more lead time buys nothing: the work is the
# same and the alert just gets ignored for longer.
MAX_USEFUL_MARGIN_DAYS = 60


VALIDATOR = ("certificates", "B21")


def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(CERTS)
    budget.check(where)
    try:
        model = load_json(root / CERTS)
    except Exception as exc:
        return [Problem("CERT_UNREADABLE", where,
                        f"cannot read the certificate lifecycle model: {exc}", "NN-07")]
    if not isinstance(model, dict):
        return [Problem("CERT_SHAPE", where, "the lifecycle model must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "CERT_VERSION_FIELD", where, "schema_version must be semver", "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "CERT_PRINCIPLE", where,
                       "state what actually goes wrong with certificates", "NN-07")
    problems += expect(list(model.get("lifecycle_stages") or []) == STAGES, "CERT_STAGES", where,
                       f"the lifecycle must cover {STAGES} in order; a lifecycle that stops at "
                       f"'rotate' has no answer for the day a key leaks", "NN-07")

    materials, problems_ = _materials(model, root, where, budget)
    problems += problems_
    problems += _domains(model, where, budget)
    problems += _alerting(model, where, materials)
    problems += _recovery(model, where)
    problems += _forbidden(model, where)
    problems += _cross_checks(model, root, where, materials, budget)
    problems += _generated(root, budget)
    return problems


def _materials(model: dict, root: Path, where: str,
               budget: Budget) -> tuple[dict, list[Problem]]:
    problems: list[Problem] = []
    materials: dict[str, dict] = {}
    entries = model.get("materials")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("CERT_SHAPE", where, "materials must be a non-empty list", "NN-07")]
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("CERT_SHAPE", where, "each material must be an object",
                                    "NN-12"))
            continue
        mid = str(entry.get("id") or "")
        scope = f"{where}#{mid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(MATERIAL_ID.match(mid), "CERT_ID", scope,
                           f"material id '{mid}' must be kebab-case", "NN-12")
        problems += expect(mid not in materials, "CERT_DUPLICATE", scope,
                           f"material '{mid}' is declared twice", "NN-12")
        problems += expect(entry.get("kind") in KINDS, "CERT_KIND", scope,
                           f"kind must be one of {sorted(KINDS)}", "NN-07")
        problems += expect(len(str(entry.get("owner") or "")) >= 4, "CERT_OWNER", scope,
                           "every certificate needs a named owner; unowned material is material "
                           "nobody renews", "NN-11")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "CERT_NOTES", scope,
                           "say what breaks when this expires", "NN-07")
        problems += expect(bool(entry.get("revocation")), "CERT_NO_REVOCATION", scope,
                           f"'{mid}' declares no revocation route; a credential that cannot be "
                           f"withdrawn is permanent", "NN-07")

        validity = int(entry.get("validity_days") or 0)
        margin = int(entry.get("renew_before_days") or 0)
        overlap = int(entry.get("overlap_days") or 0)
        problems += expect(validity > 0, "CERT_NO_VALIDITY", scope,
                           f"'{mid}' has no validity period", "NN-07")
        problems += expect(margin > 0, "CERT_RENEW_MARGIN", scope,
                           f"'{mid}' has no renewal margin", "NN-07")
        if validity > 0 and margin > 0:
            # A third of the lifetime, but never more than MAX_USEFUL_MARGIN_DAYS.
            # Proportional-only would demand a 20-month margin on a five-year CA
            # certificate, which is not caution, it is an unsatisfiable rule —
            # and unsatisfiable rules get switched off.
            required = min(validity // 3, MAX_USEFUL_MARGIN_DAYS)
            problems += expect(margin >= required, "CERT_RENEW_MARGIN", scope,
                               f"'{mid}' warns {margin} days before a {validity} day lifetime; "
                               f"at least {required} days are needed so a failed renewal is a "
                               f"ticket, not an incident", "NN-07")
            problems += expect(margin < validity, "CERT_RENEW_MARGIN", scope,
                               f"'{mid}' would renew before it is issued ({margin} >= "
                               f"{validity})", "NN-12")
        problems += expect(overlap > 0, "CERT_NO_OVERLAP", scope,
                           f"'{mid}' has no overlap window; without one, rotation means every "
                           f"holder of the old material fails at the same instant", "NN-07")
        if validity > 0 and overlap > 0:
            problems += expect(overlap <= validity, "CERT_OVERLAP_TOO_LONG", scope,
                               f"'{mid}' overlaps for {overlap} days of a {validity} day "
                               f"lifetime; an overlap longer than the material means the old "
                               f"one never actually goes away", "NN-07")
        if 0 < validity <= SHORT_LIVED_DAYS:
            problems += expect(entry.get("automated_renewal") is True,
                               "CERT_MANUAL_SHORT_LIVED", scope,
                               f"'{mid}' lives {validity} days and is renewed by hand; that is a "
                               f"scheduled outage waiting for someone's holiday", "NN-07")
        if entry.get("automated_renewal") is False:
            problems += expect(margin >= 30, "CERT_MANUAL_MARGIN", scope,
                               f"'{mid}' is renewed manually, so its margin must leave room for "
                               f"a human process; {margin} days is not enough", "NN-07")
        if mid:
            materials[mid] = entry
    return materials, problems


def _domains(model: dict, where: str, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    entries = model.get("domains")
    if not isinstance(entries, list) or not entries:
        return [Problem("CERT_SHAPE", where, "domains must be a non-empty list", "NN-07")]
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("CERT_SHAPE", where, "each domain must be an object",
                                    "NN-12"))
            continue
        name = str(entry.get("name") or "")
        scope = f"{where}#{name or '<anonymous>'}"
        budget.check(scope)
        problems += expect(bool(DOMAIN.match(name)), "DOMAIN_NAME", scope,
                           f"'{name}' is not a domain name", "NN-12")
        problems += expect(name not in seen, "DOMAIN_DUPLICATE", scope,
                           f"domain '{name}' is declared twice", "NN-12")
        seen.add(name)
        problems += expect(entry.get("registrar_lock") is True, "DOMAIN_NO_LOCK", scope,
                           f"'{name}' has no registrar lock; a stolen domain lets an attacker "
                           f"obtain a genuinely valid certificate, and then TLS proves nothing",
                           "NN-07")
        problems += expect(entry.get("dnssec") is True, "DOMAIN_NO_DNSSEC", scope,
                           f"'{name}' has no DNSSEC", "NN-07")
        caa = entry.get("caa_records")
        problems += expect(isinstance(caa, list) and bool(caa), "DOMAIN_NO_CAA", scope,
                           f"'{name}' has no CAA records; without them any public CA in the "
                           f"world may issue for it", "NN-07")
        expires = int(entry.get("expires_in_days") or 0)
        margin = int(entry.get("renew_before_days") or 0)
        problems += expect(expires > 0 and margin > 0, "DOMAIN_NO_RENEWAL", scope,
                           f"'{name}' has no renewal schedule; an expired domain is an outage "
                           f"nobody can fix from inside", "NN-07")
        if expires > 0 and margin > 0:
            problems += expect(margin >= 30, "DOMAIN_RENEW_MARGIN", scope,
                               f"'{name}' warns only {margin} days ahead; domain renewal often "
                               f"involves a registrar and a payment method, not a script",
                               "NN-07")
        problems += expect(len(str(entry.get("owner") or "")) >= 4, "DOMAIN_OWNER", scope,
                           "every domain needs a named owner", "NN-11")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "DOMAIN_NOTES", scope,
                           "say what this domain is for", "NN-07")
    return problems


def _alerting(model: dict, where: str, materials: dict) -> list[Problem]:
    alerting = model.get("alerting")
    if not isinstance(alerting, dict):
        return [Problem("CERT_SHAPE", where, "alerting must be an object", "NN-13")]
    channels = alerting.get("channels")
    problems = list(expect(isinstance(channels, list) and len(channels) >= 2,
                           "CERT_ALERT_CHANNELS", where,
                           "expiry alerts must reach more than one channel; a single channel is "
                           "one filtered mailbox away from silence", "NN-13"))
    ratio = float(alerting.get("expiry_warning_ratio") or 0)
    problems += expect(0 < ratio <= 1, "CERT_ALERT_THRESHOLD", where,
                       "the expiry warning threshold must be a ratio of the lifetime", "NN-13")
    escalate = int(alerting.get("escalate_after_failed_renewals") or 0)
    problems += expect(0 < escalate <= 3, "CERT_NO_ESCALATION", where,
                       f"automated renewal must escalate to a human after at most three "
                       f"failures, got {escalate}; silent retries are how certificates expire "
                       f"while a robot keeps trying", "NN-13")
    problems += expect(alerting.get("alert_on_unexpected_issuer") is True,
                       "CERT_NO_ISSUER_ALERT", where,
                       "an unexpected issuer must raise an alert", "NN-07")
    problems += expect(alerting.get("certificate_transparency_monitoring") is True,
                       "CERT_NO_CT_MONITORING", where,
                       "certificate transparency logs must be monitored; a certificate issued "
                       "for our domain that we did not request is the earliest signal of a "
                       "domain or CA compromise", "NN-07")
    # Deliberately not cross-multiplied against every material's lifetime: the
    # warning ratio governs short-lived automated material, while long-lived
    # material is governed by the absolute margin floor above. Requiring both
    # would demand a 20-month warning on a five-year CA certificate.
    for mid, entry in sorted(materials.items()):
        validity = int(entry.get("validity_days") or 0)
        margin = int(entry.get("renew_before_days") or 0)
        if validity and margin and ratio and validity <= 90:
            problems += expect(margin >= validity * ratio - 1e-9, "CERT_ALERT_THRESHOLD",
                               f"{where}#{mid}",
                               f"'{mid}' would be warned about at {validity * ratio:.0f} days "
                               f"but only starts renewing at {margin}", "NN-13")
    return problems


def _recovery(model: dict, where: str) -> list[Problem]:
    recovery = model.get("recovery")
    if not isinstance(recovery, dict):
        return [Problem("CERT_SHAPE", where, "recovery must be an object", "NN-07")]
    problems = list(expect(recovery.get("rehearsed") is True, "CERT_UNREHEARSED_RECOVERY", where,
                           "the recovery path must be rehearsed; an unrehearsed procedure is a "
                           "document, and documents do not restore signing capability", "NN-07"))
    interval = int(recovery.get("rehearsal_interval_days") or 0)
    problems += expect(0 < interval <= 365, "CERT_REHEARSAL_INTERVAL", where,
                       f"recovery must be rehearsed at least yearly, got {interval} days",
                       "NN-07")
    hours = int(recovery.get("max_recovery_hours") or 0)
    problems += expect(0 < hours <= 24, "CERT_RECOVERY_TIME", where,
                       f"recovery must have a bounded objective, got {hours}h", "NN-07")
    problems += expect(recovery.get("offline_backup_of_ca") is True, "CERT_NO_CA_BACKUP", where,
                       "the CA material needs an offline backup", "NN-07")
    problems += expect(recovery.get("quorum_required") is True, "CERT_RECOVERY_QUORUM", where,
                       "recovery must require a quorum, or the recovery path becomes the easiest "
                       "way to steal the CA", "NN-03")
    return problems


def _forbidden(model: dict, where: str) -> list[Problem]:
    forbidden = model.get("forbidden")
    if not isinstance(forbidden, dict):
        return [Problem("CERT_SHAPE", where, "forbidden must be an object", "NN-07")]
    problems = list(expect(forbidden.get("self_signed_at_edge") is False, "CERT_SELF_SIGNED_EDGE",
                           where, "self-signed certificates must stay forbidden at the edge",
                           "NN-07"))
    problems += expect(forbidden.get("manual_renewal_for_short_lived") is False,
                       "CERT_MANUAL_SHORT_LIVED", where,
                       "short-lived material must not be renewed by hand", "NN-07")
    problems += expect(forbidden.get("shared_key_across_environments") is False,
                       "CERT_SHARED_ENVIRONMENT_KEY", where,
                       "production and non-production must not share key material; the staging "
                       "copy is the one that leaks", "NN-07")
    return problems


def _cross_checks(model: dict, root: Path, where: str, materials: dict,
                  budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    budget.check(str(KEYS))
    try:
        keys = load_json(root / KEYS)
        known_keys = {str(k.get("id")) for k in (keys.get("keys") or []) if isinstance(k, dict)}
        provider_keys = {str(p.get("provider")): p for p in (keys.get("provider_keys") or [])
                         if isinstance(p, dict)}
    except Exception:
        known_keys, provider_keys = set(), {}
    for mid, entry in sorted(materials.items()):
        key_id = entry.get("key_id")
        problems += expect(key_id in known_keys, "CERT_KEY_UNMANAGED", f"{where}#{mid}",
                           f"'{mid}' names key '{key_id}', which governance/key-management.json "
                           f"does not manage; material outside the key hierarchy is material "
                           f"nobody can rotate", "NN-07")

    budget.check(str(IDENTITY))
    try:
        identity = load_json(root / IDENTITY)
        rotation_days = {str(p.get("id")): int(p.get("jwks_rotation_days") or 0)
                         for p in (identity.get("providers") or []) if isinstance(p, dict)}
    except Exception:
        rotation_days = {}
    for mid, entry in sorted(materials.items()):
        if entry.get("kind") != "signing_key":
            continue
        validity = int(entry.get("validity_days") or 0)
        for provider, days in sorted(rotation_days.items()):
            if provider in str(entry.get("subject") or "") and days and validity > days:
                problems.append(Problem(
                    "CERT_ROTATION_SLOWER_THAN_IDENTITY", f"{where}#{mid}",
                    f"'{mid}' is valid for {validity} days but B17 requires '{provider}' keys to "
                    f"rotate every {days}", "NN-07"))

    hsm_backed = {p for p, entry in provider_keys.items()
                  if entry.get("material") == "hsm_backed"}
    for provider in sorted(hsm_backed):
        covered = any(provider.split("-")[0] in str(m.get("subject") or "")
                      or provider.split("-")[0] in mid
                      for mid, m in materials.items())
        problems += expect(covered, "CERT_PROVIDER_UNTRACKED", where,
                           f"'{provider}' holds HSM-backed key material in B20 but has no "
                           f"lifecycle entry here; a key with no expiry date is a key that "
                           f"expires unexpectedly", "NN-07")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .certsgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("CERT_GENERATED", rel,
                                    f"cannot generate {rel}: {exc}", "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("CERT_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/certificates.json but "
                                    f"does not exist; run scripts/render-certs.py", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("CERT_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the lifecycle model generates",
                                    "NN-12"))
    return problems
