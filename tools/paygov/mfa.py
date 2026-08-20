"""B18 — phishing-resistant multi-factor authentication.

B16 named a factor called ``phishing_resistant_mfa`` and B17 left its real
strength to this batch. Here is what the phrase has to mean to be worth
anything: **the authenticator's response is bound to the origin it saw**. A
factor a person can read out, type in, or approve on a prompt can be relayed by
a site in the middle, no matter how many digits it has.

The rules therefore split into two groups. First, classification: SMS and TOTP
and push approval are *not* phishing resistant, and saying otherwise in the
model is the single edit that would make every other control here decorative.
Second, the ways a strong factor gets bypassed anyway:

* ``MFA_DOWNGRADE_FALLBACK`` — "use SMS if your key is not to hand" makes SMS the
  account's real security level;
* ``MFA_SINGLE_AUTHENTICATOR`` — registering one key does not make an account
  safer, it guarantees a weak recovery path the first time it is lost;
* ``MFA_NO_TRANSACTION_BINDING`` — a step-up that is not bound to the operation
  proves somebody authenticated recently, not that they authorised *this*
  refund;
* ``MFA_SIGN_COUNT`` — a signature counter that goes backwards means the
  authenticator was cloned, and a verifier that ignores it will never notice.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

MFA = Path("governance/mfa.json")
ZEROTRUST = Path("governance/zero-trust.json")
IDENTITY = Path("governance/identity.json")

IDENT = re.compile(r"^[a-z][a-z0-9-]*$")
# Factors a person can read out, type in, or approve on a prompt. All of them can
# be relayed in real time by a site in the middle.
RELAYABLE_KINDS = {"otp", "push"}
PRIVILEGED_ROLES = {"platform-operator", "break-glass", "merchant-admin"}


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("mfa", "B18")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    where = str(MFA)
    budget.check(where)
    try:
        mfa = load_json(root / MFA)
    except Exception as exc:
        return [Problem("MFA_UNREADABLE", where, f"cannot read the MFA policy: {exc}", "NN-12")]

    problems += expect(SEMVER.match(str(mfa.get("schema_version", ""))), "MFA_VERSION_FIELD",
                       where, "schema_version must be semver", "NN-12")
    problems += expect(len(str(mfa.get("principle") or "")) >= 20, "MFA_PRINCIPLE", where,
                       "state what phishing resistance actually means here", "NN-11")

    resistant_classes = set(mfa.get("phishing_resistant_classes") or [])
    problems += expect(resistant_classes == {"webauthn"}, "MFA_RESISTANT_CLASS", where,
                       f"only WebAuthn-class authenticators are phishing resistant, got "
                       f"{sorted(resistant_classes)}; anything a person can relay is not",
                       "NN-11")

    problems += _webauthn(mfa, where)
    problems += _step_up(mfa, where)
    problems += _fallback(mfa, where)
    problems += _enrolment(mfa, where)
    problems += _rate_limiting(mfa, where)

    authenticators, problems_ = _authenticators(mfa, where, resistant_classes, budget)
    problems += problems_
    problems += _requirements(mfa, where, authenticators, budget)
    problems += _cross_checks(mfa, root, where, authenticators)
    problems += _generated(root, budget)
    return problems


def _webauthn(mfa: dict, where: str) -> list[Problem]:
    web = mfa.get("webauthn") or {}
    problems = list(expect(bool(web.get("relying_party_id")), "MFA_RP_ID", where,
                           "a relying party id must be declared; without it an assertion is not "
                           "bound to this platform", "NN-11"))
    origins = web.get("allowed_origins") or []
    problems += expect(bool(origins), "MFA_ORIGIN", where,
                       "allowed origins must be declared; origin binding is the whole of "
                       "phishing resistance", "NN-11")
    for origin in origins:
        problems += expect(str(origin).startswith("https://"), "MFA_ORIGIN", where,
                           f"origin '{origin}' must be https", "NN-11")
    problems += expect(web.get("user_verification") == "required", "MFA_USER_VERIFICATION",
                       where,
                       "user verification must be required; without it a stolen key is a stolen "
                       "account", "NN-11")
    problems += expect(int(web.get("challenge_bytes") or 0) >= 16, "MFA_CHALLENGE", where,
                       "the challenge must be at least 16 random bytes", "NN-11")
    problems += expect(0 < int(web.get("challenge_ttl_seconds") or 0) <= 300, "MFA_CHALLENGE",
                       where,
                       "the challenge must expire within minutes; a long-lived challenge is a "
                       "replay window", "NN-11")
    problems += expect(web.get("challenge_single_use") is True, "MFA_CHALLENGE_REPLAY", where,
                       "a challenge must be single use, otherwise a captured assertion can be "
                       "replayed", "NN-11")
    problems += expect(web.get("sign_count_regression_is_clone") is True, "MFA_SIGN_COUNT",
                       where,
                       "a signature counter that goes backwards means the authenticator was "
                       "cloned; a verifier that ignores it never notices", "NN-11")
    problems += expect(bool(web.get("attestation")) and web.get("attestation") != "none",
                       "MFA_ATTESTATION", where,
                       "attestation must be requested for privileged enrolment, otherwise any "
                       "software authenticator can claim to be a hardware key", "NN-11")
    algorithms = set(web.get("allowed_algorithms") or [])
    problems += expect(algorithms and algorithms <= {-7, -257, -8}, "MFA_ALGORITHM", where,
                       f"only ES256/RS256/EdDSA COSE identifiers are accepted, got "
                       f"{sorted(algorithms)}", "NN-11")
    return problems


def _step_up(mfa: dict, where: str) -> list[Problem]:
    step_up = mfa.get("step_up") or {}
    problems = list(expect(step_up.get("required_for_high_risk") is True, "MFA_STEP_UP", where,
                           "high-risk actions must require step-up authentication", "NN-11"))
    problems += expect(0 < int(step_up.get("max_age_seconds") or 0) <= 900, "MFA_STEP_UP", where,
                       "a step-up must be recent; 'authenticated this morning' is not step-up",
                       "NN-11")
    problems += expect(step_up.get("transaction_binding") is True,
                       "MFA_NO_TRANSACTION_BINDING", where,
                       "step-up must be bound to the operation being authorised; without it the "
                       "assertion proves somebody authenticated, not that they approved this "
                       "refund", "NN-11")
    return problems


def _fallback(mfa: dict, where: str) -> list[Problem]:
    fallback = mfa.get("fallback") or {}
    problems = list(expect(fallback.get("downgrade_allowed") is False,
                           "MFA_DOWNGRADE_FALLBACK", where,
                           "no fallback may downgrade the factor; the weakest permitted path is "
                           "the account's real security level", "NN-11"))
    problems += expect(len(str(fallback.get("policy") or "")) >= 10, "MFA_DOWNGRADE_FALLBACK",
                       where, "write the fallback policy down", "NN-11")
    return problems


def _enrolment(mfa: dict, where: str) -> list[Problem]:
    enrolment = mfa.get("enrolment") or {}
    problems = list(expect(int(enrolment.get("minimum_authenticators_for_privileged") or 0) >= 2,
                           "MFA_SINGLE_AUTHENTICATOR", where,
                           "privileged accounts must register at least two authenticators; one "
                           "key guarantees a weak recovery path the first time it is lost",
                           "NN-11"))
    problems += expect(enrolment.get("verified_before_activation") is True, "MFA_ENROLMENT",
                       where,
                       "a newly registered authenticator must be exercised before it counts",
                       "NN-11")
    problems += expect(enrolment.get("notify_on_registration") is True, "MFA_ENROLMENT", where,
                       "registering a new authenticator must notify the account holder; silent "
                       "enrolment is how an attacker keeps access after a takeover", "NN-11")
    return problems


def _rate_limiting(mfa: dict, where: str) -> list[Problem]:
    limits = mfa.get("rate_limiting") or {}
    problems = list(expect(0 < int(limits.get("max_attempts_per_hour") or 0) <= 60,
                           "MFA_RATE_LIMIT", where,
                           "authentication attempts must be rate limited", "NN-11"))
    problems += expect(int(limits.get("lockout_seconds") or 0) > 0, "MFA_RATE_LIMIT", where,
                       "exceeding the limit must cost time", "NN-11")
    problems += expect(limits.get("push_fatigue_protection") is True, "MFA_PUSH_FATIGUE", where,
                       "push fatigue protection must be declared; repeated prompts until the "
                       "user taps approve is a working attack", "NN-11")
    return problems


def _authenticators(mfa: dict, where: str, resistant_classes: set,
                    budget: Budget) -> tuple[dict, list[Problem]]:
    entries = mfa.get("authenticators")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("MFA_SHAPE", where, "'authenticators' must be a non-empty list",
                            "NN-12")]
    kinds = set(mfa.get("authenticator_kinds") or [])
    problems: list[Problem] = []
    out: dict = {}
    for index, entry in enumerate(entries):
        scope = f"{where}#authenticator[{index}]"
        if not isinstance(entry, dict):
            problems.append(Problem("MFA_SHAPE", scope, "each authenticator must be an object",
                                    "NN-12"))
            continue
        budget.check(scope)
        aid = entry.get("id")
        scope = f"{where}#{aid}"
        problems += expect(isinstance(aid, str) and IDENT.match(aid or ""), "MFA_AUTH_ID", scope,
                           f"authenticator id '{aid}' must be kebab-case", "NN-12")
        problems += expect(aid not in out, "MFA_AUTH_DUPLICATE", scope,
                           f"duplicate authenticator '{aid}'", "NN-12")
        out[aid] = entry

        kind = entry.get("kind")
        problems += expect(kind in kinds, "MFA_AUTH_KIND", scope,
                           f"kind '{kind}' is not declared", "NN-12")
        resistant = entry.get("phishing_resistant")
        problems += expect(isinstance(resistant, bool), "MFA_AUTH_CLASSIFICATION", scope,
                           "phishing resistance must be declared explicitly", "NN-11")
        if kind in RELAYABLE_KINDS:
            problems += expect(resistant is False, "MFA_MISCLASSIFIED", scope,
                               f"'{aid}' is a {kind} factor and cannot be phishing resistant: a "
                               f"person can be talked into relaying it in real time. Marking it "
                               f"resistant is the one edit that makes every other rule here "
                               f"decorative", "NN-11")
            problems += expect(entry.get("origin_bound") is False, "MFA_MISCLASSIFIED", scope,
                               f"'{aid}' cannot be origin bound", "NN-11")
            problems += expect(entry.get("allowed_as_sole_factor") is False,
                               "MFA_SOLE_FACTOR", scope,
                               f"'{aid}' must never be a sole factor", "NN-11")
        if kind in resistant_classes:
            problems += expect(resistant is True, "MFA_AUTH_CLASSIFICATION", scope,
                               f"'{aid}' is a {kind} authenticator and should be classified "
                               f"phishing resistant", "NN-11")
            problems += expect(entry.get("origin_bound") is True, "MFA_ORIGIN_BINDING", scope,
                               f"'{aid}' must be origin bound; that binding *is* the phishing "
                               f"resistance", "NN-11")
        problems += expect(len(str(entry.get("notes") or "")) >= 12, "MFA_AUTH_NOTES", scope,
                           "say what this authenticator is and what it cannot do", "NN-12")
    return out, problems


def _requirements(mfa: dict, where: str, authenticators: dict,
                  budget: Budget) -> list[Problem]:
    entries = mfa.get("requirements")
    if not isinstance(entries, list) or not entries:
        return [Problem("MFA_SHAPE", where, "'requirements' must be a non-empty list", "NN-12")]
    minimum = int((mfa.get("enrolment") or {}).get("minimum_authenticators_for_privileged") or 0)
    problems: list[Problem] = []
    roles: set = set()
    for index, entry in enumerate(entries):
        scope = f"{where}#requirement[{index}]"
        if not isinstance(entry, dict):
            problems.append(Problem("MFA_SHAPE", scope, "each requirement must be an object",
                                    "NN-12"))
            continue
        budget.check(scope)
        role = entry.get("role")
        scope = f"{where}#{role}"
        problems += expect(bool(role) and role not in roles, "MFA_ROLE", scope,
                           f"duplicate or missing role '{role}'", "NN-12")
        roles.add(role)
        problems += expect(len(str(entry.get("notes") or "")) >= 12, "MFA_ROLE_NOTES", scope,
                           "say why this role gets these requirements", "NN-12")

        allowed = entry.get("allowed_authenticators") or []
        forbidden = entry.get("forbidden_authenticators") or []
        for aid in list(allowed) + list(forbidden):
            problems += expect(aid in authenticators, "MFA_UNKNOWN_AUTHENTICATOR", scope,
                               f"'{aid}' is not a declared authenticator", "NN-12")
        overlap = set(allowed) & set(forbidden)
        problems += expect(not overlap, "MFA_ROLE", scope,
                           f"{sorted(overlap)} are both allowed and forbidden", "NN-12")
        problems += expect(allowed, "MFA_ROLE", scope,
                           "a role must be able to authenticate somehow", "NN-12")

        if role in PRIVILEGED_ROLES:
            problems += expect(entry.get("required_class") == "phishing_resistant",
                               "MFA_PRIVILEGED_CLASS", scope,
                               f"'{role}' performs money or control operations and must require "
                               f"phishing-resistant authentication", "NN-11")
            weak = [aid for aid in allowed
                    if not authenticators.get(aid, {}).get("phishing_resistant")]
            problems += expect(not weak, "MFA_WEAK_FOR_PRIVILEGED", scope,
                               f"'{role}' allows non-phishing-resistant authenticators {weak}; "
                               f"the weakest allowed factor is the account's real strength",
                               "NN-11")
            problems += expect(int(entry.get("minimum_registered_authenticators") or 0)
                               >= minimum, "MFA_SINGLE_AUTHENTICATOR", scope,
                               f"'{role}' must register at least {minimum} authenticators",
                               "NN-11")
            problems += expect(bool(entry.get("step_up_actions")), "MFA_STEP_UP", scope,
                               f"'{role}' must name the actions that require step-up", "NN-11")
        else:
            problems += expect(int(entry.get("minimum_registered_authenticators") or 0) >= 1,
                               "MFA_ROLE", scope,
                               "every role needs at least one registered authenticator", "NN-12")

    for role in sorted(PRIVILEGED_ROLES):
        problems += expect(role in roles, "MFA_ROLE_UNCOVERED", where,
                           f"privileged role '{role}' has no MFA requirement; an ungoverned "
                           f"privileged role authenticates however it likes", "NN-11")
    return problems


def _cross_checks(mfa: dict, root: Path, where: str, authenticators: dict) -> list[Problem]:
    """The factor B16 named and the recovery paths B17 declared must line up."""
    problems: list[Problem] = []
    try:
        zt = load_json(root / ZEROTRUST)
    except Exception:
        zt = {}
    factors = set(zt.get("required_factors") or [])
    if factors:
        problems += expect("phishing_resistant_mfa" in factors, "MFA_FACTOR_UNBACKED", where,
                           "the zero-trust model must still declare a phishing-resistant factor "
                           "for this policy to back", "NN-11")
        resistant = [a for a in authenticators.values() if a.get("phishing_resistant")]
        problems += expect(resistant, "MFA_FACTOR_UNBACKED", where,
                           "zero trust requires a phishing-resistant factor but no authenticator "
                           "provides one", "NN-11")

    try:
        identity = load_json(root / IDENTITY)
    except Exception:
        identity = {}
    for entry in identity.get("recovery") or []:
        if not isinstance(entry, dict):
            continue
        subject = entry.get("subject")
        if subject in PRIVILEGED_ROLES:
            problems += expect(entry.get("sms_only_allowed") is False, "MFA_RECOVERY_BYPASS",
                               where,
                               f"'{subject}' requires phishing-resistant authentication but its "
                               f"recovery path allows SMS; recovery is how MFA gets bypassed",
                               "NN-11")
            problems += expect(entry.get("requires_same_or_stronger_factor") is True,
                               "MFA_RECOVERY_BYPASS", where,
                               f"'{subject}' recovery must not accept a weaker factor", "NN-11")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .mfagen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        if not path.is_file():
            problems.append(Problem("MFA_GENERATED_MISSING", rel,
                                    "generated MFA artefact is missing; run "
                                    "scripts/render-mfa.py", "NN-12"))
            continue
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("MFA_GENERATED", rel,
                                    f"the artefact cannot be derived from the policy: "
                                    f"{type(exc).__name__}: {exc}", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("MFA_GENERATED_DRIFT", rel,
                                    "the generated artefact differs from the policy; run "
                                    "scripts/render-mfa.py", "NN-12"))
    return problems
