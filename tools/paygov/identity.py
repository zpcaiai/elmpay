"""B17 — customer, administrator and service identity.

B16 said every access needs an authenticated identity. This says what an
identity *is*, and every rule here closes a way that identities get stolen or
outlive their usefulness:

* ``ID_BEARER_TOKEN`` — an unbound bearer token is fully usable by whoever
  copies it, and logs, proxies, browser extensions and crash reporters all copy
  it. Binding to a holder key (DPoP or mTLS) makes a stolen token useless;
* ``ID_FORBIDDEN_ALGORITHM`` — ``alg: none`` needs no explanation, and a shared
  symmetric secret means every party that can *verify* a token can also *forge*
  one;
* ``ID_FORBIDDEN_FLOW`` — the implicit flow puts tokens in URLs and the password
  flow hands every client the user's password;
* ``ID_RECOVERY_DOWNGRADE`` / ``ID_RECOVERY_SMS`` — account recovery is the most
  reliable way into an account, because it is designed to work when the real
  owner has lost everything. A recovery path weaker than the primary factor is
  the account's real security level, and SIM swap makes SMS recovery of a
  high-privilege account a one-night takeover;
* ``ID_STATIC_SERVICE_ACCOUNT`` — a service password has no expiry (NN-07).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

IDENTITY = Path("governance/identity.json")
ZEROTRUST = Path("governance/zero-trust.json")

IDENT = re.compile(r"^[a-z][a-z0-9-]*$")
MAX_ACCESS_TOKEN_MINUTES = 60
HIGH_PRIVILEGE_SUBJECTS = {"platform-operator", "merchant-admin"}


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("identity", "B17")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    where = str(IDENTITY)
    budget.check(where)
    try:
        identity = load_json(root / IDENTITY)
    except Exception as exc:
        return [Problem("ID_UNREADABLE", where, f"cannot read the identity model: {exc}",
                        "NN-12")]

    problems += expect(SEMVER.match(str(identity.get("schema_version", ""))),
                       "ID_VERSION_FIELD", where, "schema_version must be semver", "NN-12")
    problems += expect(len(str(identity.get("principle") or "")) >= 20, "ID_PRINCIPLE", where,
                       "state what an identity must be", "NN-12")
    problems += expect(identity.get("bearer_tokens_allowed") is False, "ID_BEARER_TOKEN", where,
                       "unbound bearer tokens must be forbidden; anything that copies the token "
                       "gains the identity, and logs and proxies copy tokens all day", "NN-07")

    forbidden_algorithms = {str(a) for a in identity.get("forbidden_algorithms") or []}
    problems += expect("none" in forbidden_algorithms, "ID_FORBIDDEN_ALGORITHM", where,
                       "'none' must be an explicitly forbidden algorithm", "NN-07")
    problems += expect(any(a.startswith("HS") for a in forbidden_algorithms),
                       "ID_FORBIDDEN_ALGORITHM", where,
                       "symmetric signing must be forbidden across parties: everyone who can "
                       "verify such a token can also forge one", "NN-07")

    problems += _oauth(identity, where)
    problems += _machine_oauth(identity, where)
    problems += _revocation(identity, where)
    problems += _binding(identity, where)
    problems += _service_accounts(identity, where)

    providers, problems_ = _providers(identity, where, forbidden_algorithms, budget)
    problems += problems_
    tokens, problems_ = _tokens(identity, where, providers, budget)
    problems += problems_
    problems += _recovery(identity, where, budget)
    problems += _principals(identity, root, where, providers, tokens)
    problems += _generated(root, budget)
    return problems


def _oauth(identity: dict, where: str) -> list[Problem]:
    oauth = identity.get("oauth") or {}
    allowed = set(oauth.get("allowed_flows") or [])
    forbidden = set(oauth.get("forbidden_flows") or [])
    problems = list(expect(allowed == {"authorization_code"}, "ID_FLOW", where,
                           f"only the authorization code flow may be allowed, got "
                           f"{sorted(allowed)}", "NN-07"))
    for flow in ("implicit", "resource_owner_password"):
        problems += expect(flow in forbidden, "ID_FORBIDDEN_FLOW", where,
                           f"'{flow}' must be explicitly forbidden; the implicit flow puts "
                           f"tokens in URLs and the password flow hands every client the user's "
                           f"password", "NN-07")
    problems += expect(oauth.get("pkce_required") is True, "ID_PKCE", where,
                       "PKCE must be required", "NN-07")
    problems += expect(oauth.get("pkce_method") == "S256", "ID_PKCE", where,
                       "PKCE must use S256; the 'plain' method protects nothing", "NN-07")
    problems += expect(oauth.get("redirect_uri_matching") == "exact", "ID_REDIRECT_MATCH", where,
                       "redirect URIs must match exactly; prefix matching is an open redirect "
                       "with extra steps (NN-10)", "NN-10")
    problems += expect(oauth.get("state_required") is True and oauth.get("nonce_required") is True,
                       "ID_CSRF", where,
                       "state and nonce must both be required", "NN-07")
    return problems


def _machine_oauth(identity: dict, where: str) -> list[Problem]:
    machine = identity.get("machine_oauth") or {}
    allowed = set(machine.get("allowed_flows") or [])
    problems = list(expect(allowed == {"client_credentials"}, "ID_MACHINE_FLOW", where,
                           "machine OAuth must allow only client_credentials", "NN-07"))
    problems += expect(machine.get("static_client_secret_allowed") is False,
                       "ID_MACHINE_STATIC_SECRET", where,
                       "machine OAuth must not authenticate merchants with static client_secret",
                       "NN-07")
    problems += expect(machine.get("client_authentication") == "mtls"
                       and machine.get("access_token_binding") == "mtls",
                       "ID_MACHINE_BINDING", where,
                       "machine OAuth client authentication and access tokens must both be "
                       "bound to mTLS", "NN-07")
    problems += expect(0 < int(machine.get("maximum_token_minutes") or 0) <= 5,
                       "ID_MACHINE_LIFETIME", where,
                       "merchant machine access tokens must expire within five minutes", "NN-07")
    problems += expect(len(str(machine.get("policy") or "")) >= 12,
                       "ID_MACHINE_FLOW", where,
                       "machine OAuth must state its security policy", "NN-12")
    return problems


def _revocation(identity: dict, where: str) -> list[Problem]:
    revocation = identity.get("revocation") or {}
    problems = list(expect(0 < int(revocation.get("propagation_seconds") or 0) <= 300,
                           "ID_REVOCATION_DEADLINE", where,
                           "revocation must take effect within minutes", "NN-12"))
    problems += expect(revocation.get("check_on_every_request") is True, "ID_REVOCATION_CHECK",
                       where,
                       "revocation must be checked on every request; a check at login only "
                       "means a revoked session lives until it expires", "NN-12")
    problems += expect(bool(revocation.get("mechanism")), "ID_REVOCATION_DEADLINE", where,
                       "name the revocation mechanism", "NN-12")
    return problems


def _binding(identity: dict, where: str) -> list[Problem]:
    binding = identity.get("session_binding") or {}
    methods = set(binding.get("methods") or [])
    problems = list(expect(binding.get("required") is True, "ID_BINDING_REQUIRED", where,
                           "every token must be bound to a holder key", "NN-07"))
    problems += expect(methods <= {"dpop", "mtls"} and methods, "ID_BINDING_METHOD", where,
                       f"binding methods must be DPoP or mTLS, got {sorted(methods)}", "NN-07")
    return problems


def _service_accounts(identity: dict, where: str) -> list[Problem]:
    accounts = identity.get("service_accounts") or {}
    problems = list(expect(accounts.get("static_secrets_allowed") is False,
                           "ID_STATIC_SERVICE_ACCOUNT", where,
                           "service accounts with static secrets must be forbidden; a password "
                           "with no expiry is a permanent breach waiting for disclosure",
                           "NN-07"))
    problems += expect(accounts.get("issuance") == "workload_identity_only",
                       "ID_STATIC_SERVICE_ACCOUNT", where,
                       "service credentials must be issued as workload identity", "NN-07")
    return problems


def _providers(identity: dict, where: str, forbidden_algorithms: set,
               budget: Budget) -> tuple[dict, list[Problem]]:
    providers = identity.get("providers")
    if not isinstance(providers, list) or not providers:
        return {}, [Problem("ID_SHAPE", where, "'providers' must be a non-empty list", "NN-12")]
    problems: list[Problem] = []
    out: dict = {}
    for index, provider in enumerate(providers):
        scope = f"{where}#provider[{index}]"
        if not isinstance(provider, dict):
            problems.append(Problem("ID_SHAPE", scope, "each provider must be an object",
                                    "NN-12"))
            continue
        budget.check(scope)
        pid = provider.get("id")
        scope = f"{where}#{pid}"
        problems += expect(isinstance(pid, str) and IDENT.match(pid or ""), "ID_PROVIDER_ID",
                           scope, f"provider id '{pid}' must be kebab-case", "NN-12")
        problems += expect(pid not in out, "ID_PROVIDER_DUPLICATE", scope,
                           f"duplicate provider '{pid}'", "NN-12")
        out[pid] = provider

        issuer = str(provider.get("issuer") or "")
        problems += expect(issuer.startswith(("https://", "spiffe://")), "ID_ISSUER", scope,
                           f"issuer '{issuer}' must be https or spiffe; a plaintext issuer can "
                           f"be spoofed by anyone on the path", "NN-07")
        problems += expect(bool(provider.get("audiences")), "ID_AUDIENCE", scope,
                           "a provider must declare its audiences; a token with no audience is "
                           "accepted everywhere it is presented", "NN-07")

        algorithms = set(provider.get("algorithms") or [])
        problems += expect(algorithms, "ID_ALGORITHM", scope,
                           "declare the accepted signature algorithms", "NN-07")
        leaked = algorithms & forbidden_algorithms
        problems += expect(not leaked, "ID_FORBIDDEN_ALGORITHM", scope,
                           f"provider accepts forbidden algorithms {sorted(leaked)}", "NN-07")

        problems += expect(0 < int(provider.get("jwks_rotation_days") or 0) <= 90,
                           "ID_KEY_ROTATION", scope,
                           "signing keys must rotate at least quarterly", "NN-07")
        problems += expect(0 < int(provider.get("max_token_minutes") or 0)
                           <= MAX_ACCESS_TOKEN_MINUTES, "ID_TOKEN_LIFETIME", scope,
                           f"tokens from this provider must live at most "
                           f"{MAX_ACCESS_TOKEN_MINUTES} minutes", "NN-07")
        problems += expect(0 < int(provider.get("clock_skew_seconds") or 0) <= 300,
                           "ID_CLOCK_SKEW", scope,
                           "clock skew tolerance must be small and stated; an unbounded skew "
                           "makes expiry meaningless", "NN-07")
        problems += expect(len(str(provider.get("notes") or "")) >= 12, "ID_PROVIDER_NOTES",
                           scope, "say what this provider is for", "NN-12")
    return out, problems


def _tokens(identity: dict, where: str, providers: dict,
            budget: Budget) -> tuple[dict, list[Problem]]:
    tokens = identity.get("tokens")
    if not isinstance(tokens, list) or not tokens:
        return {}, [Problem("ID_SHAPE", where, "'tokens' must be a non-empty list", "NN-12")]
    kinds = set(identity.get("token_kinds") or [])
    methods = set((identity.get("session_binding") or {}).get("methods") or [])
    problems: list[Problem] = []
    out: dict = {}
    for index, token in enumerate(tokens):
        scope = f"{where}#token[{index}]"
        if not isinstance(token, dict):
            problems.append(Problem("ID_SHAPE", scope, "each token must be an object", "NN-12"))
            continue
        budget.check(scope)
        tid = token.get("id")
        scope = f"{where}#{tid}"
        problems += expect(isinstance(tid, str) and IDENT.match(tid or ""), "ID_TOKEN_ID", scope,
                           f"token id '{tid}' must be kebab-case", "NN-12")
        problems += expect(tid not in out, "ID_TOKEN_DUPLICATE", scope,
                           f"duplicate token '{tid}'", "NN-12")
        out[tid] = token

        problems += expect(token.get("kind") in kinds, "ID_TOKEN_KIND", scope,
                           f"kind '{token.get('kind')}' is not declared", "NN-12")
        provider = providers.get(token.get("provider"))
        problems += expect(provider is not None, "ID_TOKEN_PROVIDER", scope,
                           f"'{token.get('provider')}' is not a declared provider", "NN-12")
        if provider:
            problems += expect(token.get("audience") in (provider.get("audiences") or []),
                               "ID_AUDIENCE", scope,
                               f"audience '{token.get('audience')}' is not one this provider "
                               f"issues for; a token accepted outside its audience is a token "
                               f"for every service", "NN-07")
            problems += expect(int(token.get("lifetime_minutes") or 0)
                               <= int(provider.get("max_token_minutes") or 0),
                               "ID_TOKEN_LIFETIME", scope,
                               "the token outlives its provider's maximum", "NN-07")
        problems += expect(0 < int(token.get("lifetime_minutes") or 0)
                           <= MAX_ACCESS_TOKEN_MINUTES, "ID_TOKEN_LIFETIME", scope,
                           "every token must expire, and soon", "NN-07")
        problems += expect(token.get("binding") in methods, "ID_BEARER_TOKEN", scope,
                           f"token binding '{token.get('binding')}' is not one of "
                           f"{sorted(methods)}; an unbound token is usable by whoever copies it",
                           "NN-07")
        problems += expect(token.get("revocable") is True, "ID_TOKEN_REVOCABLE", scope,
                           "every token must be revocable; one that can only expire cannot be "
                           "taken back during an incident", "NN-12")
        problems += expect(len(str(token.get("notes") or "")) >= 10, "ID_TOKEN_NOTES", scope,
                           "say what this token is for", "NN-12")
    return out, problems


def _recovery(identity: dict, where: str, budget: Budget) -> list[Problem]:
    entries = identity.get("recovery")
    if not isinstance(entries, list) or not entries:
        return [Problem("ID_SHAPE", where, "'recovery' must be a non-empty list; an account "
                        "system with no defined recovery grows an undefined one", "NN-12")]
    problems: list[Problem] = []
    subjects: set = set()
    for index, entry in enumerate(entries):
        scope = f"{where}#recovery[{index}]"
        if not isinstance(entry, dict):
            problems.append(Problem("ID_SHAPE", scope, "each recovery entry must be an object",
                                    "NN-12"))
            continue
        budget.check(scope)
        subject = entry.get("subject")
        scope = f"{where}#recovery:{subject}"
        problems += expect(bool(subject) and subject not in subjects, "ID_RECOVERY_SUBJECT",
                           scope, f"duplicate or missing recovery subject '{subject}'", "NN-12")
        subjects.add(subject)

        problems += expect(bool(entry.get("methods")), "ID_RECOVERY_METHOD", scope,
                           "a recovery path must name its methods", "NN-12")
        problems += expect(entry.get("requires_same_or_stronger_factor") is True,
                           "ID_RECOVERY_DOWNGRADE", scope,
                           "recovery must not accept a weaker factor than the primary one; if it "
                           "does, the weaker factor is the account's real security level",
                           "NN-11")
        problems += expect(entry.get("sms_only_allowed") is False, "ID_RECOVERY_SMS", scope,
                           "SMS-only recovery must be forbidden; SIM swap turns a phone number "
                           "into an account takeover", "NN-11")
        problems += expect(bool(entry.get("notify_channels")), "ID_RECOVERY_NOTIFY", scope,
                           "recovery must notify the account holder; a silent recovery is a "
                           "silent takeover", "NN-11")
        if subject in HIGH_PRIVILEGE_SUBJECTS:
            problems += expect(int(entry.get("delay_hours") or 0) >= 24, "ID_RECOVERY_DELAY",
                               scope,
                               "high-privilege recovery needs a cooling-off period so the real "
                               "holder can stop it", "NN-11")
        problems += expect(len(str(entry.get("notes") or "")) >= 12, "ID_RECOVERY_NOTES", scope,
                           "say why this recovery path is safe", "NN-12")

    problems += expect("platform-operator" in subjects, "ID_RECOVERY_UNCOVERED", where,
                       "the highest-privilege account must have a defined recovery path; an "
                       "undefined one becomes 'ask someone in the team'", "NN-11")
    return problems


def _principals(identity: dict, root: Path, where: str, providers: dict,
                tokens: dict) -> list[Problem]:
    """Every zero-trust principal must be backed by a real identity here."""
    try:
        zt = load_json(root / ZEROTRUST)
    except Exception:
        return []
    declared = {p.get("id"): p for p in zt.get("principals") or [] if isinstance(p, dict)}
    session_limit = int((zt.get("session") or {}).get("max_human_session_minutes") or 0)

    bindings = {b.get("principal"): b for b in identity.get("principal_bindings") or []
                if isinstance(b, dict)}
    problems: list[Problem] = []
    for pid, principal in sorted(declared.items()):
        binding = bindings.get(pid)
        problems += expect(binding is not None, "ID_PRINCIPAL_UNBACKED", where,
                           f"zero-trust principal '{pid}' has no identity binding; a principal "
                           f"with no issuer cannot be authenticated or revoked", "NN-07")
        if not binding:
            continue
        problems += expect(binding.get("provider") in providers, "ID_PRINCIPAL_PROVIDER", where,
                           f"'{pid}' is bound to unknown provider "
                           f"'{binding.get('provider')}'", "NN-07")
        token = tokens.get(binding.get("token"))
        problems += expect(token is not None, "ID_PRINCIPAL_TOKEN", where,
                           f"'{pid}' is bound to unknown token '{binding.get('token')}'",
                           "NN-07")
        if token and principal.get("kind") == "human" and session_limit:
            problems += expect(int(token.get("lifetime_minutes") or 0) <= session_limit,
                               "ID_LIFETIME_EXCEEDS_SESSION", where,
                               f"'{pid}' uses a token living "
                               f"{token.get('lifetime_minutes')} minutes, longer than the "
                               f"{session_limit}-minute zero-trust session limit", "NN-12")
        if pid == "merchant-api-client":
            problems += expect(binding.get("provider") == "merchant-authorization-server",
                               "ID_MERCHANT_API_BINDING", where,
                               "merchant API clients must use the dedicated authorization server",
                               "NN-07")
            problems += expect(binding.get("token") == "merchant-api-access" and token
                               and token.get("binding") == "mtls"
                               and token.get("audience") == "elmpay-api"
                               and int(token.get("lifetime_minutes") or 0) <= 5,
                               "ID_MERCHANT_API_BINDING", where,
                               "merchant API token must be five-minute, elmpay-api audience and "
                               "mTLS bound", "NN-07")
    for pid in sorted(bindings):
        problems += expect(pid in declared, "ID_PRINCIPAL_UNKNOWN", where,
                           f"'{pid}' has an identity binding but is not a zero-trust principal",
                           "NN-12")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .idgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        if not path.is_file():
            problems.append(Problem("ID_GENERATED_MISSING", rel,
                                    "generated identity artefact is missing; run "
                                    "scripts/render-identity.py", "NN-12"))
            continue
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("ID_GENERATED", rel,
                                    f"the artefact cannot be derived from the identity model: "
                                    f"{type(exc).__name__}: {exc}", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("ID_GENERATED_DRIFT", rel,
                                    "the generated artefact differs from the identity model; "
                                    "run scripts/render-identity.py", "NN-12"))
    return problems
