"""B20 — KMS, HSM and envelope encryption.

A key is not configuration; it is a *capability*. The application never owns
the root key or a key-encryption key — it borrows the ability to decrypt, for a
few minutes, through a broker that records the fact.

Envelope encryption earns its keep in three places, and this gate exists to
stop each of them being quietly given up:

* ``KEY_AAD_MISSING`` — a ciphertext that is not bound to its tenant, purpose
  and key version can be **moved onto another tenant's row** and will decrypt
  perfectly. Additional authenticated data is the only thing preventing that,
  and it costs nothing, which is exactly why it gets dropped;
* ``KEY_NONCE_REUSE`` — reusing a GCM nonce under one key lets an attacker
  recover plaintext from two ciphertexts and forge new ones. It is not a
  hardening item, it is a total break;
* ``KEY_EXPORTABLE_ROOT`` — a root key that can leave the HSM is no longer a
  root key, it is a file.

The cross-checks matter as much as the local rules: every provider that B17
declares, and every field B19 classifies as card, financial or personal data,
must be covered here. A key policy that governs only the keys somebody
remembered to list is a key policy with holes shaped like the things people
forget.
"""
from __future__ import annotations

import re
from pathlib import Path

from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json
from .structs import SEMVER, expect

KEYS = Path("governance/key-management.json")
IDENTITY = Path("governance/identity.json")
AUTHZ = Path("governance/authorization.json")
PROJECT = Path("governance/project-config.json")

KEY_ID = re.compile(r"^[a-z][a-z0-9-]*$")
CLASSES = {"root", "kek", "dek"}
STORAGE = {"hsm", "kms", "envelope"}
MATERIALS = {"hsm_backed", "envelope_encrypted", "external_jwks"}
# Field classifications that must be covered by a key. Card data is handled by
# never storing it at all (B19), but if it is ever classified here it must be
# encrypted too — the rule is written so that adding a class is safe by default.
PROTECTED_CLASSIFICATIONS = {"pan", "cvv", "pii", "financial"}
AEAD = {"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"}


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("key-management", "B20")

def validate(root: Path, budget: Budget) -> list[Problem]:
    try:
        return _validate(root, budget)
    except BudgetExceeded:
        raise


def _validate(root: Path, budget: Budget) -> list[Problem]:
    where = str(KEYS)
    budget.check(where)
    try:
        model = load_json(root / KEYS)
    except Exception as exc:
        return [Problem("KEY_UNREADABLE", where, f"cannot read the key policy: {exc}", "NN-12")]
    if not isinstance(model, dict):
        return [Problem("KEY_SHAPE", where, "the key policy must be an object", "NN-12")]

    problems = list(expect(SEMVER.match(str(model.get("schema_version", ""))),
                           "KEY_VERSION_FIELD", where, "schema_version must be semver", "NN-12"))
    problems += expect(len(str(model.get("principle") or "")) >= 20, "KEY_PRINCIPLE", where,
                       "state what the key hierarchy is actually protecting against", "NN-07")
    problems += _hsm(model, where)
    problems += _envelope(model, where)
    keys, problems_ = _keys(model, where, budget)
    problems += problems_
    problems += _rotation(model, where)
    problems += _access(model, where)
    problems += _destruction(model, where)
    problems += _forbidden(model, where, keys)
    problems += _provider_keys(model, root, where, keys, budget)
    problems += _field_coverage(model, root, where, keys, budget)
    problems += _generated(root, budget)
    return problems


def _hsm(model: dict, where: str) -> list[Problem]:
    hsm = model.get("hsm")
    if not isinstance(hsm, dict):
        return [Problem("KEY_SHAPE", where, "hsm must be an object", "NN-07")]
    problems = list(expect(hsm.get("required_for_root") is True, "KEY_HSM_REQUIRED", where,
                           "root keys must live in an HSM; a root key in software is a file "
                           "someone can copy", "NN-07"))
    problems += expect(int(hsm.get("fips_140_level") or 0) >= 2, "KEY_HSM_LEVEL", where,
                       "the HSM must be FIPS 140 level 2 or above", "NN-07")
    problems += expect(hsm.get("root_key_exportable") is False, "KEY_EXPORTABLE_ROOT", where,
                       "the root key must not be exportable", "NN-07")
    problems += expect(hsm.get("attestation_required") is True, "KEY_HSM_ATTESTATION", where,
                       "the HSM must attest to what it is before it is trusted with the root key",
                       "NN-07")
    quorum = hsm.get("quorum_m_of_n")
    ok = (isinstance(quorum, list) and len(quorum) == 2
          and all(isinstance(x, int) for x in quorum) and 1 < quorum[0] <= quorum[1])
    problems += expect(ok, "KEY_QUORUM", where,
                       f"root key operations need an m-of-n quorum with m > 1, got {quorum}; "
                       f"one person able to use the root key alone is a single point of theft",
                       "NN-03")
    return problems


def _envelope(model: dict, where: str) -> list[Problem]:
    env = model.get("envelope")
    if not isinstance(env, dict):
        return [Problem("KEY_SHAPE", where, "envelope must be an object", "NN-07")]
    problems = list(expect(env.get("data_key_algorithm") in AEAD, "KEY_ALGORITHM", where,
                           f"the data key algorithm must be AEAD, got "
                           f"{env.get('data_key_algorithm')!r}; without authentication a "
                           f"ciphertext can be edited", "NN-07"))
    problems += expect(env.get("key_wrapping_algorithm") in AEAD, "KEY_ALGORITHM", where,
                       "key wrapping must also be authenticated", "NN-07")
    problems += expect(env.get("data_key_per") == "record", "KEY_DEK_SCOPE", where,
                       "one data key per record; a single data key for a whole table means one "
                       "leak exposes everything", "NN-07")
    problems += expect(int(env.get("nonce_bytes") or 0) >= 12, "KEY_NONCE_SIZE", where,
                       "GCM nonces must be at least 12 bytes", "NN-07")
    problems += expect(env.get("nonce_reuse_forbidden") is True, "KEY_NONCE_REUSE", where,
                       "nonce reuse must be forbidden explicitly; under GCM it is not a "
                       "weakness, it is a full break of both confidentiality and integrity",
                       "NN-07")
    problems += expect(env.get("aad_required") is True, "KEY_AAD_MISSING", where,
                       "additional authenticated data must be required", "NN-07")
    aad = set(env.get("aad_fields") or [])
    problems += expect({"tenant_id", "purpose", "key_id"} <= aad, "KEY_AAD_MISSING", where,
                       f"AAD must bind tenant, purpose and key version, got {sorted(aad)}; "
                       f"otherwise a ciphertext can be moved to another tenant's row and will "
                       f"decrypt cleanly", "NN-06")
    ttl = int(env.get("plaintext_data_key_ttl_seconds") or 0)
    problems += expect(0 < ttl <= 900, "KEY_PLAINTEXT_TTL", where,
                       f"a plaintext data key may live in memory for at most 15 minutes, got "
                       f"{ttl}s", "NN-07")
    problems += expect(env.get("store_unwrapped_data_key") is False, "KEY_UNWRAPPED_STORED",
                       where, "an unwrapped data key must never be stored; storing it makes the "
                              "envelope decorative", "NN-07")
    return problems


def _keys(model: dict, where: str, budget: Budget) -> tuple[dict, list[Problem]]:
    problems: list[Problem] = []
    keys: dict[str, dict] = {}
    entries = model.get("keys")
    if not isinstance(entries, list) or not entries:
        return {}, [Problem("KEY_SHAPE", where, "keys must be a non-empty list", "NN-07")]
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("KEY_SHAPE", where, "each key must be an object", "NN-12"))
            continue
        kid = str(entry.get("id") or "")
        scope = f"{where}#{kid or '<anonymous>'}"
        budget.check(scope)
        problems += expect(KEY_ID.match(kid), "KEY_ID", scope,
                           f"key id '{kid}' must be kebab-case", "NN-12")
        problems += expect(kid not in keys, "KEY_DUPLICATE", scope,
                           f"key '{kid}' is declared twice", "NN-12")
        problems += expect(entry.get("class") in CLASSES, "KEY_CLASS", scope,
                           f"class must be one of {sorted(CLASSES)}", "NN-07")
        problems += expect(entry.get("storage") in STORAGE, "KEY_STORAGE", scope,
                           f"storage must be one of {sorted(STORAGE)}", "NN-07")
        problems += expect(entry.get("exportable") is False, "KEY_EXPORTABLE", scope,
                           f"key '{kid}' must not be exportable", "NN-07")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "KEY_NOTES", scope,
                           "say what this key protects and what its loss would mean", "NN-07")
        days = int(entry.get("rotation_days") or 0)
        problems += expect(0 < days <= 730, "KEY_ROTATION_MISSING", scope,
                           f"key '{kid}' needs a rotation period of at most two years, got "
                           f"{days}", "NN-07")
        klass = entry.get("class")
        if klass == "root":
            problems += expect(entry.get("storage") == "hsm", "KEY_ROOT_STORAGE", scope,
                               f"root key '{kid}' must be stored in the HSM", "NN-07")
            problems += expect(entry.get("dual_control") is True, "KEY_ROOT_DUAL_CONTROL", scope,
                               f"root key '{kid}' must require dual control", "NN-03")
            problems += expect(not entry.get("protects_fields"), "KEY_ROOT_DIRECT_USE", scope,
                               f"root key '{kid}' must not encrypt business data directly; it "
                               f"wraps other keys", "NN-07")
        if klass == "dek":
            problems += expect(entry.get("storage") == "envelope", "KEY_DEK_STORAGE", scope,
                               f"data key '{kid}' must be stored wrapped, inside the envelope",
                               "NN-07")
            wrapped_by = entry.get("wrapped_by")
            problems += expect(bool(wrapped_by), "KEY_DEK_UNWRAPPED", scope,
                               f"data key '{kid}' must declare which KEK wraps it", "NN-07")
            problems += expect(entry.get("algorithm") in AEAD, "KEY_ALGORITHM", scope,
                               f"data key '{kid}' must use an AEAD algorithm", "NN-07")
        if kid:
            keys[kid] = entry

    for kid, entry in sorted(keys.items()):
        wrapped_by = entry.get("wrapped_by")
        if wrapped_by:
            parent = keys.get(wrapped_by)
            problems += expect(parent is not None, "KEY_WRAPPER_UNKNOWN", f"{where}#{kid}",
                               f"key '{kid}' is wrapped by unknown key '{wrapped_by}'", "NN-12")
            if parent is not None:
                problems += expect(parent.get("class") in {"root", "kek"},
                                   "KEY_WRAPPER_CLASS", f"{where}#{kid}",
                                   f"key '{kid}' is wrapped by '{wrapped_by}', which is a "
                                   f"{parent.get('class')} — only root or KEK may wrap", "NN-07")
                problems += expect(int(parent.get("rotation_days") or 0)
                                   >= int(entry.get("rotation_days") or 0),
                                   "KEY_ROTATION_INVERTED", f"{where}#{kid}",
                                   f"data key '{kid}' rotates less often than the KEK that wraps "
                                   f"it; the hierarchy is upside down", "NN-07")
    kek = [k for k in keys.values() if k.get("class") == "kek"]
    problems += expect(kek, "KEY_NO_KEK", where,
                       "there must be at least one key-encryption key between the root key and "
                       "the data", "NN-07")
    return keys, problems


def _rotation(model: dict, where: str) -> list[Problem]:
    rot = model.get("rotation")
    if not isinstance(rot, dict):
        return [Problem("KEY_SHAPE", where, "rotation must be an object", "NN-07")]
    problems = list(expect(0 < int(rot.get("kek_days") or 0) <= 365, "KEY_ROTATION_PERIOD", where,
                           "KEKs must rotate at least yearly", "NN-07"))
    problems += expect(0 < int(rot.get("root_days") or 0) <= 1095, "KEY_ROTATION_PERIOD", where,
                       "the root key must rotate at least every three years", "NN-07")
    problems += expect(rot.get("dek_per_record") is True, "KEY_DEK_SCOPE", where,
                       "data keys must be per record", "NN-07")
    overlap = int(rot.get("overlap_window_days") or 0)
    problems += expect(0 < overlap <= 30, "KEY_ROTATION_OVERLAP", where,
                       f"rotation needs a bounded overlap window so old ciphertext stays "
                       f"readable during the change, got {overlap} days; no overlap means "
                       f"rotation is an outage, an unbounded one means rotation never finishes",
                       "NN-07")
    problems += expect(rot.get("re_encrypt_strategy") == "rewrap_data_keys",
                       "KEY_REENCRYPT_STRATEGY", where,
                       "KEK rotation must rewrap data keys rather than rewrite every record; "
                       "a strategy that requires rewriting all data is a strategy nobody runs",
                       "NN-07")
    hours = int(rot.get("emergency_rotation_hours") or 0)
    problems += expect(0 < hours <= 24, "KEY_EMERGENCY_ROTATION", where,
                       f"a compromised key must be rotatable within a day, got {hours}h; "
                       f"without a rehearsed emergency path, a leak becomes a project", "NN-07")
    return problems


def _access(model: dict, where: str) -> list[Problem]:
    access = model.get("access")
    if not isinstance(access, dict):
        return [Problem("KEY_SHAPE", where, "access must be an object", "NN-07")]
    problems = list(expect(access.get("application_holds_key_material") is False,
                           "KEY_APP_HOLDS_MATERIAL", where,
                           "the application must not hold key material; it borrows the ability "
                           "to decrypt, it does not own the key", "NN-07"))
    problems += expect(access.get("decrypt_only_through_broker") is True, "KEY_BROKER_BYPASS",
                       where, "decryption must go through the key broker so every use is "
                              "mediated and recorded", "NN-07")
    problems += expect(access.get("key_use_audited") is True, "KEY_USE_UNAUDITED", where,
                       "every key use must be audited; without it, a stolen capability is "
                       "invisible", "NN-13")
    problems += expect(access.get("audit_includes_key_version") is True, "KEY_AUDIT_VERSION",
                       where, "the audit record must name the key version that was used",
                       "NN-13")
    problems += expect(access.get("dual_control_for_root_operations") is True,
                       "KEY_ROOT_DUAL_CONTROL", where,
                       "root key operations require two people", "NN-03")
    return problems


def _destruction(model: dict, where: str) -> list[Problem]:
    dest = model.get("destruction")
    if not isinstance(dest, dict):
        return [Problem("KEY_SHAPE", where, "destruction must be an object", "NN-07")]
    problems = list(expect(dest.get("crypto_shredding") is True, "KEY_NO_SHREDDING", where,
                           "crypto-shredding must be supported; in a system with backups, "
                           "destroying the key is the only deletion that can be verified",
                           "NN-06"))
    problems += expect(dest.get("tenant_offboarding_destroys_kek") is True, "KEY_NO_SHREDDING",
                       where, "offboarding a tenant must destroy that tenant's KEK", "NN-06")
    problems += expect(dest.get("destroyed_key_is_unrecoverable") is True,
                       "KEY_SHRED_RECOVERABLE", where,
                       "a destroyed key must be unrecoverable, otherwise the deletion is a "
                       "promise rather than a fact", "NN-06")
    return problems


def _forbidden(model: dict, where: str, keys: dict) -> list[Problem]:
    forbidden = model.get("forbidden")
    if not isinstance(forbidden, dict):
        return [Problem("KEY_SHAPE", where, "forbidden must be an object", "NN-07")]
    banned = {str(a).upper() for a in forbidden.get("algorithms") or []}
    problems = list(expect({"DES", "3DES", "RC4", "MD5", "SHA1", "AES-ECB"} <= banned,
                           "KEY_WEAK_ALGORITHM_ALLOWED", where,
                           f"the banned list must include the broken primitives, missing "
                           f"{sorted({'DES', '3DES', 'RC4', 'MD5', 'SHA1', 'AES-ECB'} - banned)}",
                           "NN-07"))
    problems += expect(int(forbidden.get("minimum_rsa_bits") or 0) >= 2048, "KEY_RSA_SIZE", where,
                       "RSA keys must be at least 2048 bits", "NN-07")
    problems += expect(forbidden.get("hardcoded_key_material") is False, "KEY_HARDCODED", where,
                       "hardcoded key material must be forbidden", "NN-07")
    problems += expect(forbidden.get("plaintext_key_in_logs") is False, "KEY_IN_LOGS", where,
                       "plaintext key material must never reach logs", "NN-04")
    for kid, entry in sorted(keys.items()):
        algorithm = str(entry.get("algorithm") or "").upper()
        problems += expect(algorithm not in banned, "KEY_WEAK_ALGORITHM", f"{where}#{kid}",
                           f"key '{kid}' uses banned algorithm '{algorithm}'", "NN-07")
    return problems


def _provider_keys(model: dict, root: Path, where: str, keys: dict,
                   budget: Budget) -> list[Problem]:
    problems: list[Problem] = []
    banned = {str(a).upper() for a in (model.get("forbidden") or {}).get("algorithms") or []}
    declared: dict[str, dict] = {}
    entries = model.get("provider_keys")
    if not isinstance(entries, list) or not entries:
        return [Problem("KEY_SHAPE", where, "provider_keys must be a non-empty list", "NN-07")]
    for entry in entries:
        if not isinstance(entry, dict):
            problems.append(Problem("KEY_SHAPE", where, "each provider key must be an object",
                                    "NN-12"))
            continue
        provider = str(entry.get("provider") or "")
        scope = f"{where}#{provider or '<anonymous>'}"
        budget.check(scope)
        problems += expect(provider not in declared, "KEY_PROVIDER_DUPLICATE", scope,
                           f"provider '{provider}' is declared twice", "NN-12")
        problems += expect(entry.get("material") in MATERIALS, "KEY_PROVIDER_MATERIAL", scope,
                           f"material must be one of {sorted(MATERIALS)}", "NN-07")
        problems += expect(entry.get("key_id") in keys, "KEY_PROVIDER_KEY_UNKNOWN", scope,
                           f"provider '{provider}' references unknown key "
                           f"'{entry.get('key_id')}'", "NN-12")
        problems += expect(len(str(entry.get("notes") or "")) >= 8, "KEY_PROVIDER_NOTES", scope,
                           "say where this provider's private key actually lives", "NN-07")
        algorithm = str(entry.get("signing_algorithm") or "")
        problems += expect(algorithm.upper() not in banned or algorithm == "none",
                           "KEY_WEAK_ALGORITHM", scope,
                           f"provider '{provider}' signs with banned algorithm '{algorithm}'",
                           "NN-07")
        if algorithm.upper().startswith("RSA-"):
            try:
                bits = int(algorithm.split("-")[1])
            except (IndexError, ValueError):
                bits = 0
            minimum = int((model.get("forbidden") or {}).get("minimum_rsa_bits") or 2048)
            problems += expect(bits >= minimum, "KEY_RSA_SIZE", scope,
                               f"provider '{provider}' uses {bits}-bit RSA, below the {minimum} "
                               f"bit floor", "NN-07")
        if provider:
            declared[provider] = entry

    budget.check(str(IDENTITY))
    try:
        identity = load_json(root / IDENTITY)
        idps = [str(p.get("id")) for p in (identity.get("providers") or []) if isinstance(p, dict)]
    except Exception:
        idps = []
    budget.check(str(PROJECT))
    try:
        project = load_json(root / PROJECT)
        channels = sorted((project.get("providers") or {}).keys())
    except Exception:
        channels = []
    for provider in sorted(set(idps) | set(channels)):
        problems += expect(provider in declared, "KEY_PROVIDER_UNMANAGED", where,
                           f"'{provider}' issues or verifies credentials but has no entry here; "
                           f"an unmanaged provider key is a key somebody keeps in a file",
                           "NN-07")
    return problems


def _field_coverage(model: dict, root: Path, where: str, keys: dict,
                    budget: Budget) -> list[Problem]:
    """Every field B19 classifies as sensitive must be covered by a data key."""
    problems: list[Problem] = []
    budget.check(str(AUTHZ))
    try:
        authz = load_json(root / AUTHZ)
        rules = [f for f in (authz.get("field_rules") or []) if isinstance(f, dict)]
    except Exception:
        return problems
    protected: set[str] = set()
    for entry in keys.values():
        for field in entry.get("protects_fields") or []:
            protected.add(str(field))
    for rule in rules:
        classification = str(rule.get("classification") or "")
        field = str(rule.get("field") or "")
        if classification not in PROTECTED_CLASSIFICATIONS:
            continue
        if rule.get("never_readable") is True:
            # Card data is not encrypted here because it is never stored at all
            # (B19/NN-04). Encrypting it would imply we keep it.
            problems += expect(field not in protected, "KEY_NEVER_STORED_ENCRYPTED", where,
                               f"'{field}' is declared never readable, so it must not be listed "
                               f"as an encrypted field; encrypting it implies we store it",
                               "NN-04")
            continue
        problems += expect(field in protected, "KEY_FIELD_UNPROTECTED", where,
                           f"'{field}' is classified '{classification}' but no data key protects "
                           f"it; masking controls who may read it, encryption controls what a "
                           f"stolen backup is worth", "NN-04")
    return problems


def _generated(root: Path, budget: Budget) -> list[Problem]:
    from .keysgen import TARGETS
    problems: list[Problem] = []
    for rel, render in sorted(TARGETS.items()):
        path = root / rel
        budget.check(rel)
        try:
            expected = render(root, budget)
        except BudgetExceeded:
            raise
        except Exception as exc:
            problems.append(Problem("KEY_GENERATED", rel,
                                    f"cannot generate {rel} from the key policy: {exc}", "NN-12"))
            continue
        if not path.is_file():
            problems.append(Problem("KEY_GENERATED_MISSING", rel,
                                    f"{rel} is generated from governance/key-management.json but "
                                    f"does not exist; run scripts/render-keys.py", "NN-12"))
            continue
        if path.read_text(encoding="utf-8") != expected:
            problems.append(Problem("KEY_GENERATED_DRIFT", rel,
                                    f"{rel} differs from what the key policy generates; edit "
                                    f"governance/key-management.json, not the artefact", "NN-12"))
    return problems
