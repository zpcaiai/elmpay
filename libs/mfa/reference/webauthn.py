"""B18 — executable model of the WebAuthn assertion ceremony.

"Phishing resistant" is a property, not an adjective, and this is the code that
makes it one. The authenticator signs over the origin *it* saw; the verifier
compares that origin with its own list. A phishing site can copy the page, relay
the challenge, and convince the user of anything — and still cannot produce an
assertion whose origin says ``https://pay.example.invalid``.

That single check is why ``test_a_phishing_origin_is_rejected`` exists and why
OTP factors cannot be classified the same way: a person can be talked into
reading six digits to a stranger, but cannot be talked into changing what the
browser told the authenticator.

Also modelled, because each is a real bypass:

* a replayed challenge — captured assertions must not work twice;
* a missing user-verification flag — a stolen key must not equal a stolen
  account;
* a signature counter that goes backwards — the authenticator has been cloned;
* a step-up that is not bound to the operation — it proves somebody
  authenticated, not that they approved *this* refund.

Not modelled: real signature verification, CBOR/COSE parsing, attestation chain
validation. Those need crypto. What is modelled is the ceremony's decision
order, because that is where verifiers get bypassed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


class CeremonyRejected(Exception):
    def __init__(self, reason: str, code: str) -> None:
        super().__init__(reason)
        self.code = code


@dataclass(frozen=True)
class Assertion:
    """What the authenticator returns, with the fields that decide the outcome."""

    credential_id: str
    origin: str            # the origin the *authenticator* saw, not the one we hoped for
    relying_party_id: str
    challenge: str
    user_verified: bool
    sign_count: int
    algorithm: int = -7
    signature_valid: bool = True
    transaction_hash: str = ""


def transaction_hash(operation: str, payload: str) -> str:
    return hashlib.sha256(f"{operation}|{payload}".encode("utf-8")).hexdigest()


@dataclass
class RelyingParty:
    relying_party_id: str
    allowed_origins: frozenset
    user_verification: str = "required"
    allowed_algorithms: frozenset = frozenset({-7, -257})
    challenge_single_use: bool = True
    sign_count_regression_is_clone: bool = True
    issued_challenges: dict = field(default_factory=dict)
    spent_challenges: set = field(default_factory=set)
    credentials: dict = field(default_factory=dict)

    @classmethod
    def from_policy(cls, policy: dict) -> "RelyingParty":
        web = policy["webauthn"]
        return cls(relying_party_id=web["relying_party_id"],
                   allowed_origins=frozenset(web["allowed_origins"]),
                   user_verification=web["user_verification"],
                   allowed_algorithms=frozenset(web["allowed_algorithms"]),
                   challenge_single_use=bool(web["challenge_single_use"]),
                   sign_count_regression_is_clone=bool(web["sign_count_regression_is_clone"]))

    def issue_challenge(self, name: str, *, expires_at: int = 10 ** 12) -> str:
        self.issued_challenges[name] = expires_at
        return name

    def register(self, credential_id: str, sign_count: int = 0) -> None:
        self.credentials[credential_id] = sign_count

    def verify(self, assertion: Assertion, *, now: int = 0,
               expect_transaction: str = "") -> Assertion:
        if assertion.algorithm not in self.allowed_algorithms:
            raise CeremonyRejected(
                f"algorithm {assertion.algorithm} is not accepted", "BAD_ALGORITHM")

        # Origin first. This is the check the whole batch is about: the
        # authenticator signs over the origin it saw, and a phishing site cannot
        # make that say ours.
        if assertion.origin not in self.allowed_origins:
            raise CeremonyRejected(
                f"assertion was produced for origin '{assertion.origin}', which is not one of "
                f"{sorted(self.allowed_origins)}; this is what a phishing site cannot fake",
                "WRONG_ORIGIN")
        if assertion.relying_party_id != self.relying_party_id:
            raise CeremonyRejected(
                f"relying party id '{assertion.relying_party_id}' is not "
                f"'{self.relying_party_id}'", "WRONG_RP_ID")

        expiry = self.issued_challenges.get(assertion.challenge)
        if expiry is None:
            raise CeremonyRejected("challenge was never issued by us", "UNKNOWN_CHALLENGE")
        if now > expiry:
            raise CeremonyRejected("challenge has expired", "STALE_CHALLENGE")
        if self.challenge_single_use and assertion.challenge in self.spent_challenges:
            raise CeremonyRejected(
                "challenge has already been used; a captured assertion must not work twice",
                "REPLAYED_CHALLENGE")

        if self.user_verification == "required" and not assertion.user_verified:
            raise CeremonyRejected(
                "user verification flag is not set; without it a stolen key is a stolen account",
                "NO_USER_VERIFICATION")
        if not assertion.signature_valid:
            raise CeremonyRejected("signature does not verify", "BAD_SIGNATURE")

        known = self.credentials.get(assertion.credential_id)
        if known is None:
            raise CeremonyRejected("credential is not registered", "UNKNOWN_CREDENTIAL")
        if self.sign_count_regression_is_clone and assertion.sign_count <= known \
                and not (assertion.sign_count == 0 and known == 0):
            raise CeremonyRejected(
                f"signature counter went from {known} to {assertion.sign_count}; the "
                f"authenticator has been cloned", "CLONED_AUTHENTICATOR")

        if expect_transaction:
            if assertion.transaction_hash != expect_transaction:
                raise CeremonyRejected(
                    "the assertion is not bound to this operation; it proves somebody "
                    "authenticated, not that they approved this one",
                    "TRANSACTION_NOT_BOUND")

        self.spent_challenges.add(assertion.challenge)
        self.credentials[assertion.credential_id] = assertion.sign_count
        return assertion
