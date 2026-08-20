"""B17 — executable reference for token verification.

A token policy is a list of promises. This is the code that keeps them, small
enough to audit and strict enough that each promise has a test:

* ``alg: none`` and symmetric algorithms are rejected **before** any signature
  check, because the classic attack is to make the verifier pick the algorithm;
* the audience must match exactly. A token accepted outside its audience is a
  token for every service that shares the issuer;
* expiry is checked against a bounded clock skew. An unbounded skew makes expiry
  decorative;
* an unbound token is rejected outright when binding is required, and a bound
  token presented by a different holder key is rejected too. That second check is
  the one that matters: it is what makes a stolen token useless;
* revocation is checked on every verification, not at issue time.

Not modelled: real signature verification, JWKS fetching, DPoP proof
construction. Those need crypto and a network. What is modelled is the decision
order, because getting the order wrong is how verifiers get bypassed.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class TokenRejected(Exception):
    def __init__(self, reason: str, code: str) -> None:
        super().__init__(reason)
        self.code = code


@dataclass(frozen=True)
class Token:
    issuer: str
    audience: str
    subject: str
    algorithm: str
    issued_at: int
    expires_at: int
    binding: str = ""
    holder_key: str = ""
    token_id: str = ""
    signature_valid: bool = True


@dataclass
class Verifier:
    issuer: str
    audiences: frozenset
    algorithms: frozenset
    forbidden_algorithms: frozenset
    clock_skew_seconds: int = 60
    binding_required: bool = True
    revoked: set = field(default_factory=set)
    verifications: int = 0

    @classmethod
    def for_provider(cls, provider: dict, identity: dict) -> "Verifier":
        return cls(issuer=provider["issuer"],
                   audiences=frozenset(provider["audiences"]),
                   algorithms=frozenset(provider["algorithms"]),
                   forbidden_algorithms=frozenset(identity["forbidden_algorithms"]),
                   clock_skew_seconds=int(provider["clock_skew_seconds"]),
                   binding_required=bool(identity["session_binding"]["required"]))

    def revoke(self, token_id: str) -> None:
        self.revoked.add(token_id)

    def verify(self, token: Token, *, now: int, presented_key: str = "") -> Token:
        """Return the token if acceptable; raise TokenRejected otherwise."""
        self.verifications += 1

        # Algorithm first, deliberately. The classic bypass is to let the token
        # choose the algorithm and have the verifier follow it.
        if token.algorithm in self.forbidden_algorithms:
            raise TokenRejected(
                f"algorithm '{token.algorithm}' is forbidden; a token must not be able to "
                f"choose how it is verified", "FORBIDDEN_ALGORITHM")
        if token.algorithm not in self.algorithms:
            raise TokenRejected(
                f"algorithm '{token.algorithm}' is not accepted by this provider",
                "UNKNOWN_ALGORITHM")
        if not token.signature_valid:
            raise TokenRejected("signature does not verify", "BAD_SIGNATURE")
        if token.issuer != self.issuer:
            raise TokenRejected(
                f"issuer '{token.issuer}' is not '{self.issuer}'", "WRONG_ISSUER")
        if token.audience not in self.audiences:
            raise TokenRejected(
                f"audience '{token.audience}' is not one this verifier accepts; a token "
                f"accepted outside its audience is a token for every service", "WRONG_AUDIENCE")
        if now > token.expires_at + self.clock_skew_seconds:
            raise TokenRejected(
                f"expired at {token.expires_at}, now {now} "
                f"(skew {self.clock_skew_seconds}s)", "EXPIRED")
        if now + self.clock_skew_seconds < token.issued_at:
            raise TokenRejected("issued in the future", "NOT_YET_VALID")
        if self.binding_required:
            if not token.binding or not token.holder_key:
                raise TokenRejected(
                    "unbound bearer token; whoever copies it gains the identity",
                    "UNBOUND_TOKEN")
            if presented_key != token.holder_key:
                raise TokenRejected(
                    "the token is bound to a different holder key; a stolen token is useless "
                    "without the private key", "WRONG_HOLDER")
        if token.token_id and token.token_id in self.revoked:
            raise TokenRejected("token has been revoked", "REVOKED")
        return token
