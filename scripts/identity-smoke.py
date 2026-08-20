#!/usr/bin/env python3
"""B17 runtime proof — verify tokens instead of describing them.

Every declared token is built for real and pushed through the verifier of its
own provider, then attacked eight ways:

1. the happy path is accepted;
2. ``alg: none`` is rejected;
3. a symmetric algorithm is rejected;
4. a token for another audience is rejected;
5. an expired token is rejected, and the clock skew is bounded;
6. an unbound token is rejected;
7. a bound token presented by a different holder key is rejected — this is the
   check that makes a stolen token useless;
8. a revoked token is rejected on the very next verification.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.identity.reference.tokens import Token, TokenRejected, Verifier  # noqa: E402

IDENTITY = json.loads((ROOT / "governance/identity.json").read_text(encoding="utf-8"))
PROVIDERS = {p["id"]: p for p in IDENTITY["providers"]}

CHECKS: list[str] = []
FAILURES: list[str] = []
NOW = 1_000_000


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def rejected(verifier, token, key, expected_code) -> bool:
    try:
        verifier.verify(token, now=NOW, presented_key=key)
        return False
    except TokenRejected as exc:
        return exc.code == expected_code


def build(spec, **overrides) -> Token:
    provider = PROVIDERS[spec["provider"]]
    kwargs = {"issuer": provider["issuer"], "audience": spec["audience"],
              "subject": "subject-1", "algorithm": provider["algorithms"][0],
              "issued_at": NOW - 60,
              "expires_at": NOW + spec["lifetime_minutes"] * 60,
              "binding": spec["binding"], "holder_key": "key-a",
              "token_id": spec["id"]}
    kwargs.update(overrides)
    return Token(**kwargs)


def main() -> int:
    tokens = IDENTITY["tokens"]
    print(f"== 对全部 {len(tokens)} 种令牌做同一组攻击")

    accepted, results = [], {code: [] for code in
                             ("FORBIDDEN_ALGORITHM", "WRONG_AUDIENCE", "EXPIRED",
                              "UNBOUND_TOKEN", "WRONG_HOLDER", "REVOKED")}
    symmetric_rejected = []
    for spec in tokens:
        provider = PROVIDERS[spec["provider"]]
        # A real service configures its verifier with *its own* audience, not with
        # every audience the issuer serves. Verifying against the full issuer list
        # would let a checkout token in at the merchant portal.
        verifier = Verifier.for_provider(provider, IDENTITY)
        verifier.audiences = frozenset({spec["audience"]})
        good = build(spec)
        try:
            verifier.verify(good, now=NOW, presented_key="key-a")
            accepted.append(spec["id"])
        except TokenRejected as exc:
            print(f"       {spec['id']} happy path 被拒: {exc.code}")

        if rejected(verifier, build(spec, algorithm="none"), "key-a", "FORBIDDEN_ALGORITHM"):
            results["FORBIDDEN_ALGORITHM"].append(spec["id"])
        if rejected(verifier, build(spec, algorithm="HS256"), "key-a", "FORBIDDEN_ALGORITHM"):
            symmetric_rejected.append(spec["id"])
        other = next(a for a in ("checkout-web", "admin-web", "internal-api",
                                 "provider-egress", "artifact-registry",
                                 "cloud-control-plane", "merchant-portal")
                     if a != spec["audience"])
        # 'other' is any audience this verifier is not configured for.
        if rejected(verifier, build(spec, audience=other), "key-a", "WRONG_AUDIENCE"):
            results["WRONG_AUDIENCE"].append(spec["id"])
        stale = build(spec, expires_at=NOW - provider["clock_skew_seconds"] - 1)
        if rejected(verifier, stale, "key-a", "EXPIRED"):
            results["EXPIRED"].append(spec["id"])
        if rejected(verifier, build(spec, binding="", holder_key=""), "key-a",
                    "UNBOUND_TOKEN"):
            results["UNBOUND_TOKEN"].append(spec["id"])
        if rejected(verifier, good, "key-stolen", "WRONG_HOLDER"):
            results["WRONG_HOLDER"].append(spec["id"])
        verifier.revoke(spec["id"])
        if rejected(verifier, good, "key-a", "REVOKED"):
            results["REVOKED"].append(spec["id"])

    total = len(tokens)
    check("每种令牌的 happy path 都被接受", len(accepted) == total, f"{len(accepted)}/{total}")
    check("alg=none 一律被拒", len(results["FORBIDDEN_ALGORITHM"]) == total,
          f"{len(results['FORBIDDEN_ALGORITHM'])}/{total}")
    check("对称算法一律被拒", len(symmetric_rejected) == total,
          f"{len(symmetric_rejected)}/{total}")
    check("受众不符一律被拒（校验器只配置自己的受众）",
          len(results["WRONG_AUDIENCE"]) == total,
          f"{len(results['WRONG_AUDIENCE'])}/{total}")
    check("过期一律被拒", len(results["EXPIRED"]) == total, f"{len(results['EXPIRED'])}/{total}")
    check("无绑定令牌一律被拒", len(results["UNBOUND_TOKEN"]) == total,
          f"{len(results['UNBOUND_TOKEN'])}/{total}")
    check("**被偷的令牌换个持有者密钥就用不了**", len(results["WRONG_HOLDER"]) == total,
          f"{len(results['WRONG_HOLDER'])}/{total}")
    check("撤销后下一次校验立即被拒", len(results["REVOKED"]) == total,
          f"{len(results['REVOKED'])}/{total}")

    print()
    print("== 时钟容差是有界的")
    spec = tokens[0]
    provider = PROVIDERS[spec["provider"]]
    verifier = Verifier.for_provider(provider, IDENTITY)
    verifier.audiences = frozenset({spec["audience"]})
    skew = provider["clock_skew_seconds"]
    just_expired = build(spec, expires_at=NOW - skew + 1)
    long_expired = build(spec, expires_at=NOW - skew - 1)
    try:
        verifier.verify(just_expired, now=NOW, presented_key="key-a")
        within = True
    except TokenRejected:
        within = False
    check(f"容差 {skew} 秒内仍接受", within)
    check(f"超过容差 {skew} 秒立即拒绝",
          rejected(verifier, long_expired, "key-a", "EXPIRED"))
    check("容差不超过 300 秒", skew <= 300, skew)

    print()
    print("== 契约层的硬性质")
    check("禁止无绑定 bearer 令牌", IDENTITY["bearer_tokens_allowed"] is False)
    check("禁止 none 与对称算法",
          "none" in IDENTITY["forbidden_algorithms"]
          and any(a.startswith("HS") for a in IDENTITY["forbidden_algorithms"]))
    check("只允许授权码流 + PKCE(S256)",
          IDENTITY["oauth"]["allowed_flows"] == ["authorization_code"]
          and IDENTITY["oauth"]["pkce_method"] == "S256")
    check("重定向 URI 精确匹配", IDENTITY["oauth"]["redirect_uri_matching"] == "exact")
    check("撤销每次请求都检查", IDENTITY["revocation"]["check_on_every_request"] is True)
    check("没有任何恢复路径允许仅短信",
          all(r["sms_only_allowed"] is False for r in IDENTITY["recovery"]))
    check("没有任何恢复路径允许降级",
          all(r["requires_same_or_stronger_factor"] for r in IDENTITY["recovery"]))
    check("禁止带静态密钥的服务账号",
          IDENTITY["service_accounts"]["static_secrets_allowed"] is False)

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
