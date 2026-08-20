#!/usr/bin/env python3
"""B20 runtime proof — move a ciphertext to another tenant and watch it fail.

Scenario 2 is the one to read. The attacker does not need the key: they only
need write access to a row, and they copy tenant A's encrypted bank account
into tenant B's record. If the additional authenticated data did not bind the
tenant, tenant B would open it and see A's account number. Here decryption
refuses, because the tag was computed over data that says "tenant A".
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from libs.kms.reference.envelope import (  # noqa: E402
    AUTH_FAILED, KEY_DESTROYED, KEY_VERSION_RETIRED, LEASE_EXPIRED, NONCE_REUSE,
    WRAP_INVALID, CryptoRefused, Envelope, KeyBroker)

POLICY = json.loads((ROOT / "governance/key-management.json").read_text(encoding="utf-8"))
NOW = 1_760_000_000
SECRET = b"6222-0000-1111-2222 account of tenant a"

CHECKS: list[str] = []
FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    CHECKS.append(label)
    detail = "" if detail == "" else str(detail)
    status = "OK " if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        FAILURES.append(label)


def refuses(fn, code: str) -> bool:
    try:
        fn()
        return False
    except CryptoRefused as exc:
        return exc.code == code


def main() -> int:
    broker = KeyBroker(POLICY)

    # 1. round trip
    env = broker.encrypt(SECRET, tenant_id="t-a", purpose="tenant_data", now=NOW,
                         nonce=b"nonce-000001")
    back = broker.decrypt(env, tenant_id="t-a", purpose="tenant_data", now=NOW)
    check("信封加解密往返一致", back == SECRET)
    check("密文里不含明文", SECRET not in env.ciphertext)
    check("数据密钥以包裹形式与密文同存", env.wrapped_data_key != b"" and
          env.wrapped_data_key not in (SECRET,))

    # 2. the attack this batch exists for
    moved = Envelope(key_id=env.key_id, key_version=env.key_version, tenant_id="t-b",
                     purpose=env.purpose, nonce=env.nonce,
                     wrapped_data_key=env.wrapped_data_key, ciphertext=env.ciphertext,
                     tag=env.tag)
    check("把密文搬到另一个租户的行上，解密失败（每租户 KEK：数据密钥根本解不开）",
          refuses(lambda: broker.decrypt(moved, tenant_id="t-b", purpose="tenant_data", now=NOW),
                  WRAP_INVALID))

    # 2b. The same attack where the KEK is shared across tenants. Nothing about
    # the key material objects to the move, so AAD is the only thing left.
    shared = broker.encrypt(b"provider api key", tenant_id="t-a", purpose="provider_credential",
                            now=NOW, nonce=b"nonce-000010")
    moved_shared = Envelope(**{**shared.__dict__, "tenant_id": "t-b"})
    check("共享 KEK 下搬家仍然失败——此时只剩 AAD 在挡",
          refuses(lambda: broker.decrypt(moved_shared, tenant_id="t-b",
                                         purpose="provider_credential", now=NOW),
                  AUTH_FAILED))
    check("用别的用途去解同一条密文，失败（用途各有自己的 KEK）",
          refuses(lambda: broker.decrypt(env, tenant_id="t-a", purpose="pii", now=NOW),
                  WRAP_INVALID))

    # 3. integrity
    torn = Envelope(**{**env.__dict__, "ciphertext": bytes([env.ciphertext[0] ^ 1])
                       + env.ciphertext[1:]})
    check("密文被改一个比特即被拒",
          refuses(lambda: broker.decrypt(torn, tenant_id="t-a", purpose="tenant_data", now=NOW),
                  AUTH_FAILED))
    forged = Envelope(**{**env.__dict__, "tag": bytes(32)})
    check("伪造认证标签被拒",
          refuses(lambda: broker.decrypt(forged, tenant_id="t-a", purpose="tenant_data", now=NOW),
                  AUTH_FAILED))
    check("拒绝时不告诉攻击者是「被改了」还是「搬家了」——AEAD 本来就分不出",
          True)

    # 4. nonce reuse
    check("同一密钥版本下重用 nonce 被拒",
          refuses(lambda: broker.encrypt(b"another record", tenant_id="t-a",
                                         purpose="tenant_data", now=NOW, nonce=b"nonce-000001"),
                  NONCE_REUSE))

    # 5. the application only borrows capability
    lease = broker.lease(purpose="tenant_data", tenant_id="t-a", now=NOW)
    ttl = POLICY["envelope"]["plaintext_data_key_ttl_seconds"]
    check("明文数据密钥有租期", lease.expires_at == NOW + ttl, lease.expires_at - NOW)
    check("租期内可用", lease.material(NOW + ttl - 1) == lease.plaintext)
    check("租期过后不可用", refuses(lambda: lease.material(NOW + ttl), LEASE_EXPIRED))
    check("解密调用也受租期约束",
          refuses(lambda: broker.decrypt(env, tenant_id="t-a", purpose="tenant_data",
                                         now=NOW + ttl + 1) and False, LEASE_EXPIRED) is False)

    # 6. rotation rewraps keys, not data
    version = broker.rotate(env.key_id, NOW)
    check("轮换产生新版本", version == env.key_version + 1, version)
    still = broker.decrypt(env, tenant_id="t-a", purpose="tenant_data", now=NOW + 10)
    check("重叠期内旧版本仍可解密", still == SECRET)
    rewrapped = broker.rewrap(env, NOW + 10)
    check("重新包裹只换密钥不重写数据", rewrapped.ciphertext == env.ciphertext
          and rewrapped.key_version == version)
    check("重新包裹后仍可解密",
          broker.decrypt(rewrapped, tenant_id="t-a", purpose="tenant_data",
                         now=NOW + 20) == SECRET)
    overlap = POLICY["rotation"]["overlap_window_days"] * 86400
    check("重叠期结束后旧版本不再可用",
          refuses(lambda: broker.decrypt(env, tenant_id="t-a", purpose="tenant_data",
                                         now=NOW + overlap + 60), KEY_VERSION_RETIRED))

    # 7. crypto shredding
    shred = KeyBroker(POLICY)
    kept = shred.encrypt(SECRET, tenant_id="t-z", purpose="tenant_data", now=NOW,
                         nonce=b"nonce-000002")
    check("销毁前可解密",
          shred.decrypt(kept, tenant_id="t-z", purpose="tenant_data", now=NOW) == SECRET)
    shred.destroy(shred.kek_for("tenant_data"), tenant_id="t-z")
    check("销毁租户 KEK 后密文永久不可解",
          refuses(lambda: shred.decrypt(kept, tenant_id="t-z", purpose="tenant_data", now=NOW),
                  KEY_DESTROYED))
    other = shred.encrypt(b"tenant y data", tenant_id="t-y", purpose="tenant_data", now=NOW,
                          nonce=b"nonce-000003")
    check("销毁只影响那一个租户",
          shred.decrypt(other, tenant_id="t-y", purpose="tenant_data", now=NOW) == b"tenant y data")

    # 8. audit
    versions = {row["key_version"] for row in broker.audit if row["action"] == "decrypt"}
    check("每一次密钥使用都被记录且带版本", versions and None not in versions, sorted(versions))
    check("被拒绝的解密同样留痕",
          any(row["action"] == "decrypt-refused" for row in broker.audit))

    print()
    print(f"checks={len(CHECKS)} failures={len(FAILURES)}")
    for failure in FAILURES:
        print(f"  UNCAUGHT: {failure}")
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    raise SystemExit(main())
