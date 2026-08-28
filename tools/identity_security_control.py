#!/usr/bin/env python3
"""Executable B16-B21 identity-security administration and decision surface."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent / "runtime"))

from elmpay_runtime.common import ValidationError, parse_instant, read_json  # noqa: E402
from elmpay_runtime.identity_security import IdentitySecurityStore  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ELMPay zero-trust identity security control")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--policy", type=Path,
                        default=ROOT / "platform/security/identity-security-policy.json")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    evaluate = commands.add_parser("evaluate")
    evaluate.add_argument("--request", type=Path, required=True)
    oidc = commands.add_parser("verify-oidc")
    oidc.add_argument("--token-file", type=Path, required=True)
    oidc.add_argument("--public-keys", type=Path, required=True)
    oidc.add_argument("--issuer", required=True)
    oidc.add_argument("--audience", required=True)
    oidc.add_argument("--nonce", required=True)
    oidc.add_argument("--holder-thumbprint", required=True)
    oidc.add_argument("--device-id", required=True)
    challenge = commands.add_parser("issue-webauthn")
    for name in ("tenant", "user", "operation", "origin", "rp-id", "session-binding"):
        challenge.add_argument("--" + name, required=True)
    assertion = commands.add_parser("verify-webauthn")
    for name in ("tenant", "challenge-id", "credential-id", "session-binding"):
        assertion.add_argument("--" + name, required=True)
    assertion.add_argument("--client-data", type=Path, required=True)
    assertion.add_argument("--authenticator-data", type=Path, required=True)
    assertion.add_argument("--signature", type=Path, required=True)
    propose = commands.add_parser("propose-grant")
    for name in ("tenant", "subject", "role", "object-scope", "proposer",
                 "valid-from", "valid-until"):
        propose.add_argument("--" + name, required=True)
    propose.add_argument("--fields", required=True,
                         help="comma-separated field allowlist; use * explicitly for all")
    approve = commands.add_parser("approve-grant")
    approve.add_argument("--tenant", required=True)
    approve.add_argument("--grant-id", required=True)
    approve.add_argument("--approver", required=True)
    recovery = commands.add_parser("propose-recovery")
    for name in ("tenant", "subject", "proposer", "reason", "expires-at"):
        recovery.add_argument("--" + name, required=True)
    approve_recovery = commands.add_parser("approve-recovery")
    approve_recovery.add_argument("--tenant", required=True)
    approve_recovery.add_argument("--recovery-id", required=True)
    approve_recovery.add_argument("--approver", required=True)
    commands.add_parser("scan-certificates")
    return parser


def _emit(value: object) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store = None
    try:
        args.db.parent.mkdir(parents=True, exist_ok=True)
        store = IdentitySecurityStore(str(args.db), read_json(args.policy))
        now = datetime.now(timezone.utc)
        if args.command == "init":
            _emit({"initialized": True, "defaultDecision": "DENY",
                   "certificationStatus": "NOT_CERTIFIED"})
        elif args.command == "evaluate":
            _emit(store.evaluate_zero_trust(read_json(args.request), now).__dict__)
        elif args.command == "verify-oidc":
            principal = store.verify_oidc_and_issue_session(
                args.token_file.read_text(encoding="ascii").strip(), read_json(args.public_keys),
                expected_issuer=args.issuer, expected_audience=args.audience,
                expected_nonce=args.nonce, holder_thumbprint=args.holder_thumbprint,
                device_id=args.device_id, now=now,
            )
            _emit(principal.__dict__)
        elif args.command == "issue-webauthn":
            _emit(store.issue_webauthn_challenge(
                args.tenant, args.user, args.operation, args.origin, args.rp_id,
                args.session_binding, now,
            ))
        elif args.command == "verify-webauthn":
            result = store.verify_webauthn_assertion(
                tenant_id=args.tenant, challenge_id=args.challenge_id,
                credential_id=args.credential_id,
                client_data_json=args.client_data.read_bytes(),
                authenticator_data=args.authenticator_data.read_bytes(),
                signature=args.signature.read_bytes(), session_binding=args.session_binding,
                now=now,
            )
            _emit(result.__dict__)
        elif args.command == "propose-grant":
            grant_id = store.propose_grant(
                args.tenant, args.subject, args.role, args.object_scope,
                [item.strip() for item in args.fields.split(",") if item.strip()],
                parse_instant(args.valid_from, "valid-from"),
                parse_instant(args.valid_until, "valid-until"), args.proposer, now,
            )
            _emit({"grantId": grant_id, "state": "PROPOSED"})
        elif args.command == "approve-grant":
            store.approve_grant(args.tenant, args.grant_id, args.approver, now)
            _emit({"grantId": args.grant_id, "state": "ACTIVE"})
        elif args.command == "propose-recovery":
            recovery_id = store.propose_recovery(
                args.tenant, args.subject, args.proposer, args.reason,
                parse_instant(args.expires_at, "expires-at"), now,
            )
            _emit({"recoveryId": recovery_id, "state": "PROPOSED"})
        elif args.command == "approve-recovery":
            revoked = store.approve_recovery(args.tenant, args.recovery_id, args.approver, now)
            _emit({"recoveryId": args.recovery_id, "state": "APPROVED",
                   "revokedSessions": revoked})
        elif args.command == "scan-certificates":
            _emit({"alerts": store.certificate_expiry_scan(now)})
        else:
            raise ValidationError("unsupported identity-security command")
        return 0
    except (OSError, TypeError, ValueError, ValidationError) as exc:
        _emit({"allowed": False, "reasons": [f"input_invalid:{exc}"]})
        return 2
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    sys.exit(main())
