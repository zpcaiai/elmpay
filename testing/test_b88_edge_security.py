from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.edge_security import (  # noqa: E402
    EdgeGuard,
    EdgeRequest,
    MappingSecretResolver,
    SQLiteEdgeStateStore,
    sign_request,
)


NOW = datetime(2026, 8, 28, 0, 0, tzinfo=timezone.utc)


class EdgeSecurityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.secret = b"k" * 32
        self.state = SQLiteEdgeStateStore(str(Path(self.temp.name) / "edge.sqlite"))
        self.guard = EdgeGuard(
            secrets=MappingSecretResolver({("tenant-a", "project-a"): self.secret}),
            state=self.state,
            allowed_origins={"tenant-a": ("https://merchant.example",)},
            trusted_proxy_cidrs=("10.0.0.0/8",),
            request_limit_per_minute=2,
            ip_limit_per_minute=10,
        )

    def tearDown(self) -> None:
        self.state.close()
        self.temp.cleanup()

    def request(self, nonce: str, **changes: object) -> EdgeRequest:
        values: dict[str, object] = {
            "tenant_id": "tenant-a",
            "project_id": "project-a",
            "method": "POST",
            "path": "/v1/payment-intents",
            "body": b'{"amountMinor":100}',
            "content_type": "application/json",
            "origin": "https://merchant.example",
            "source_ip": "10.0.0.8",
            "forwarded_for": "198.51.100.7, 10.0.0.9",
            "timestamp": NOW,
            "nonce": nonce,
            "signature": "0" * 64,
        }
        values.update(changes)
        unsigned = EdgeRequest(**values)  # type: ignore[arg-type]
        return EdgeRequest(**{**values, "signature": sign_request(unsigned, self.secret)})  # type: ignore[arg-type]

    def test_signed_request_is_tenant_bound_and_forward_chain_is_safe(self) -> None:
        decision = self.guard.authorize(self.request("nonce-00000000000001"), now=NOW)
        self.assertTrue(decision.allowed)
        self.assertEqual("198.51.100.7", decision.effective_ip)

    def test_replay_and_nonce_conflict_fail_closed(self) -> None:
        first = self.request("nonce-00000000000002")
        self.assertTrue(self.guard.authorize(first, now=NOW).allowed)
        self.assertEqual("REQUEST_REPLAYED", self.guard.authorize(first, now=NOW).code)
        changed = self.request("nonce-00000000000002", body=b'{"amountMinor":101}')
        self.assertEqual("REQUEST_NONCE_CONFLICT", self.guard.authorize(changed, now=NOW).code)

    def test_waf_cors_signature_and_rate_limit_are_enforced(self) -> None:
        malicious = self.request("nonce-00000000000003", body=b'{"q":"<script>"}')
        self.assertEqual("WAF_INPUT_REJECTED", self.guard.authorize(malicious, now=NOW).code)
        bad_origin = self.request("nonce-00000000000004", origin="https://evil.example")
        self.assertEqual("CORS_ORIGIN_DENIED", self.guard.authorize(bad_origin, now=NOW).code)
        bad_signature = self.request("nonce-00000000000005")
        bad_signature = EdgeRequest(**{**bad_signature.__dict__, "signature": "f" * 64})
        self.assertEqual("REQUEST_SIGNATURE_INVALID", self.guard.authorize(bad_signature, now=NOW).code)
        self.assertTrue(self.guard.authorize(self.request("nonce-00000000000006"), now=NOW).allowed)
        self.assertTrue(self.guard.authorize(self.request("nonce-00000000000007"), now=NOW).allowed)
        self.assertEqual(
            "TENANT_RATE_LIMITED",
            self.guard.authorize(self.request("nonce-00000000000008"), now=NOW).code,
        )

    def test_untrusted_peer_cannot_spoof_forwarded_for(self) -> None:
        request = self.request(
            "nonce-00000000000009",
            source_ip="203.0.113.4",
            forwarded_for="198.51.100.99",
        )
        decision = self.guard.authorize(request, now=NOW)
        self.assertTrue(decision.allowed)
        self.assertEqual("203.0.113.4", decision.effective_ip)


if __name__ == "__main__":
    unittest.main()
