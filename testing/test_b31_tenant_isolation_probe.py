from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError, sha256_json  # noqa: E402
from elmpay_runtime.tenant_isolation_probe import (  # noqa: E402
    SURFACES,
    SurfaceObservation,
    TenantIsolationProbeRunner,
)


NOW = datetime(2026, 8, 28, tzinfo=timezone.utc)
DIGEST = "a" * 64


class FakeSurface:
    def __init__(self, surface: str, *, leak: bool = False,
                 unavailable: bool = False, wrong_digest: bool = False) -> None:
        self.surface = surface
        self.leak = leak
        self.unavailable = unavailable
        self.wrong_digest = wrong_digest
        self.requests: list[dict[str, str]] = []

    def observe(self, **request: str) -> SurfaceObservation:
        self.requests.append(request)
        if self.unavailable:
            raise OSError("offline")
        owner_digest = "b" * 64 if self.wrong_digest else request["expected_digest"]
        response = {
            "surface": self.surface,
            "owner": owner_digest,
            "crossTenantDenied": not self.leak,
            "nonce": request["nonce"],
        }
        return SurfaceObservation(
            self.surface, True, owner_digest, not self.leak,
            sha256_json(response), "ISOLATED" if not self.leak else "LEAK",
        )


class TenantIsolationProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = Path(self.directory.name) / "isolation.sqlite"

    def tearDown(self) -> None:
        self.directory.cleanup()

    def runner(self, **overrides: FakeSurface) -> tuple[TenantIsolationProbeRunner,
                                                        dict[str, FakeSurface]]:
        surfaces = {name: overrides.get(name, FakeSurface(name)) for name in SURFACES}
        return TenantIsolationProbeRunner(self.database, surfaces), surfaces

    @staticmethod
    def request() -> dict[str, object]:
        return {
            "owner_tenant_id": "tenant-owner",
            "attacker_tenant_id": "tenant-attacker",
            "canary_id": "canary-payment-1",
            "expected_digest": DIGEST,
            "run_id": "probe-run-1",
            "now": NOW,
        }

    def test_all_five_live_surface_observations_are_required_and_durable(self) -> None:
        runner, surfaces = self.runner()
        result = runner.run(**self.request())
        self.assertEqual("PASSED", result["status"])
        self.assertEqual(5, len(result["surfaces"]))
        self.assertEqual("NOT_CERTIFIED", result["certificationStatus"])
        for surface in surfaces.values():
            self.assertEqual("tenant-owner", surface.requests[0]["owner_tenant_id"])
            self.assertEqual("tenant-attacker", surface.requests[0]["attacker_tenant_id"])
        replay = runner.run(**self.request())
        self.assertIs(replay["replayed"], True)
        self.assertEqual(result["resultDigest"], replay["resultDigest"])

    def test_leak_unavailable_or_owner_digest_mismatch_fail_closed(self) -> None:
        runner, _ = self.runner(
            cache=FakeSurface("cache", leak=True),
            log=FakeSurface("log", unavailable=True),
            export=FakeSurface("export", wrong_digest=True),
        )
        result = runner.run(**self.request())
        self.assertEqual("FAILED", result["status"])
        reasons = {item["surface"]: item["reasonCode"] for item in result["surfaces"]}
        self.assertEqual("LEAK", reasons["cache"])
        self.assertEqual("SURFACE_UNAVAILABLE", reasons["log"])
        self.assertEqual("OWNER_CANARY_DIGEST_MISMATCH", reasons["export"])

    def test_cross_tenant_identity_and_run_binding_cannot_be_weakened(self) -> None:
        runner, _ = self.runner()
        same_tenant = dict(self.request(), attacker_tenant_id="tenant-owner")
        with self.assertRaisesRegex(ValidationError, "must be different"):
            runner.run(**same_tenant)
        runner.run(**self.request())
        with self.assertRaisesRegex(ValidationError, "bound to another request"):
            runner.run(**dict(self.request(), canary_id="canary-payment-2"))


if __name__ == "__main__":
    unittest.main()
