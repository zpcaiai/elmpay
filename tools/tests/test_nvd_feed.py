"""Deterministic controls for the OWASP NVD data-feed preflight."""
from __future__ import annotations

from datetime import datetime, timezone

UTC = timezone.utc

from tools.paygov import nvdfeed
from tools.tests.support import FixtureTestCase


VALID_METADATA = b"""lastModifiedDate:2026-08-22T11:16:54.447Z
size:22334543
gzSize:2944874
sha256:6ddffe4a20db0e9bb189697ac647dc4eba624f7759e927f076361283716ca9a9
"""


class NvdFeedPreflightTests(FixtureTestCase):
    def test_accepts_fresh_strict_metadata(self):
        seen = []

        def fetch(url, timeout):
            seen.append((url, timeout))
            return VALID_METADATA

        result = nvdfeed.check(
            self.fixture.root,
            fetcher=fetch,
            now=datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["max_age_hours"], 48)
        self.assertEqual(result["feed_gzip_size"], 2944874)
        self.assertEqual(
            seen,
            [(
                "https://dependency-check.github.io/DependencyCheck_Builder/"
                "nvd_cache/nvdcve-modified.meta",
                20,
            )],
        )

    def test_rejects_stale_metadata(self):
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "older than 48 hours"):
            nvdfeed.check(
                self.fixture.root,
                fetcher=lambda _url, _timeout: VALID_METADATA,
                now=datetime(2026, 8, 25, 12, 0, tzinfo=UTC),
            )

    def test_rejects_future_metadata(self):
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "future"):
            nvdfeed.check(
                self.fixture.root,
                fetcher=lambda _url, _timeout: VALID_METADATA,
                now=datetime(2026, 8, 22, 11, 0, tzinfo=UTC),
            )

    def test_rejects_missing_metadata_field(self):
        malformed = VALID_METADATA.replace(b"gzSize:2944874\n", b"")
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "governed schema"):
            nvdfeed.parse_metadata(malformed)

    def test_rejects_duplicate_metadata_field(self):
        malformed = VALID_METADATA + b"size:1\n"
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "duplicate field"):
            nvdfeed.parse_metadata(malformed)

    def test_rejects_invalid_feed_digest(self):
        malformed = VALID_METADATA.replace(
            b"6ddffe4a20db0e9bb189697ac647dc4eba624f7759e927f076361283716ca9a9",
            b"not-a-digest",
        )
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "sha256"):
            nvdfeed.parse_metadata(malformed)

    def test_rejects_relaxed_catalogue_policy(self):
        self.fixture.mutate(
            "governance/version-catalog.json",
            lambda document: next(
                entry for entry in document["entries"]
                if entry["id"] == "owasp-dependency-check"
            )["datafeed_policy"].__setitem__("max_age_hours", 168),
        )
        with self.assertRaisesRegex(nvdfeed.FeedPolicyError, "not exact"):
            nvdfeed.check(
                self.fixture.root,
                fetcher=lambda _url, _timeout: VALID_METADATA,
                now=datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
            )
