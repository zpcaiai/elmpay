"""Deterministic controls for the OWASP NVD data-feed preflight."""
from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

UTC = timezone.utc

from tools.paygov import nvdfeed
from tools.tests.support import FixtureTestCase


VALID_METADATA = b"""lastModifiedDate:2026-08-22T11:16:54.447Z
size:22334543
gzSize:2944874
sha256:6ddffe4a20db0e9bb189697ac647dc4eba624f7759e927f076361283716ca9a9
"""
VALID_CACHE_PROPERTIES = br"""# mirror state
prefix=nvdcve-
cache.is.new=false
lastModifiedDate=2026-08-22T11\:16\:54Z
lastModifiedDate.modified=2026-08-22T11\:16\:54Z
""" + "".join(
    f"lastModifiedDate.{year}=2026-08-22T11\\:16\\:54Z\n"
    for year in range(2002, 2027)
).encode("ascii")


def valid_fetch(url, _timeout):
    if url.endswith("cache.properties"):
        return VALID_CACHE_PROPERTIES
    return VALID_METADATA


class NvdFeedPreflightTests(FixtureTestCase):
    def test_accepts_fresh_strict_metadata(self):
        seen = []

        def fetch(url, timeout):
            seen.append((url, timeout))
            return valid_fetch(url, timeout)

        result = nvdfeed.check(
            self.fixture.root,
            fetcher=fetch,
            now=datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["max_age_hours"], 48)
        self.assertEqual(result["feed_gzip_size"], 2944874)
        self.assertEqual(
            result["declared_feed_sha256"],
            "6ddffe4a20db0e9bb189697ac647dc4eba624f7759e927f076361283716ca9a9",
        )
        self.assertNotIn("feed_sha256", result)
        self.assertEqual(
            seen,
            [
                (
                    "https://dependency-check.github.io/DependencyCheck_Builder/"
                    "nvd_cache/nvdcve-modified.meta",
                    20,
                ),
                (
                    "https://dependency-check.github.io/DependencyCheck_Builder/"
                    "nvd_cache/cache.properties",
                    20,
                ),
            ],
        )

    def test_rejects_stale_metadata(self):
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "older than 48 hours"):
            nvdfeed.check(
                self.fixture.root,
                fetcher=valid_fetch,
                now=datetime(2026, 8, 25, 12, 0, tzinfo=UTC),
            )

    def test_rejects_metadata_even_one_millisecond_past_freshness_limit(self):
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "older than 48 hours"):
            nvdfeed.check(
                self.fixture.root,
                fetcher=valid_fetch,
                now=datetime(2026, 8, 24, 11, 16, 54, 448000, tzinfo=UTC),
            )

    def test_rejects_future_metadata(self):
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "future"):
            nvdfeed.check(
                self.fixture.root,
                fetcher=valid_fetch,
                now=datetime(2026, 8, 22, 11, 0, tzinfo=UTC),
            )

    def test_rejects_metadata_even_one_millisecond_past_future_tolerance(self):
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "future"):
            nvdfeed.check(
                self.fixture.root,
                fetcher=valid_fetch,
                now=datetime(2026, 8, 22, 11, 11, 54, 446000, tzinfo=UTC),
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
                fetcher=valid_fetch,
                now=datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
            )

    def test_rejects_cache_properties_that_disagrees_with_modified_metadata(self):
        stale_cache = VALID_CACHE_PROPERTIES.replace(
            b"2026-08-22T11\\:16\\:54Z", b"2026-08-22T10\\:16\\:54Z"
        )

        def fetch(url, _timeout):
            return stale_cache if url.endswith("cache.properties") else VALID_METADATA

        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "timestamps disagree"):
            nvdfeed.check(
                self.fixture.root,
                fetcher=fetch,
                now=datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
            )

    def test_rejects_an_escaped_cache_properties_key(self):
        escaped_key = VALID_CACHE_PROPERTIES.replace(
            b"lastModifiedDate.2002=", b"lastModifiedDate\\.2002=", 1
        )
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "key.*unsupported escape"):
            nvdfeed.parse_cache_properties(escaped_key)

    def test_rejects_a_leading_whitespace_java_canonical_duplicate(self):
        canonical_duplicate = (
            VALID_CACHE_PROPERTIES
            + b" lastModifiedDate=2000-01-01T00\\:00\\:00Z\n"
        )
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "unsupported field"):
            nvdfeed.parse_cache_properties(canonical_duplicate)

    def test_rejects_a_missing_historical_feed_year(self):
        missing_year = VALID_CACHE_PROPERTIES.replace(
            b"lastModifiedDate.2014=2026-08-22T11\\:16\\:54Z\n", b"", 1
        )
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "lastModifiedDate.2014"):
            nvdfeed.parse_cache_properties(missing_year)

    def test_rejects_a_malformed_historical_feed_timestamp(self):
        malformed_year = VALID_CACHE_PROPERTIES.replace(
            b"lastModifiedDate.2014=2026-08-22T11\\:16\\:54Z",
            b"lastModifiedDate.2014=not-a-timestampZ",
            1,
        )
        with self.assertRaisesRegex(nvdfeed.FeedPreflightError, "valid ISO-8601"):
            nvdfeed.parse_cache_properties(malformed_year)

    def test_rejects_redirect_before_contacting_same_or_cross_origin_target(self):
        target_requests = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib handler API
                target_requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(VALID_METADATA)

            def log_message(self, _format, *args):
                return

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        target_thread = Thread(target=target.serve_forever, daemon=True)
        target_thread.start()
        try:
            for destination in ("/target", f"http://127.0.0.1:{target.server_port}/target"):
                seen = []

                class RedirectHandler(BaseHTTPRequestHandler):
                    def do_GET(self):  # noqa: N802 - stdlib handler API
                        seen.append(self.path)
                        if self.path == "/start":
                            self.send_response(302)
                            self.send_header("Location", destination)
                            self.end_headers()
                            return
                        target_requests.append(self.path)
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(VALID_METADATA)

                    def log_message(self, _format, *args):
                        return

                redirector = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
                redirect_thread = Thread(target=redirector.serve_forever, daemon=True)
                redirect_thread.start()
                try:
                    with self.assertRaisesRegex(nvdfeed.FeedUnavailable, "redirects are forbidden"):
                        nvdfeed._download_metadata(
                            f"http://127.0.0.1:{redirector.server_port}/start", 2
                        )
                finally:
                    redirector.shutdown()
                    redirector.server_close()
                    redirect_thread.join(timeout=2)
                self.assertEqual(seen, ["/start"])
            self.assertEqual(target_requests, [])
        finally:
            target.shutdown()
            target.server_close()
            target_thread.join(timeout=2)

    def test_rejects_oversized_http_response(self):
        class OversizedHandler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib handler API
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"x" * (nvdfeed.MAX_METADATA_BYTES + 1))

            def log_message(self, _format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), OversizedHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaisesRegex(nvdfeed.FeedUnavailable, "byte limit"):
                nvdfeed._download_metadata(
                    f"http://127.0.0.1:{server.server_port}/modified.meta", 2
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_rejects_non_success_http_status(self):
        class UnavailableHandler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib handler API
                self.send_response(503)
                self.end_headers()

            def log_message(self, _format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), UnavailableHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaisesRegex(nvdfeed.FeedUnavailable, "HTTPError"):
                nvdfeed._download_metadata(
                    f"http://127.0.0.1:{server.server_port}/modified.meta", 2
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
