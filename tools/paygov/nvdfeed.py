"""Fail-closed freshness preflight for the governed OWASP NVD data feed.

Dependency-Check validates and imports the feed itself.  This preflight has a
smaller, separate responsibility: refuse to start an expensive aggregate scan
when the official mirror's ``modified`` metadata or Dependency-Check cache
manifest is unavailable, inconsistent, malformed, or older than the governed
freshness budget.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
# ``datetime.UTC`` was added in Python 3.11; the governed compatibility floor
# is Python 3.10, where ``timezone.utc`` is the portable equivalent.
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .repo import load_json, repo_root

CATALOG = Path("governance/version-catalog.json")
ENTRY_ID = "owasp-dependency-check"
DATAFEED_URL = (
    "https://dependency-check.github.io/DependencyCheck_Builder/"
    "nvd_cache/nvdcve-{0}.json.gz"
)
DATAFEED_DOCUMENTATION = (
    "https://dependency-check.github.io/DependencyCheck/data/mirrornvd.html"
)
MAX_AGE_HOURS = 48
REQUEST_TIMEOUT_SECONDS = 20
MAX_METADATA_BYTES = 4096
FUTURE_TOLERANCE_SECONDS = 300
SHA256 = re.compile(r"^[a-f0-9]{64}$")
EXPECTED_POLICY = {
    "url_template": DATAFEED_URL,
    "documentation": DATAFEED_DOCUMENTATION,
    "max_age_hours": MAX_AGE_HOURS,
    "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
}


class FeedPreflightError(RuntimeError):
    """Base class for deterministic, user-facing preflight failures."""

    code = "NVD_FEED_REJECTED"


class FeedPolicyError(FeedPreflightError):
    code = "NVD_FEED_POLICY"


class FeedUnavailable(FeedPreflightError):
    code = "NVD_FEED_UNAVAILABLE"


class _RejectRedirects(HTTPRedirectHandler):
    """Reject redirects before urllib can contact the advertised target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise FeedUnavailable("metadata endpoint redirects are forbidden")


def _policy(root: Path) -> dict:
    document = load_json(root / CATALOG)
    entries = document.get("entries") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise FeedPolicyError("version catalogue entries are missing")
    entry = next(
        (candidate for candidate in entries
         if isinstance(candidate, dict) and candidate.get("id") == ENTRY_ID),
        None,
    )
    if not isinstance(entry, dict):
        raise FeedPolicyError(f"version catalogue entry '{ENTRY_ID}' is missing")
    policy = entry.get("datafeed_policy")
    if policy != EXPECTED_POLICY:
        raise FeedPolicyError("the OWASP NVD data-feed policy is absent or not exact")
    return policy


def metadata_url(template: str) -> str:
    suffix = "{0}.json.gz"
    if template.count("{0}") != 1 or not template.endswith(suffix):
        raise FeedPolicyError("data-feed URL must end in the single placeholder '{0}.json.gz'")
    return template[: -len(suffix)] + "modified.meta"


def cache_properties_url(template: str) -> str:
    suffix = "nvdcve-{0}.json.gz"
    if template.count("{0}") != 1 or not template.endswith(suffix):
        raise FeedPolicyError(
            "data-feed URL must end in the single filename template "
            "'nvdcve-{0}.json.gz'"
        )
    return template[: -len(suffix)] + "cache.properties"


def _download_metadata(url: str, timeout_seconds: int) -> bytes:
    request = Request(
        url,
        headers={
            "Accept": "text/plain",
            "User-Agent": "elmpay-nvd-feed-preflight/1.0",
        },
    )
    try:
        opener = build_opener(_RejectRedirects())
        with opener.open(request, timeout=timeout_seconds) as response:  # noqa: S310
            status = getattr(response, "status", None)
            final_url = response.geturl()
            if status != 200:
                raise FeedUnavailable(f"metadata endpoint returned HTTP {status}")
            if final_url != url:
                raise FeedUnavailable("metadata endpoint redirected outside the governed URL")
            content = response.read(MAX_METADATA_BYTES + 1)
    except FeedPreflightError:
        raise
    except HTTPError as exc:
        # HTTPError is also a file-like response; close it explicitly so a
        # rejected feed cannot leak a socket or tempfile descriptor.
        try:
            raise FeedUnavailable(f"metadata request failed: {type(exc).__name__}") from exc
        finally:
            exc.close()
    except (URLError, TimeoutError, OSError) as exc:
        raise FeedUnavailable(f"metadata request failed: {type(exc).__name__}") from exc
    if len(content) > MAX_METADATA_BYTES:
        raise FeedUnavailable("metadata response exceeds the byte limit")
    return content


def parse_metadata(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FeedPreflightError("metadata is not valid UTF-8") from exc
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        if not raw_line or ":" not in raw_line:
            raise FeedPreflightError("metadata contains a malformed line")
        key, value = raw_line.split(":", 1)
        if key in values:
            raise FeedPreflightError(f"metadata contains duplicate field '{key}'")
        values[key] = value
    required = {"lastModifiedDate", "size", "gzSize", "sha256"}
    if set(values) != required:
        raise FeedPreflightError("metadata fields do not match the governed schema")
    if not SHA256.fullmatch(values["sha256"]):
        raise FeedPreflightError("metadata sha256 is not 64 lowercase hexadecimal characters")
    for key in ("size", "gzSize"):
        try:
            amount = int(values[key])
        except ValueError as exc:
            raise FeedPreflightError(f"metadata field '{key}' is not an integer") from exc
        if amount <= 0:
            raise FeedPreflightError(f"metadata field '{key}' must be positive")
    return values


def parse_cache_properties(content: bytes) -> dict[str, str]:
    """Parse only the strict Java-properties subset published by the mirror."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FeedPreflightError("cache.properties is not valid UTF-8") from exc
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        if not raw_line or raw_line.startswith(("#", "!")):
            continue
        if "=" not in raw_line:
            raise FeedPreflightError("cache.properties contains a malformed line")
        key, value = raw_line.split("=", 1)
        if "\\" in key:
            raise FeedPreflightError(
                f"cache.properties key '{key}' contains an unsupported escape"
            )
        if not key or key in values:
            raise FeedPreflightError(
                f"cache.properties contains duplicate or empty field '{key}'"
            )
        if "\\" in value.replace("\\:", ""):
            raise FeedPreflightError(
                f"cache.properties field '{key}' contains an unsupported escape"
            )
        values[key] = value.replace("\\:", ":")
    required = {
        "prefix",
        "cache.is.new",
        "lastModifiedDate",
        "lastModifiedDate.modified",
    }
    if not required.issubset(values):
        raise FeedPreflightError("cache.properties is missing governed fields")
    if values["prefix"] != "nvdcve-" or values["cache.is.new"] != "false":
        raise FeedPreflightError("cache.properties does not describe the governed ready cache")
    current = _parse_timestamp(values["lastModifiedDate"])
    modified = _parse_timestamp(values["lastModifiedDate.modified"])
    if current != modified:
        raise FeedPreflightError("cache.properties modified timestamps disagree")
    feed_year_keys = [
        f"lastModifiedDate.{year}" for year in range(2002, current.year + 1)
    ]
    missing_year_keys = [key for key in feed_year_keys if key not in values]
    if missing_year_keys:
        raise FeedPreflightError(
            "cache.properties is missing continuous feed-year field "
            f"'{missing_year_keys[0]}'"
        )
    expected_keys = required | set(feed_year_keys)
    unexpected_keys = sorted(set(values) - expected_keys)
    if unexpected_keys:
        raise FeedPreflightError(
            "cache.properties contains unsupported field "
            f"'{unexpected_keys[0]}'"
        )
    for key in feed_year_keys:
        _parse_timestamp(values[key])
    year_key = f"lastModifiedDate.{current.year}"
    if values.get(year_key) != values["lastModifiedDate"]:
        raise FeedPreflightError(
            f"cache.properties current-year timestamp '{year_key}' disagrees"
        )
    return values


def _parse_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise FeedPreflightError("lastModifiedDate must be an explicit UTC timestamp")
    try:
        timestamp = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise FeedPreflightError("lastModifiedDate is not a valid ISO-8601 timestamp") from exc
    if timestamp.tzinfo != UTC:
        raise FeedPreflightError("lastModifiedDate must use UTC")
    return timestamp


def check(
    root: Path,
    *,
    fetcher: Callable[[str, int], bytes] = _download_metadata,
    now: datetime | None = None,
) -> dict:
    policy = _policy(root)
    url = metadata_url(policy["url_template"])
    metadata = parse_metadata(fetcher(url, policy["request_timeout_seconds"]))
    modified = _parse_timestamp(metadata["lastModifiedDate"])
    cache_url = cache_properties_url(policy["url_template"])
    cache = parse_cache_properties(fetcher(cache_url, policy["request_timeout_seconds"]))
    cache_modified = _parse_timestamp(cache["lastModifiedDate.modified"])
    if cache_modified != modified.replace(microsecond=0):
        raise FeedPreflightError(
            "modified metadata and Dependency-Check cache.properties timestamps disagree"
        )
    checked_at = now or datetime.now(UTC)
    if checked_at.tzinfo != UTC:
        raise FeedPreflightError("preflight clock must use UTC")
    age = checked_at - modified
    if age < -timedelta(seconds=FUTURE_TOLERANCE_SECONDS):
        raise FeedPreflightError("feed metadata timestamp is implausibly in the future")
    if age > timedelta(hours=policy["max_age_hours"]):
        raise FeedPreflightError(
            f"feed metadata is older than {policy['max_age_hours']} hours"
        )
    age_seconds = int(age.total_seconds())
    return {
        "ok": True,
        "feed_url_template": policy["url_template"],
        "metadata_url": url,
        "cache_properties_url": cache_url,
        "feed_last_modified": metadata["lastModifiedDate"],
        "cache_last_modified": cache["lastModifiedDate.modified"],
        "feed_age_seconds": age_seconds,
        "max_age_hours": policy["max_age_hours"],
        "declared_feed_sha256": metadata["sha256"],
        "feed_size": int(metadata["size"]),
        "feed_gzip_size": int(metadata["gzSize"]),
        "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
    }


def _render(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nvd-feed-preflight",
        description="fail closed when the governed OWASP NVD data feed is stale or unavailable",
    )
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--out", help="atomically write the JSON result inside the repository")
    args = parser.parse_args(argv)
    try:
        root = repo_root(Path(args.repo).resolve())
        payload = check(root)
        code = 0
    except FeedPreflightError as exc:
        root = Path(args.repo).resolve()
        payload = {"ok": False, "code": exc.code, "message": str(exc)}
        code = 3 if isinstance(exc, FeedUnavailable) else 2
    except Exception as exc:  # noqa: BLE001 - unexpected preflight errors fail closed
        root = Path(args.repo).resolve()
        payload = {
            "ok": False,
            "code": "NVD_FEED_CRASHED",
            "message": f"{type(exc).__name__}: {exc}",
        }
        code = 3
    output = _render(payload)
    if args.out:
        try:
            from .cli import _write_report

            _write_report(root, args.out, output)
        except Exception as exc:  # noqa: BLE001 - missing evidence must fail closed
            print(_render({
                "ok": False,
                "code": "NVD_FEED_REPORT_WRITE",
                "message": f"{type(exc).__name__}: {exc}",
            }))
            return 3
    print(output)
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
