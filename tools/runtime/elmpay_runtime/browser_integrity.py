"""B85 versioned browser asset allowlist and repository integrity gate."""
from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

from .common import GateReport, ValidationError, canonical_json, parse_instant, read_json, require_list, require_mapping, require_text, sha256_json
from .security_store import SecurityStore


SRI_RE = re.compile(r"^sha384-[A-Za-z0-9+/]{64}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_PRIVILEGES = frozenset({
    "dom:checkout",
    "network:self",
    "security:report",
    "provider-sdk:tokenize",
    "provider-sdk:authorize",
})
REPORT_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
REPORT_REASONS = frozenset({
    "POLICY_UNAVAILABLE", "UNAUTHORIZED_SCRIPT_ELEMENT", "DUPLICATE_SCRIPT_ELEMENT",
    "SCRIPT_SRI_MISMATCH", "ALLOWLISTED_SCRIPT_MISSING",
})


def _asset_path(public_root: Path, source: str) -> Path:
    if not source.startswith("/") or "?" in source or "#" in source or "\\" in source:
        raise ValidationError("script source must be an immutable same-origin absolute path")
    relative = PurePosixPath(source.removeprefix("/"))
    if not relative.parts or ".." in relative.parts or relative.suffix != ".mjs":
        raise ValidationError("script source is not a safe module path")
    result = public_root.joinpath(*relative.parts)
    try:
        result.resolve().relative_to(public_root.resolve())
    except ValueError as exc:
        raise ValidationError("script source leaves the checkout public root") from exc
    return result


def _sri(path: Path) -> str:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise ValidationError(f"allowlisted browser asset is unavailable: {path.name}") from exc
    return "sha384-" + base64.b64encode(hashlib.sha384(content).digest()).decode("ascii")


def validate_script_manifest(
    public_root: str | Path,
    manifest_path: str | Path,
    *,
    now: datetime | None = None,
) -> GateReport:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    reasons: list[str] = []
    checks: list[str] = []
    try:
        root = Path(public_root)
        value = require_mapping(read_json(Path(manifest_path)), "script manifest")
        expected = {
            "schemaVersion", "manifestVersion", "reviewExpiresAt", "pageTemplateSha256",
            "trustedTypesPolicy", "scripts", "externalAssessmentStatus",
        }
        if set(value) != expected or value["schemaVersion"] != 1:
            raise ValidationError("script manifest fields do not match schema version 1")
        version = require_text(value["manifestVersion"], "manifestVersion")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", version):
            raise ValidationError("manifestVersion has an invalid format")
        if parse_instant(value["reviewExpiresAt"], "reviewExpiresAt") <= current:
            reasons.append("SCRIPT_MANIFEST_REVIEW_EXPIRED")
        if value["externalAssessmentStatus"] not in {"BLOCKED", "VERIFIED"}:
            raise ValidationError("external assessment status is invalid")
        if value["trustedTypesPolicy"] != "elmpay-checkout":
            reasons.append("TRUSTED_TYPES_POLICY_MISSING")
        template_digest = require_text(value["pageTemplateSha256"], "pageTemplateSha256")
        if not HASH_RE.fullmatch(template_digest):
            raise ValidationError("pageTemplateSha256 must be lowercase SHA-256")
        template = root / "index.html"
        try:
            actual_template = hashlib.sha256(template.read_bytes()).hexdigest()
        except OSError as exc:
            raise ValidationError("checkout page template is unavailable") from exc
        if actual_template != template_digest:
            reasons.append("CHECKOUT_PAGE_TEMPLATE_DIGEST_MISMATCH")
        scripts = require_list(value["scripts"], "scripts")
        if not scripts:
            reasons.append("SCRIPT_ALLOWLIST_EMPTY")
        identifiers: set[str] = set()
        sources: set[str] = set()
        for index, raw in enumerate(scripts):
            item = require_mapping(raw, f"scripts[{index}]")
            required = {
                "id", "source", "sri", "owner", "purpose", "reviewExpiresAt",
                "thirdParty", "executionContext", "privileges",
            }
            if set(item) != required:
                raise ValidationError(f"scripts[{index}] fields are invalid")
            identifier = require_text(item["id"], f"scripts[{index}].id")
            source = require_text(item["source"], f"scripts[{index}].source")
            if identifier in identifiers or source in sources:
                raise ValidationError("script allowlist ids and sources must be unique")
            identifiers.add(identifier)
            sources.add(source)
            expected_sri = require_text(item["sri"], f"scripts[{index}].sri")
            if not SRI_RE.fullmatch(expected_sri):
                raise ValidationError("script SRI must be a SHA-384 value")
            if not require_text(item["owner"], f"scripts[{index}].owner") or not require_text(
                item["purpose"], f"scripts[{index}].purpose"
            ):
                raise ValidationError("script owner and purpose are required")
            if parse_instant(item["reviewExpiresAt"], f"scripts[{index}].reviewExpiresAt") <= current:
                reasons.append(f"SCRIPT_REVIEW_EXPIRED:{identifier}")
            if not isinstance(item["thirdParty"], bool):
                raise ValidationError("thirdParty must be boolean")
            execution_context = item["executionContext"]
            if item["thirdParty"] and execution_context != "isolated-frame":
                reasons.append(f"THIRD_PARTY_SCRIPT_NOT_ISOLATED:{identifier}")
            if not item["thirdParty"] and execution_context != "main":
                raise ValidationError("first-party script execution context is invalid")
            privileges = require_list(item["privileges"], f"scripts[{index}].privileges")
            if not privileges or any(privilege not in ALLOWED_PRIVILEGES for privilege in privileges):
                raise ValidationError("script privileges are empty or unsupported")
            if _sri(_asset_path(root, source)) != expected_sri:
                reasons.append(f"SCRIPT_DIGEST_MISMATCH:{identifier}")
            checks.append(f"SCRIPT_VERIFIED:{identifier}")
        if "/integrity.mjs" not in sources:
            reasons.append("RUNTIME_INTEGRITY_MONITOR_MISSING")
        if "/checkout.mjs" not in sources:
            reasons.append("CHECKOUT_CONTROLLER_NOT_ALLOWLISTED")
        checks.extend(("CSP_NONCE_REQUIRED", "SRI_SHA384_REQUIRED", "PAGE_TEMPLATE_VERIFIED"))
    except (TypeError, ValidationError):
        return GateReport(False, ("SCRIPT_MANIFEST_INVALID",), ())
    return GateReport.from_reasons(reasons, checks)


def public_script_policy(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the non-sensitive subset the browser integrity monitor consumes."""

    scripts = require_list(manifest.get("scripts"), "scripts")
    return {
        "manifestVersion": require_text(manifest.get("manifestVersion"), "manifestVersion"),
        "trustedTypesPolicy": require_text(manifest.get("trustedTypesPolicy"), "trustedTypesPolicy"),
        "scripts": [
            {
                "source": require_text(require_mapping(item, "script").get("source"), "source"),
                "sri": require_text(require_mapping(item, "script").get("sri"), "sri"),
            }
            for item in scripts
        ],
    }


class BrowserSecurityReportService:
    """Durable, idempotent ingest for already-sanitized checkout reports."""

    def __init__(self, store: SecurityStore, policy_version: str) -> None:
        self.store = store
        self.policy_version = require_text(policy_version, "policy_version")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", self.policy_version):
            raise ValidationError("policy_version has an invalid format")

    def record(
        self,
        deployment_id: str,
        report: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> str:
        deployment = require_text(deployment_id, "deployment_id")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", deployment):
            raise ValidationError("deployment_id has an invalid format")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        safe = self._validate(report, current)
        digest = sha256_json(safe)
        with self.store.transaction() as connection:
            prior = connection.execute(
                "SELECT report_digest FROM browser_security_report WHERE deployment_id=? AND report_id=?",
                (deployment, safe["reportId"]),
            ).fetchone()
            if prior is not None:
                if prior["report_digest"] != digest:
                    raise ValidationError("browser report idempotency conflict")
                return digest
            connection.execute(
                "INSERT INTO browser_security_report VALUES (?,?,?,?,?,?,?,?)",
                (
                    deployment, safe["reportId"], safe["category"], safe["policyVersion"],
                    digest, canonical_json(safe).decode("utf-8"), safe["occurredAt"], current.isoformat(),
                ),
            )
        return digest

    def recent(self, deployment_id: str, *, limit: int = 100) -> tuple[Mapping[str, Any], ...]:
        deployment = require_text(deployment_id, "deployment_id")
        if not 1 <= limit <= 1000:
            raise ValidationError("report limit is outside the safe range")
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT report_json FROM browser_security_report WHERE deployment_id=? "
                "ORDER BY occurred_at DESC,report_id DESC LIMIT ?",
                (deployment, limit),
            ).fetchall()
        return tuple(json.loads(row["report_json"]) for row in rows)

    def _validate(self, report: Mapping[str, Any], current: datetime) -> dict[str, Any]:
        if not isinstance(report, dict):
            raise ValidationError("browser report must be an object")
        common = {"reportId", "occurredAt", "category", "policyVersion"}
        report_id = require_text(report.get("reportId"), "reportId")
        if not REPORT_ID_RE.fullmatch(report_id):
            raise ValidationError("reportId must be a UUID")
        occurred = parse_instant(report.get("occurredAt"), "occurredAt")
        if abs(current - occurred).total_seconds() > 600:
            raise ValidationError("browser report timestamp is outside the accepted window")
        if report.get("policyVersion") != self.policy_version:
            raise ValidationError("browser report policy version mismatch")
        category = report.get("category")
        if category == "BROWSER_INTEGRITY":
            expected = common | {"type", "reasons"}
            if set(report) != expected or report.get("type") not in {
                "PAGE_INTEGRITY", "PAGE_MUTATION", "POLICY_UNAVAILABLE",
            }:
                raise ValidationError("browser integrity report fields are invalid")
            reasons = report.get("reasons")
            if (
                not isinstance(reasons, list) or not 1 <= len(reasons) <= 16
                or any(reason not in REPORT_REASONS for reason in reasons)
            ):
                raise ValidationError("browser integrity reasons are invalid")
        elif category == "CSP":
            expected = common | {"directive", "disposition", "document", "blocked"}
            if set(report) != expected or not re.fullmatch(r"[a-z-]{3,64}", str(report.get("directive", ""))):
                raise ValidationError("CSP report fields are invalid")
            if report.get("disposition") not in {"enforce", "report"}:
                raise ValidationError("CSP disposition is invalid")
            for field in ("document", "blocked"):
                value = report.get(field)
                if value is not None and (
                    not isinstance(value, str) or len(value) > 512 or "?" in value or "#" in value
                    or not value.startswith(("https://", "http://"))
                ):
                    raise ValidationError(f"CSP {field} URL is not sanitized")
        else:
            raise ValidationError("browser report category is invalid")
        return dict(report)
