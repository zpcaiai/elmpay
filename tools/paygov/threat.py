"""B02 — threat model and residual risk ledger validation.

Two properties are enforced that prose cannot enforce on its own:

* every abuse case listed upstream has a local entry with adversaries, assets,
  controls and mitigating batches that actually exist;
* every accepted residual risk has a named owner, verifiable compensating
  controls, a review batch and a *future* due date. An expired exception makes
  the gate fail (NN-15), which is the only way a deadline means anything.
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any

from . import catalogue
from .errors import BudgetExceeded, Problem
from .repo import Budget, load_json, read_text
from .structs import BATCH_ID, ISO_DATE, SEMVER, expect

PATH = Path("governance/threat-model.json")
UPSTREAM = Path(".payment-platform/skill-package/security/THREAT_MODEL.md")
UPSTREAM_ITEM = re.compile(r"^\d+\.\s+\S", re.MULTILINE)

VALID_CLASSIFICATION = {"secret", "identity", "financial", "business-critical",
                        "personal-data", "supply-chain", "governance"}
VALID_ABUSE_STATUS = {"mitigated", "planned", "accepted"}
# 'critical' is intentionally absent: a critical residual risk may not be accepted.
VALID_SEVERITY = {"high", "medium", "low"}
PLACEHOLDER_OWNERS = {"", "tbd", "TBD", "unknown", "待定"}


def validate(root: Path, budget: Budget | None = None, today: date | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    today = today or date.today()
    where = str(PATH)
    try:
        doc: Any = load_json(root / PATH, budget)
    except BudgetExceeded:
        raise
    except Exception as exc:
        return [Problem("THREAT_UNREADABLE", where, str(exc), "NN-12")]

    problems: list[Problem] = []
    problems += expect(bool(SEMVER.match(str(doc.get("schema_version", "")))),
                       "THREAT_VERSION", where, "schema_version must be semantic version", "NN-12")

    sections = ("zones", "assets", "trust_boundaries", "adversaries", "abuse_cases", "residual_risks")
    for name in sections:
        if not isinstance(doc.get(name), list) or not doc[name]:
            problems.append(Problem("THREAT_SHAPE", where, f"'{name}' must be a non-empty array",
                                    "NN-12"))
    if problems and any(p.code == "THREAT_SHAPE" for p in problems):
        return problems

    known_modules = catalogue.module_names(str(root))
    known_batches = catalogue.batch_ids(str(root))
    known_controls = catalogue.control_ids(str(root))
    known_rules = catalogue.non_negotiable_ids(str(root))

    zone_ids = {z["id"] for z in doc["zones"]}
    asset_ids = {a["id"] for a in doc["assets"]}
    adversary_ids = {a["id"] for a in doc["adversaries"]}

    for asset in doc["assets"]:
        scope = f"{where}#{asset.get('id', '?')}"
        problems += expect(asset.get("classification") in VALID_CLASSIFICATION,
                           "THREAT_ASSET", scope,
                           f"classification must be one of {sorted(VALID_CLASSIFICATION)}", "NN-12")
        problems += expect(str(asset.get("owner", "")).strip() not in PLACEHOLDER_OWNERS,
                           "THREAT_ASSET", scope, "asset must have a named owner", "NN-11")
        problems += expect(isinstance(asset.get("threats"), list) and bool(asset["threats"]),
                           "THREAT_ASSET", scope, "asset must list at least one threat", "NN-12")
        for module in asset.get("modules", []):
            problems += expect(module in known_modules, "THREAT_ASSET", scope,
                               f"unknown module '{module}'", "NN-12")

    for boundary in doc["trust_boundaries"]:
        scope = f"{where}#{boundary.get('id', '?')}"
        between = boundary.get("between")
        problems += expect(isinstance(between, list) and len(between) == 2,
                           "THREAT_BOUNDARY", scope, "'between' must name exactly two zones", "NN-12")
        for zone in between or []:
            problems += expect(zone in zone_ids, "THREAT_BOUNDARY", scope,
                               f"unknown zone '{zone}'", "NN-12")
        controls = boundary.get("controls")
        problems += expect(isinstance(controls, list) and bool(controls), "THREAT_BOUNDARY", scope,
                           "each trust boundary must name at least one control", "NN-12")
        for control in controls or []:
            problems += expect(control in known_controls or control in known_rules,
                               "THREAT_BOUNDARY", scope, f"unknown control '{control}'", "NN-12")

    accepted_cases: set[str] = set()
    case_ids: set[str] = set()
    for index, case in enumerate(doc["abuse_cases"], 1):
        cid = case.get("id", "?")
        scope = f"{where}#{cid}"
        case_ids.add(cid)
        problems += expect(cid == f"AC-{index:02d}", "THREAT_ABUSE_ID", scope,
                           f"abuse case ids must be dense and ordered; expected AC-{index:02d}",
                           "NN-12")
        problems += expect(len(str(case.get("title", "")).strip()) >= 6, "THREAT_ABUSE", scope,
                           "abuse case needs a descriptive title", "NN-12")
        problems += expect(case.get("status") in VALID_ABUSE_STATUS, "THREAT_ABUSE", scope,
                           f"status must be one of {sorted(VALID_ABUSE_STATUS)}", "NN-12")
        if case.get("status") == "accepted":
            accepted_cases.add(cid)
        for field, universe, label in (("adversaries", adversary_ids, "adversary"),
                                       ("assets", asset_ids, "asset")):
            values = case.get(field)
            problems += expect(isinstance(values, list) and bool(values), "THREAT_ABUSE", scope,
                               f"abuse case must reference at least one {label}", "NN-12")
            for value in values or []:
                problems += expect(value in universe, "THREAT_ABUSE", scope,
                                   f"unknown {label} '{value}'", "NN-12")
        controls = case.get("controls")
        problems += expect(isinstance(controls, list) and bool(controls), "THREAT_ABUSE", scope,
                           "abuse case must reference at least one control", "NN-12")
        for control in controls or []:
            problems += expect(control in known_controls or control in known_rules,
                               "THREAT_ABUSE", scope, f"unknown control '{control}'", "NN-12")
        batches = case.get("mitigating_batches")
        problems += expect(isinstance(batches, list) and bool(batches), "THREAT_ABUSE", scope,
                           "abuse case must name the batches that mitigate it", "NN-12")
        for batch in batches or []:
            problems += expect(bool(BATCH_ID.match(str(batch))) and batch in known_batches,
                               "THREAT_ABUSE", scope, f"unknown batch '{batch}'", "NN-12")

    problems += _upstream_parity(root, doc["abuse_cases"], where, budget)

    covered_by_risk: set[str] = set()
    for risk in doc["residual_risks"]:
        rid = risk.get("id", "?")
        scope = f"{where}#{rid}"
        severity = risk.get("severity")
        problems += expect(severity in VALID_SEVERITY, "THREAT_RISK_SEVERITY", scope,
                           "a residual risk may not be 'critical'; critical findings must be fixed",
                           "NN-15")
        problems += expect(str(risk.get("owner", "")).strip() not in PLACEHOLDER_OWNERS,
                           "THREAT_RISK_OWNER", scope,
                           "an accepted risk must have a named owner", "NN-15")
        controls = risk.get("compensating_controls")
        problems += expect(isinstance(controls, list) and bool(controls),
                           "THREAT_RISK_CONTROL", scope,
                           "an accepted risk must list compensating controls", "NN-15")
        due = str(risk.get("due_date", ""))
        if not ISO_DATE.match(due):
            problems.append(Problem("THREAT_RISK_DUE", scope,
                                    "due_date must be ISO-8601 (YYYY-MM-DD)", "NN-15"))
        else:
            problems += expect(date.fromisoformat(due) >= today, "THREAT_RISK_EXPIRED", scope,
                               f"security exception expired on {due}; it must be re-reviewed or "
                               f"the risk must be fixed", "NN-15", due_date=due,
                               today=today.isoformat())
        review = risk.get("review_batch", "")
        problems += expect(bool(BATCH_ID.match(str(review))) and review in known_batches,
                           "THREAT_RISK_REVIEW", scope,
                           f"review_batch '{review}' is not a batch in the manifest", "NN-15")
        for case in risk.get("related_abuse_cases", []):
            problems += expect(case in case_ids, "THREAT_RISK_LINK", scope,
                               f"unknown abuse case '{case}'", "NN-12")
            covered_by_risk.add(case)

    for cid in sorted(accepted_cases - covered_by_risk):
        problems.append(Problem("THREAT_ACCEPTED_UNTRACKED", f"{where}#{cid}",
                                "an abuse case marked 'accepted' must be tracked by a residual risk "
                                "entry with an owner and a due date", "NN-15"))
    return problems


def _upstream_parity(root: Path, cases: list, where: str, budget: Budget) -> list[Problem]:
    path = root / UPSTREAM
    if not path.is_file():
        return [Problem("THREAT_UPSTREAM_MISSING", str(UPSTREAM),
                        "upstream threat model is missing; cannot prove abuse-case parity", "NN-12")]
    text = read_text(path, budget)
    section = text.split("## 必须覆盖的滥用案例", 1)
    if len(section) != 2:
        return [Problem("THREAT_UPSTREAM_MISSING", str(UPSTREAM),
                        "upstream abuse-case section not found", "NN-12")]
    upstream_count = len(UPSTREAM_ITEM.findall(section[1]))
    return expect(upstream_count == len(cases), "THREAT_PARITY", where,
                  f"upstream defines {upstream_count} abuse cases but the local model has "
                  f"{len(cases)}", "NN-12")
