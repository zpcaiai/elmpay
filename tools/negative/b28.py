"""B28 negative controls — the four ways routing stops being explainable."""
from __future__ import annotations

from . import EXIT_PROBLEMS

REL = "governance/routing-policy.json"
AUTHZ = "governance/authorization.json"


def _rule(d, rid):
    return next(r for r in d["rules"] if r["id"] == rid)


def _factor(d, fid):
    return next(f for f in d["scoring"]["factors"] if f["id"] == fid)


EXPECTED_CODES = {
    "B28 the same payment may route differently twice": "ROUTE_NONDETERMINISTIC",
    "B28 routing may pick a provider at random": "ROUTE_NONDETERMINISTIC",
    "B28 decisions stop recording their configuration version":
        "ROUTE_DECISION_UNVERSIONED",
    "B28 a published configuration version becomes editable": "ROUTE_VERSION_MUTABLE",
    "B28 one person activates a routing configuration": "ROUTE_ACTIVATION_SINGLE_PERSON",
    "B28 the activation permission drops dual control": "ROUTE_ACTIVATION_SINGLE_PERSON",
    "B28 too few versions are kept to roll back to": "ROUTE_HISTORY_TOO_SHORT",
    "B28 a decision becomes unreplayable": "ROUTE_UNREPLAYABLE",
    "B28 ties are broken by nothing in particular": "ROUTE_NO_TIE_BREAK",
    "B28 two rules share a priority": "ROUTE_PRIORITY_COLLISION",
    "B28 a rule routes to a provider that cannot serve it": "ROUTE_TARGET_INCAPABLE",
    "B28 a rule routes to a provider with no binding": "ROUTE_PROVIDER_UNKNOWN",
    "B28 a rule loses its amount ceiling": "ROUTE_NO_AMOUNT_CEILING",
    "B28 scoring loses the risk factor": "ROUTE_NO_FACTORS",
    "B28 factor weights stop summing to 100": "ROUTE_WEIGHTS_UNNORMALISED",
    "B28 a provider is judged on ten payments": "ROUTE_SAMPLE_TOO_SMALL",
    "B28 the exploration floor is removed": "ROUTE_NO_EXPLORATION",
    "B28 the starvation guard is switched off": "ROUTE_NO_EXPLORATION",
    "B28 the canary splits on a random number": "ROUTE_RANDOM_SPLIT",
    "B28 the canary splits on the user instead of the payment": "ROUTE_SPLIT_KEY",
    "B28 the canary promotes itself": "ROUTE_AUTO_PROMOTE",
    "B28 rollback becomes a new release": "ROUTE_ROLLBACK_IS_A_RELEASE",
    "B28 rollback is gated behind an approval": "ROUTE_ROLLBACK_GATED",
    "B28 the shadow evaluator may move money": "ROUTE_SHADOW_MOVES_MONEY",
    "B28 a retry may change provider": "ROUTE_RETRY_CHANGES_PROVIDER",
    "B28 a retry gets a fresh idempotency key": "ROUTE_RETRY_NEW_KEY",
    "B28 routing changes map to a nonexistent audit class": "ROUTE_AUDIT_CLASS_UNKNOWN",
    "B28 routing document hand-edited": "ROUTE_GENERATED_DRIFT",
}

SCENARIOS = [
    ("B28 the same payment may route differently twice", REL,
     lambda d: d["determinism"].__setitem__("same_inputs_same_decision", False),
     EXIT_PROBLEMS),
    ("B28 routing may pick a provider at random", REL,
     lambda d: d["determinism"].__setitem__("random_selection_allowed", True), EXIT_PROBLEMS),
    ("B28 decisions stop recording their configuration version", REL,
     lambda d: d["config_versioning"].__setitem__("decision_records_config_version", False),
     EXIT_PROBLEMS),
    ("B28 a published configuration version becomes editable", REL,
     lambda d: d["config_versioning"].__setitem__("versions_are_immutable", False),
     EXIT_PROBLEMS),
    ("B28 one person activates a routing configuration", REL,
     lambda d: d["config_versioning"].__setitem__("activation_approvers_required", 1),
     EXIT_PROBLEMS),
    ("B28 the activation permission drops dual control", AUTHZ,
     lambda d: next(p for p in d["permissions"] if p["id"] == "config.write")
     .__setitem__("dual_control", False), EXIT_PROBLEMS),
    ("B28 too few versions are kept to roll back to", REL,
     lambda d: d["config_versioning"].__setitem__("retain_versions", 2), EXIT_PROBLEMS),
    ("B28 a decision becomes unreplayable", REL,
     lambda d: d["determinism"].__setitem__("replayable", False), EXIT_PROBLEMS),
    ("B28 ties are broken by nothing in particular", REL,
     lambda d: d["determinism"].__setitem__("tie_break", "whatever"), EXIT_PROBLEMS),
    ("B28 two rules share a priority", REL,
     lambda d: _rule(d, "eu_cards").__setitem__("priority", _rule(d, "hk_cards")["priority"]),
     EXIT_PROBLEMS),
    ("B28 a rule routes to a provider that cannot serve it", REL,
     lambda d: _rule(d, "eu_cards").__setitem__("prefer", ["wechat"]), EXIT_PROBLEMS),
    ("B28 a rule routes to a provider with no binding", REL,
     lambda d: _rule(d, "eu_cards").__setitem__("prefer", ["klarna"]), EXIT_PROBLEMS),
    ("B28 a rule loses its amount ceiling", REL,
     lambda d: _rule(d, "eu_cards")["when"].__setitem__("max_amount_minor", 0), EXIT_PROBLEMS),
    ("B28 scoring loses the risk factor", REL,
     lambda d: d["scoring"].__setitem__("factors", [f for f in d["scoring"]["factors"]
                                                    if f["id"] != "risk"]), EXIT_PROBLEMS),
    ("B28 factor weights stop summing to 100", REL,
     lambda d: _factor(d, "cost").__setitem__("weight", 31), EXIT_PROBLEMS),
    ("B28 a provider is judged on ten payments", REL,
     lambda d: d["scoring"].__setitem__("min_sample", 10), EXIT_PROBLEMS),
    ("B28 the exploration floor is removed", REL,
     lambda d: d["scoring"].__setitem__("exploration_floor_percent", 0), EXIT_PROBLEMS),
    ("B28 the starvation guard is switched off", REL,
     lambda d: d["scoring"].__setitem__("starvation_guard", False), EXIT_PROBLEMS),
    ("B28 the canary splits on a random number", REL,
     lambda d: d["canary"].__setitem__("random_split_allowed", True), EXIT_PROBLEMS),
    ("B28 the canary splits on the user instead of the payment", REL,
     lambda d: d["canary"].__setitem__("split_key", "user_id"), EXIT_PROBLEMS),
    ("B28 the canary promotes itself", REL,
     lambda d: d["canary"].__setitem__("auto_promote", True), EXIT_PROBLEMS),
    ("B28 rollback becomes a new release", REL,
     lambda d: d["rollback"].__setitem__("to_existing_version_only", False), EXIT_PROBLEMS),
    ("B28 rollback is gated behind an approval", REL,
     lambda d: d["rollback"].__setitem__("requires_approval", True), EXIT_PROBLEMS),
    ("B28 the shadow evaluator may move money", REL,
     lambda d: d["simulation"].__setitem__("shadow_moves_money", True), EXIT_PROBLEMS),
    ("B28 a retry may change provider", REL,
     lambda d: d["retry"].__setitem__("change_provider_on_retry_allowed", True),
     EXIT_PROBLEMS),
    ("B28 a retry gets a fresh idempotency key", REL,
     lambda d: d["retry"].__setitem__("reuse_idempotency_key", False), EXIT_PROBLEMS),
    ("B28 routing changes map to a nonexistent audit class", REL,
     lambda d: d.__setitem__("audit_event_class", "routing.vanished"), EXIT_PROBLEMS),
]

TEXT_SCENARIOS = [
    ("B28 routing document hand-edited",
     "docs/routing/ROUTING_POLICY.md", "确定性且可重放", "尽量保持一致", EXIT_PROBLEMS),
]
