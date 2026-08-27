"""B34 — derive the capture-lifecycle conformance vectors from the model.

The vectors are not hand-written examples. They are the governance model and
the reference implementation applied to one another, so a rule that is relaxed
in ``governance/capture-lifecycle.json`` cannot leave the vectors behind
agreeing with the old rule. Every language implementation replays this file;
the Java one does it in ``CaptureLifecycleVectorsTest``.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from .repo import Budget, load_json

MODEL = Path("governance/capture-lifecycle.json")
CAPS = Path("governance/provider-capabilities.json")
REFERENCE = Path("libs/capture/reference/capture.py")

AUTHORIZED = 1000
PARTIAL = 600
SECOND = 400


def _reference(root: Path):
    """Load the reference by path, never through ``sys.modules``.

    Importing ``libs.capture.reference.capture`` would resolve to whichever copy
    was imported first. Inside a disposable fixture repository that is the real
    repository's copy, so a deliberately broken fixture would be validated by
    working code and pass. Same defect, same fix, as B09's money generator.
    """
    path = root / REFERENCE
    key = "capture_reference_" + hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(key, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load the capture reference at {path}")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _profiles(root: Path, budget: Budget | None = None) -> list[dict]:
    """One profile per distinct capability triple, labelled by who shares it."""
    caps = load_json(root / CAPS)
    grouped: dict[tuple, list[str]] = {}
    for entry in caps.get("capabilities") or []:
        if not isinstance(entry, dict):
            continue
        key = (bool(entry.get("supports_authorization_capture")),
               bool(entry.get("partial_capture")),
               int(entry.get("authorization_valid_hours") or 0))
        label = f"{entry.get('provider')}:{entry.get('method')}"
        grouped.setdefault(key, []).append(label)
    profiles = []
    for (auth_capture, partial, hours), members in sorted(
            grouped.items(), key=lambda kv: (kv[0], sorted(kv[1]))):
        profiles.append({
            "id": f"authcapture={int(auth_capture)}.partial={int(partial)}.hours={hours}",
            "supports_authorization_capture": auth_capture,
            "partial_capture": partial,
            "authorization_valid_hours": hours,
            "declared_by": sorted(members),
        })
    return profiles


# One capability assumption for every case: a provider that supports deferred and
# partial capture. Which providers those are is B27's matrix, checked separately
# by ``CAPTURE_CAPABILITY_SOURCE``; repeating the same lifecycle verdicts once per
# provider profile would only make the drift check slower, not stricter.
CAPABILITY = {
    "supports_authorization_capture": True,
    "partial_capture": True,
    "authorization_valid_hours": 168,
}

# ``initial_state`` is the intent state the sequence starts from, so an
# implementation replays it against its own state machine rather than against a
# second copy of this table. ``created`` exists only for the immediate path,
# where authorisation and capture are one provider call.
SEQUENCES: tuple[tuple[str, str, tuple[dict, ...], str], ...] = (
    ("immediate-full-capture", "created",
     ({"op": "capture", "amount_minor": AUTHORIZED},),
     "确认即全额捕获：授权与捕获合为一次调用，没有剩余。"),
    ("deferred-full-capture", "authorized",
     ({"op": "capture", "amount_minor": AUTHORIZED},),
     "先授权后全额捕获，累计等于授权额，授权自然走完。"),
    ("partial-then-close", "authorized",
     ({"op": "capture", "amount_minor": PARTIAL}, {"op": "close"}),
     "本批次存在的理由：部分捕获后显式释放剩余的 400，而不是等它过期。"),
    ("multi-capture-to-full", "authorized",
     ({"op": "capture", "amount_minor": PARTIAL},
      {"op": "capture", "amount_minor": SECOND}),
     "分两次捕获至全额，累计等于授权额，无需关闭。"),
    ("partial-then-void-refused", "authorized",
     ({"op": "capture", "amount_minor": PARTIAL}, {"op": "void"}),
     "捕获之后不再是撤销：剩余走关闭，已捕获走退款。"),
    ("close-without-capture-refused", "authorized",
     ({"op": "close"},),
     "一分钱没捕获就想关闭：那叫撤销。"),
    ("capture-exceeding-authorized-refused", "authorized",
     ({"op": "capture", "amount_minor": PARTIAL},
      {"op": "capture", "amount_minor": AUTHORIZED}),
     "累计捕获超过授权额必须拒绝——这是整数不变量，不是提醒。"),
    ("capture-after-full-capture-refused", "authorized",
     ({"op": "capture", "amount_minor": AUTHORIZED},
      {"op": "capture", "amount_minor": 1}),
     "终态授权上不得再捕获。"),
    ("close-after-full-capture-refused", "authorized",
     ({"op": "capture", "amount_minor": AUTHORIZED}, {"op": "close"}),
     "全额捕获之后没有剩余可关闭。"),
    ("void-before-capture", "authorized",
     ({"op": "void"},),
     "未捕获时撤销释放全部授权。"),
    ("expire-without-action", "authorized",
     ({"op": "expire"},),
     "无人动作时授权过期，1000 一直被占用到过期为止。这是兜底路径，不是释放方式。"),
    ("non-positive-capture-refused", "authorized",
     ({"op": "capture", "amount_minor": 0},),
     "捕获金额必须是正的整数最小单位。"),
)


def _run(ref, operations: tuple[dict, ...]) -> dict:
    auth = ref.Authorization(AUTHORIZED)
    capability = ref.Capability(
        supports_authorization_capture=CAPABILITY["supports_authorization_capture"],
        partial_capture=CAPABILITY["partial_capture"],
        authorization_valid_hours=CAPABILITY["authorization_valid_hours"])
    refused_at = None
    refused_code = None
    for index, step in enumerate(operations):
        try:
            op = step["op"]
            if op == "capture":
                auth = ref.capture(auth, int(step["amount_minor"]), capability)
            elif op == "void":
                auth = ref.void(auth)
            elif op == "close":
                auth = ref.close(auth)
            elif op == "expire":
                auth = ref.expire(auth)
            elif op == "query":
                auth = ref.query(auth, str(step["provider_says"]))
            else:  # pragma: no cover - guarded by the sequence table
                raise ValueError(f"unknown operation {op!r}")
        except ref.CaptureRefused as refusal:
            refused_at = index
            refused_code = refusal.code
            break
    released = 0
    if auth.state == ref.CANCELED:
        released = auth.authorized_minor
    elif auth.state == ref.CAPTURED:
        released = auth.authorized_minor - auth.captured_minor
    return {
        "state": auth.state,
        "captured_minor": auth.captured_minor,
        "released_minor": released,
        "held_until_expiry_minor": auth.remaining_minor if auth.state == ref.EXPIRED else 0,
        "unresolved_unknown": auth.unresolved_unknown,
        "refused_at_step": refused_at,
        "refused_with": refused_code,
    }


def build_vectors(root: Path, budget: Budget | None = None) -> dict:
    model = load_json(root / MODEL)
    ref = _reference(root)
    cases = []
    for name, initial_state, operations, why in SEQUENCES:
        if budget is not None:
            budget.check(str(MODEL))
        cases.append({
            "id": name,
            "initial_state": initial_state,
            "authorized_minor": AUTHORIZED,
            "operations": [dict(step) for step in operations],
            "why": why,
            "expected": _run(ref, operations),
        })
    return {
        "_generated": "GENERATED FILE — scripts/render-capture.py; do not edit by hand",
        "schema_version": "1.0.0",
        "note": "由 governance/capture-lifecycle.json 与 libs/capture/reference 派生。"
                "任何语言实现必须逐条复现这些裁决，包括拒绝发生在第几步、以哪条码拒绝。"
                "未知结果的落定语义属于 B33，由该批次的向量证明，这里不重复。",
        "principle_digest": hashlib.sha256(
            str(model.get("principle", "")).encode("utf-8")).hexdigest(),
        "authorized_minor": AUTHORIZED,
        "capability": dict(CAPABILITY),
        "capability_gate": _profiles(root, budget),
        "cases": cases,
    }


def vectors_json(root: Path, budget: Budget | None = None) -> str:
    return json.dumps(build_vectors(root, budget), ensure_ascii=False, indent=2,
                      sort_keys=True) + "\n"


TARGETS = {"contracts/capture/vectors.json": vectors_json}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
