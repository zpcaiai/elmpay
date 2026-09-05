"""B35 — derive the sensitive-field catalogue from governance, in every language.

Four hand-written copies of "what must never be stored" is not four defences. It
is one defence with three holes in it, and nobody can say which holes without
diffing four files in three languages. So the list is written once, here it is
projected: a language-neutral contract for the JavaScript, Python and Go
implementations, and a generated Java constant for the ones that cannot read a
file at class-init time.

Both projections carry the GENERATED banner and are drift-checked, so editing a
copy instead of the source turns the build red rather than turning one language
quietly permissive.
"""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

MODEL = Path("governance/payment-method.json")

CONTRACT = "contracts/payment-method/sensitive-fields.json"
JAVA_CATALOG = "libs/security/src/main/java/com/elmpay/security/SensitiveFieldCatalog.java"

BANNER = "GENERATED FILE — scripts/render-paymethod.py; do not edit by hand"


def normalize(name: str, rules: dict) -> str:
    text = str(name)
    if rules.get("lowercase", True):
        text = text.lower()
    for character in rules.get("strip_characters") or []:
        text = text.replace(character, "")
    return text


def catalogue(root: Path, budget: Budget | None = None) -> dict:
    model = load_json(root / MODEL, budget)
    rules = model.get("normalization") or {}
    families = []
    every: set[str] = set()
    for family in model.get("forbidden_fields") or []:
        names = [family["canonical"], *family.get("aliases", [])]
        normalized = sorted({normalize(name, rules) for name in names})
        every.update(normalized)
        families.append({
            "canonical": family["canonical"],
            "names": sorted(names),
            "normalized": normalized,
            "reason": family.get("reason", ""),
        })
    families.sort(key=lambda item: item["canonical"])
    return {
        "model": model,
        "families": families,
        "normalized_names": sorted(every),
        "normalization": rules,
        "display_allowlist": sorted(model.get("display_allowlist") or []),
        "schemes": sorted((model.get("token_reference") or {}).get("schemes") or []),
    }


def contract_json(root: Path, budget: Budget | None = None) -> str:
    data = catalogue(root, budget)
    payload = {
        "_generated": BANNER,
        "schema_version": "1.0.0",
        "note": "由 governance/payment-method.json 派生。任何语言的实现必须使用这份清单，"
                "不得另写字面量副本——四份互不相同的副本正是本批次要消灭的东西。",
        "normalization": data["normalization"],
        "families": data["families"],
        "normalized_names": data["normalized_names"],
        "display_allowlist": data["display_allowlist"],
        "token_reference_schemes": data["schemes"],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _java_set(names: list[str]) -> str:
    quoted = [f'"{name}"' for name in names]
    lines: list[str] = []
    current = "            "
    for index, item in enumerate(quoted):
        piece = item + ("," if index < len(quoted) - 1 else "")
        if len(current) + len(piece) + 1 > 100:
            lines.append(current.rstrip())
            current = "            "
        current += piece + " "
    lines.append(current.rstrip())
    return "\n".join(lines)


def java_catalog(root: Path, budget: Budget | None = None) -> str:
    data = catalogue(root, budget)
    reasons = "\n".join(
        f" *   <li>{family['canonical']} — {family['reason']}</li>"
        for family in data["families"])
    return f"""// {BANNER}
// Source of truth: {MODEL.as_posix()}
package com.elmpay.security;

import java.util.Set;

/**
 * Field names that must never reach storage, logs, traces or CI artefacts.
 *
 * <p>Names are normalised before comparison — lower-cased with {{@code _ - .}} and spaces
 * removed — so {{@code card_pan}}, {{@code cardPan}} and {{@code CARD-PAN}} are one name, not three.
 * Before B35 they were three, which is how {{@code card_pan}} passed a guard that was watching
 * {{@code pan}}.
 *
 * <ul>
{reasons}
 * </ul>
 */
public final class SensitiveFieldCatalog {{
    /** Normalised names. Compare with {{@link #normalize(String)}}, never raw. */
    public static final Set<String> DENIED_KEYS = Set.of(
{_java_set(data["normalized_names"])});

    /** Schemes a payment-method reference may use. An allowlist, deliberately. */
    public static final Set<String> TOKEN_SCHEMES = Set.of(
{_java_set(data["schemes"])});

    /** Fields that may be shown to a human or returned by an API. */
    public static final Set<String> DISPLAY_ALLOWLIST = Set.of(
{_java_set(data["display_allowlist"])});

    private SensitiveFieldCatalog() {{
    }}

    /** Lower-case and drop separators, so one field name is one name. */
    public static String normalize(String name) {{
        if (name == null) {{
            return "";
        }}
        StringBuilder builder = new StringBuilder(name.length());
        for (int index = 0; index < name.length(); index++) {{
            char character = name.charAt(index);
            if (character == '_' || character == '-' || character == '.' || character == ' ') {{
                continue;
            }}
            builder.append(Character.toLowerCase(character));
        }}
        return builder.toString();
    }}

    /** True when the name is forbidden under any spelling. */
    public static boolean denied(String name) {{
        return DENIED_KEYS.contains(normalize(name));
    }}
}}
"""


TARGETS = {CONTRACT: contract_json, JAVA_CATALOG: java_catalog}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}
