"""B11 — generate OpenAPI, the error catalogue and the review document.

Integrators read OpenAPI; reviewers read prose; both are generated from
``governance/api-contract.json`` so neither can quietly disagree with the gate.
"""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

CONTRACT = Path("governance/api-contract.json")
BANNER_MD = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/api-contract.json\n"
             "     Regenerate with: python3 scripts/render-api.py -->\n")


def _load(root: Path) -> dict:
    return load_json(root / CONTRACT)


def _money_schema(contract: dict) -> dict:
    shape = contract["money_shape"]
    return {
        "type": "object",
        "required": [shape["amount_field"], shape["currency_field"]],
        "additionalProperties": False,
        "properties": {
            shape["amount_field"]: {
                "type": "integer", "format": "int64",
                "description": "最小货币单位整数。精度由 governance/currency-metadata.json 决定。"},
            shape["currency_field"]: {"type": "string", "minLength": 3, "maxLength": 3,
                                      "pattern": "^[A-Z]{3}$"},
        },
    }


def _security_schemes(contract: dict) -> dict:
    """Translate the governance auth catalogue into standard OpenAPI schemes."""
    result: dict = {}
    for scheme in contract["auth_schemes"]:
        if scheme["type"] == "oauth2_mtls":
            result["OAuth2"] = {
                "type": "oauth2",
                "description": scheme["description"],
                "flows": {"clientCredentials": {
                    "tokenUrl": scheme["token_url"],
                    "scopes": scheme["scopes"],
                }},
                "x-token-type": scheme["token_type"],
            }
            result["MutualTLS"] = {
                "type": "mutualTLS",
                "description": "OAuth2 access token holder binding; certificate thumbprint "
                               "must match cnf.x5t#S256.",
                "x-holder-binding": scheme["holder_binding"],
            }
        elif scheme["type"] == "provider_signature":
            result["ProviderSignature"] = {
                "type": "apiKey", "in": "header", "name": scheme["header"],
                "description": scheme["description"],
            }
        else:  # validation rejects this; rendering must fail closed too
            raise ValueError(f"unsupported auth scheme type: {scheme.get('type')}")
    return result


def _operation_security(operation: dict, auth_schemes: dict[str, dict]) -> list[dict]:
    scheme = auth_schemes[operation["auth"]]
    if scheme["type"] == "oauth2_mtls":
        # Keys in one Security Requirement Object are ANDed by OpenAPI.
        return [{"OAuth2": operation["required_scopes"], "MutualTLS": []}]
    if scheme["type"] == "provider_signature":
        return [{"ProviderSignature": []}]
    raise ValueError(f"unsupported auth scheme type: {scheme.get('type')}")


def openapi_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    contract = _load(root)
    auth_schemes = {scheme["id"]: scheme for scheme in contract["auth_schemes"]}
    paths: dict = {}
    for operation in contract["operations"]:
        budget.check(operation["id"])
        item = paths.setdefault(operation["path"], {})
        parameters = []
        for segment in operation["path"].split("/"):
            if segment.startswith("{"):
                parameters.append({"name": segment[1:-1], "in": "path", "required": True,
                                   "schema": {"type": "string"}})
        for header in contract["trace"]["required_headers"]:
            parameters.append({"name": header, "in": "header", "required": True,
                               "schema": {"type": "string"}})
        idem = operation.get("idempotency")
        if idem:
            parameters.append({"name": idem["header"], "in": "header", "required": True,
                               "schema": {"type": "string", "maxLength": 255},
                               "description": f"幂等键，作用域 {idem['scope']}，"
                                              f"保留 {idem['retention_hours']} 小时。"})
        signature = operation.get("signature")
        if signature:
            for header in (signature["header"], signature["timestamp_header"]):
                parameters.append({"name": header, "in": "header", "required": True,
                                   "schema": {"type": "string"}})
        pagination = operation.get("pagination")
        if pagination:
            parameters.append({"name": pagination["cursor_param"], "in": "query",
                               "required": False, "schema": {"type": "string"}})
            parameters.append({"name": pagination["limit_param"], "in": "query",
                               "required": False,
                               "schema": {"type": "integer", "minimum": 1,
                                          "maximum": pagination["max_limit"],
                                          "default": pagination["default_limit"]}})
        responses = {"200": {"description": "成功"}}
        for code in operation["errors"]:
            entry = next(e for e in contract["errors"] if e["code"] == code)
            responses.setdefault(str(entry["http_status"]), {
                "description": entry["safe_message"],
                "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Error"}}}})
        item[operation["method"].lower()] = {
            "operationId": operation["id"],
            "summary": operation["summary"],
            "parameters": parameters,
            "responses": responses,
            "security": _operation_security(operation, auth_schemes),
            "x-actor": operation["actor"],
            "x-drives-transition": operation.get("drives_transition"),
            "x-deprecated-sunset": (operation.get("deprecated") or {}).get("sunset"),
        }

    # Insertion order, not sort_keys: the "GENERATED FILE" banner has to land in
    # the first few hundred bytes so the SSOT gate can see it, and OpenAPI
    # extension keys are required to start with "x-", which sorts last.
    # Determinism comes from deterministic construction instead.
    document = {
        "x-generated": "GENERATED FILE — scripts/render-api.py; do not edit by hand",
        "openapi": "3.1.0",
        "info": {"title": "elmpay 支付平台 API", "version": contract["api_version"],
                 "description": contract["versioning"]["policy"]},
        "servers": [{"url": "https://api.example.invalid"}],
        "components": {
            "securitySchemes": _security_schemes(contract),
            "schemas": {
                "Money": _money_schema(contract),
                "Error": {
                    "type": "object",
                    "required": ["code", "message", "request_id"],
                    "additionalProperties": False,
                    "properties": {
                        "code": {"type": "string",
                                 "enum": sorted(e["code"] for e in contract["errors"])},
                        "message": {"type": "string"},
                        "remedy": {"type": "string"},
                        "request_id": {"type": "string"},
                    },
                },
            },
        },
        "paths": dict(sorted(paths.items())),
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def errors_json(root: Path, budget: Budget | None = None) -> str:
    """Language-neutral error catalogue: clients branch on this, not on prose."""
    contract = _load(root)
    document = {
        "_generated": "GENERATED FILE — scripts/render-api.py; do not edit by hand",
        "schema_version": contract["schema_version"],
        "api_version": contract["api_version"],
        "errors": sorted(contract["errors"], key=lambda e: e["code"]),
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def contract_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    contract = _load(root)
    out = [BANNER_MD, "# API 规范、错误与兼容模型（B11）", ""]
    out.append("本文由 `governance/api-contract.json` 生成。"
               "操作与状态机转移的绑定由门禁强制一致（`API_TRANSITION_KEY_MISMATCH`、"
               "`API_TRANSITION_ACTOR`）。")
    out.append("")
    out.append("## 版本与弃用")
    out.append("")
    versioning = contract["versioning"]
    out.append(f"- 版本方式：路径大版本（当前 `v{versioning['current_major']}`）")
    out.append(f"- 策略：{versioning['policy']}")
    out.append(f"- 旧大版本并行支持：不少于 {versioning['minimum_parallel_support_months']} 个月")
    out.append(f"- 弃用：`{versioning['deprecation']['header']}` 头 + "
               f"不少于 {versioning['deprecation']['notice_days']} 天预告")
    out.append("")
    out.append("## 幂等、分页、追踪与金额")
    out.append("")
    idem = contract["idempotency"]
    out.append(f"- 幂等：`{idem['header']}`，最短保留 {idem['min_retention_hours']} 小时；"
               f"{idem['policy']}")
    out.append(f"- 分页：{contract['pagination']['policy']}"
               f"（禁止参数：{', '.join('`' + p + '`' for p in contract['pagination']['forbidden_params'])}）")
    out.append(f"- 追踪：必须携带 {', '.join('`' + h + '`' for h in contract['trace']['required_headers'])}；"
               f"{contract['trace']['policy']}")
    out.append(f"- 金额：{contract['money_shape']['policy']}")
    out.append("")
    out.append("## 错误目录")
    out.append("")
    out.append("| 错误码 | HTTP | 可重试 | 类别 | 含义 | 应对 |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for entry in sorted(contract["errors"], key=lambda e: e["code"]):
        retry = "是" if entry["retryable"] else "否"
        out.append(f"| `{entry['code']}` | {entry['http_status']} | {retry} | "
                   f"{entry['category']} | {entry['safe_message']} | {entry['remedy']} |")
    out.append("")
    out.append("## 操作")
    out.append("")
    out.append("| 操作 | 方法 | 路径 | 调用方 | 认证 | 权限范围 | 幂等键作用域 | 驱动的状态转移 |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for operation in contract["operations"]:
        budget.check(operation["id"])
        idem = operation.get("idempotency")
        scope = f"`{idem['scope']}`" if idem else "—"
        transition = operation.get("drives_transition")
        drives = (f"`{transition['machine']}` / `{transition['event']}`" if transition else "—")
        required_scopes = operation.get("required_scopes") or []
        scopes = ", ".join(f"`{value}`" for value in required_scopes) or "—"
        out.append(f"| `{operation['id']}` | {operation['method']} | `{operation['path']}` | "
                   f"`{operation['actor']}` | `{operation['auth']}` | {scopes} | {scope} | "
                   f"{drives} |")
    out.append("")
    writes = [o for o in contract["operations"] if o["method"] != "GET"]
    out.append(f"共 {len(contract['operations'])} 个操作（其中 {len(writes)} 个写操作，"
               f"全部要求幂等键）、{len(contract['errors'])} 个错误码。")
    out.append("")
    return "\n".join(out)


def transition_vectors_json(root: Path, budget: Budget | None = None) -> str:
    """Language-neutral vectors binding API operations to state transitions.

    B10 defined the transitions and left this gap open on purpose: the vectors
    could not be pinned until the API fixed the event names. Any implementation
    must reproduce these results -- accept the accepted ones, reject the rejected
    ones with the stated reason, and treat a replay as a no-op.
    """
    budget = budget or Budget(seconds=60).start()
    contract = _load(root)
    model = load_json(root / Path("governance/state-machines.json"))
    machines = {m["name"]: m for m in model["machines"]}
    index: dict = {}
    for m in model["machines"]:
        for t in m["transitions"]:
            index.setdefault((m["name"], t["event"]), []).append(t)

    accepted = []
    for operation in contract["operations"]:
        transition = operation.get("drives_transition")
        if not transition:
            continue
        budget.check(operation["id"])
        # One vector per legal source state: the same event may be allowed from
        # several states, and each of them is a separate thing to get right.
        for declared in index[(transition["machine"], transition["event"])]:
            accepted.append({
                "operation": operation["id"],
                "machine": transition["machine"],
                "from": declared["from"],
                "event": declared["event"],
                "actor": declared["actor"],
                "idempotency_scope": declared["idempotency"],
                "expected_to": declared["to"],
                "replay_is_no_op": True,
            })

    rejected = []
    for machine_name, machine in sorted(machines.items()):
        success = set(model["success_states"].get(machine["entity"], []))
        for tr in machine["transitions"]:
            if tr["to"] in success:
                rejected.append({
                    "machine": machine_name,
                    "from": tr["from"],
                    "event": tr["event"],
                    "actor": "merchant",
                    "expected_rejection": "WRONG_ACTOR"
                    if tr["actor"] != "merchant" else "UNTRUSTED_SUCCESS",
                    "reason": "只有已验签渠道事件或对账定责可以写入成功状态（NN-03）",
                })
        rejected.append({
            "machine": machine_name,
            "from": machine["initial"],
            "event": "provider.nonexistent_event",
            "actor": "provider-event",
            "expected_rejection": "EVENT_NOT_ALLOWED",
            "reason": "未声明的事件不得被静默忽略，必须被拒绝",
        })

    document = {
        "_generated": "GENERATED FILE — scripts/render-api.py; do not edit by hand",
        "schema_version": contract["schema_version"],
        "api_version": contract["api_version"],
        "note": "由 governance/{api-contract,state-machines}.json 生成。"
                "任何语言实现必须逐条复现这些结果。",
        "accepted": accepted,
        "rejected": rejected,
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


TARGETS = {
    "contracts/api/openapi.json": openapi_json,
    "contracts/api/errors.json": errors_json,
    "contracts/api/transition-vectors.json": transition_vectors_json,
    "docs/api/API_CONTRACT.md": contract_markdown,
}


def render_all(root: Path) -> dict[str, str]:
    return {rel: fn(root) for rel, fn in TARGETS.items()}


def baseline_json(root: Path) -> str:
    """Snapshot the compatibility-relevant surface of the current major."""
    contract = _load(root)
    document = {
        "_generated": "GENERATED FILE — scripts/render-api.py --record-baseline",
        "note": "记录当前大版本的兼容性基线。只有开新大版本时才允许重录。",
        "major": contract["versioning"]["current_major"],
        "operations": {
            op["id"]: {"method": op["method"], "path": op["path"],
                       "errors": sorted(op.get("errors") or []),
                       "auth": op["auth"],
                       "required_scopes": sorted(op.get("required_scopes") or []),
                       "idempotency": {"required": bool((op.get("idempotency") or {})
                                                        .get("required"))}}
            for op in contract["operations"]
        },
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
