"""B33 — generate the payment attempt contract and its review document."""
from __future__ import annotations

import json
from pathlib import Path

from .repo import Budget, load_json

ATTEMPT = Path("governance/payment-attempt.json")
MD_BANNER = ("<!-- GENERATED FILE — do not edit by hand.\n"
             "     Source of truth: governance/payment-attempt.json\n"
             "     Regenerate with: python3 scripts/render-attempt.py -->\n")
BLOCKS = ("attempt", "tenant_scope", "concurrency", "reference_runtime", "deployable_runtime",
          "request_record", "response_record", "timeout", "retry", "finality", "lifecycle")


def _without_notes(block: dict) -> dict:
    return {k: v for k, v in sorted(block.items()) if k != "notes"}


def contract_json(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ATTEMPT)
    document = {
        "_generated": "GENERATED FILE — scripts/render-attempt.py; do not edit by hand",
        "schema_version": model["schema_version"],
        "outcome_classes": [{"id": c["id"], "final": c["final"],
                             "settles_intent": c["settles_intent"],
                             "retry_allowed": c["retry_allowed"],
                             "requires_resolution": c["requires_resolution"]}
                            for c in sorted(model["outcome_classes"], key=lambda x: x["id"])],
        "error_taxonomy": [{"provider": e["provider"],
                            "code_namespace": e["code_namespace"],
                            "provider_code": e["provider_code"],
                            "outcome_class": e["outcome_class"]}
                           for e in sorted(model["error_taxonomy"],
                                           key=lambda x: (x["provider"], x["code_namespace"],
                                                          x["provider_code"]))],
        "unmapped_code_class": model["unmapped_code_class"],
        "audit_event_class": model["audit_event_class"],
    }
    for block in BLOCKS:
        budget.check(block)
        document[block] = _without_notes(model[block])
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def attempt_markdown(root: Path, budget: Budget | None = None) -> str:
    budget = budget or Budget(seconds=60).start()
    model = load_json(root / ATTEMPT)
    attempt = model["attempt"]
    tenant = model["tenant_scope"]
    concurrency = model["concurrency"]
    runtime = model["reference_runtime"]
    deployable = model["deployable_runtime"]
    record = model["request_record"]
    response = model["response_record"]
    timeout = model["timeout"]
    retry = model["retry"]
    finality = model["finality"]
    lifecycle = model["lifecycle"]

    out = [MD_BANNER, "# 支付尝试与渠道交易（B33）", "", model["principle"], "",
           "## attempt", "",
           f"- 不可变：{'是' if attempt['immutable'] else '否'}；"
           f"一次渠道调用一条：{'是' if attempt['one_per_provider_call'] else '否'}",
           f"- 重试复用旧记录：{'允许' if not attempt['reuse_on_retry_forbidden'] else '**禁止**'}",
           f"- 每笔意图内序号单调："
           f"{'是' if attempt['sequence_monotonic_per_intent'] else '否'}",
           "- 必需字段：" + "、".join(f"`{f}`" for f in attempt["required_fields"]),
           "", attempt["notes"], "",
           "## 租户边界与并发", "",
           f"- tenant_id 必填：{'是' if tenant['tenant_id_required'] else '否'}；"
           "查询键：" + " + ".join(f"`{f}`" for f in tenant["lookup_key"]),
           f"- 外部 ID 不作为内部 ID："
           f"{'是' if tenant['external_ids_never_used_as_internal_ids'] else '否'}",
           "", tenant["notes"], "",
           f"- start 原子化：{'是' if concurrency['atomic_start'] else '否'}；"
           "冲突键：" + " + ".join(f"`{f}`" for f in concurrency["conflict_key"]),
           f"- 并发重复：`{concurrency['concurrent_duplicate_policy']}`",
           "", concurrency["notes"], "",
           "## 参考实现边界", "",
           f"- 进程内锁：{'是' if runtime['process_local_lock'] else '否'}；"
           f"持久化：{'是' if runtime['durable_storage'] else '**否**'}；"
           f"数据库唯一约束：{'是' if runtime['database_unique_constraint'] else '**否**'}",
           f"- 运行时审计写入：{'是' if runtime['runtime_audit_sink'] else '**否**'}；"
           f"生产就绪：{'是' if runtime['production_ready'] else '**否**'}",
           f"- B32 replacement confirmation 已接通："
           f"{'是' if runtime['b32_replacement_confirmation_integrated'] else '**否**'}",
           "", runtime["notes"], "",
           "## 可部署 Java 运行时", "",
           f"- 实现：`{deployable['implementation']}`",
           f"- 迁移：`{deployable['migration']}`",
           f"- 持久化：{'是' if deployable['durable_storage'] else '否'}；"
           f"数据库唯一约束：{'是' if deployable['database_unique_constraint'] else '否'}；"
           f"事务 outbox：{'是' if deployable['transactional_outbox'] else '否'}",
           f"- 租户 RLS：{'是' if deployable['tenant_rls'] else '否'}；"
           f"B32 confirm 接入：{'是' if deployable['b32_confirmation_integrated'] else '否'}；"
           f"UNKNOWN 查询收敛：{'是' if deployable['unknown_query_recovery'] else '否'}",
           f"- 本地测试等同认证：{'是' if deployable['local_tests_are_certification'] else '**否**'}",
           "", deployable["notes"], "",
           "## 请求记录", "",
           f"- 存摘要不存报文：{'是' if record['store_digest_not_payload'] else '否'}；"
           f"算法：`{record['digest_algorithm']}`",
           "- 脱敏字段：" + "、".join(f"`{f}`" for f in record["redacted_fields"]),
           f"- 可重放：{'是' if record['payload_replayable'] else '**否**'}",
           "", record["notes"], "",
           "## 响应记录", "",
           f"- 存规范化摘要不存原始响应："
           f"{'是' if response['store_summary_not_payload'] else '否'}；"
           f"算法：`{response['digest_algorithm']}`",
           "- 保留的证据字段：" + "、".join(
               f"`{f}`" for f in response["required_evidence_fields"]),
           "- 禁止进入记录：" + "、".join(f"`{f}`" for f in response["forbidden_fields"]),
           f"- 可重放：{'是' if response['payload_replayable'] else '**否**'}",
           "", response["notes"], "",
           "## 结果分类", "",
           "| 分类 | attempt 终态 | 落定 intent | 同请求可重试 | 需落定 | 说明 |",
           "| --- | --- | --- | --- | --- | --- |"]
    for entry in model["outcome_classes"]:
        budget.check(entry["id"])
        out.append(f"| `{entry['id']}` | {'是' if entry['final'] else '否'} | "
                   f"{'是' if entry['settles_intent'] else '否'} | "
                   f"{'是' if entry['retry_allowed'] else '否'} | "
                   f"{'是' if entry['requires_resolution'] else '否'} | {entry['notes']} |")

    out += ["", "## 超时", "",
            f"- 归类为：**`{timeout['classified_as']}`**",
            f"- 落定前允许重试："
            f"{'是' if timeout['retry_before_resolution_allowed'] else '**否**'}",
            "- 落定方式：" + "、".join(f"`{m}`" for m in timeout["resolution_methods"]),
            f"- 最长落定时限：{timeout['max_resolution_hours']} 小时",
            "", timeout["notes"], "",
            "## 重试", "",
            f"- 必须开新 attempt：{'是' if retry['new_attempt_required'] else '否'}；"
            f"复用幂等键：{'是' if retry['reuse_idempotency_key'] else '否'}",
            f"- 仅限可重试分类：{'是' if retry['only_for_retryable'] else '否'}；"
            f"上限：{retry['max_attempts_per_intent']} 次",
            "- 更换资金源仅允许在：" + "、".join(
                f"`{c}`" for c in retry["replacement_request_allowed_after"]),
            f"- 更换请求必须使用新幂等键："
            f"{'是' if retry['replacement_request_requires_new_idempotency_key'] else '否'}；"
            f"必须由客户动作触发："
            f"{'是' if retry['replacement_request_requires_customer_action'] else '否'}",
            "- 退避：" + "、".join(f"{s}s" for s in retry["backoff_seconds"]),
            "", retry["notes"], "",
            "## 渠道错误分类表", "",
            "| 渠道 | 码命名空间 | 渠道码 | 分类 | 说明 |",
            "| --- | --- | --- | --- | --- |"]
    for entry in sorted(model["error_taxonomy"],
                        key=lambda x: (x["provider"], x["code_namespace"],
                                       x["provider_code"])):
        budget.check(f"{entry['provider']}/{entry['provider_code']}")
        out.append(f"| `{entry['provider']}` | `{entry['code_namespace']}` | "
                   f"`{entry['provider_code']}` | "
                   f"`{entry['outcome_class']}` | {entry['notes']} |")
    out += ["", f"**未登记的渠道码一律归入 `{model['unmapped_code_class']}`**——"
            "没见过的码，按定义就是不知道结果。", "",
            "## 最终性", "",
            f"- 终态 attempt 不可修改：{'是' if finality['final_attempt_immutable'] else '否'}",
            f"- 意图结果取自终态 attempt："
            f"{'是' if finality['intent_outcome_from_final_attempt'] else '否'}",
            f"- 后到的矛盾事件：开对账项 "
            f"{'是' if finality['contradicting_later_event_opens_reconciliation'] else '否'}；"
            f"覆盖 {'是' if finality['contradicting_later_event_overwrites'] else '**否**'}",
            "", finality["notes"], "",
            "## 生命周期", "",
            f"- 来源：`{lifecycle['source']}`（B10 定义，此处引用）",
            "- 状态：" + "、".join(f"`{s}`" for s in lifecycle["states"]),
            f"- 初始：`{lifecycle['initial']}`；终态："
            + "、".join(f"`{s}`" for s in lifecycle["terminal"]),
            "- 成功态：" + "、".join(f"`{s}`" for s in lifecycle["success_states"]),
            "", lifecycle["notes"], "",
            f"审计事件类别：`{model['audit_event_class']}`（见 B23）。", ""]
    return "\n".join(out)


TARGETS = {
    "contracts/payment/attempt.json": contract_json,
    "docs/payment/PAYMENT_ATTEMPT.md": attempt_markdown,
}


def render_all(root: Path, budget: Budget | None = None) -> dict[str, str]:
    budget = budget or Budget(seconds=60).start()
    return {rel: render(root, budget) for rel, render in TARGETS.items()}
