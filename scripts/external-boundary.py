#!/usr/bin/env python3
"""Report which batches cannot be certified from this repository, and why.

Two different things get called "not done" in this programme and they need to
stay apart:

* work that is missing — nobody has written it yet;
* work that is finished here and still cannot be certified, because the proof
  it needs is a document somebody outside this repository has to sign.

The second list is not a backlog. It is the boundary of what a repository can
honestly say about itself. ``platform/compliance/external-evidence-policy.json``
already refuses to certify without those documents; this script names the
batches each refusal is holding, so nobody has to rediscover the mapping by
running the release gate and reading twenty-two reason codes.

Run it whenever someone asks "why is B127 still blocked".
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import read_json                      # noqa: E402
from elmpay_runtime.external_evidence import validate_external_evidence  # noqa: E402

POLICY = ROOT / "platform/compliance/external-evidence-policy.json"
BATCHES = ROOT / ".payment-platform/skill-package/batches"

# Which batches each external category is holding. Every entry cites the batch
# title it came from, so a reviewer can check the mapping against the spec
# rather than trust it.
BLOCKS: dict[str, list[tuple[str, str]]] = {
    "provider_certification": [
        ("B40", "微信支付 APIv3 核心与凭证"),
        ("B44", "支付宝证书模式与核心 SDK"),
        ("B48", "Stripe PaymentIntents 与令牌化卡支付"),
        ("B51", "PayPal Orders v2 授权与捕获"),
        ("B54", "Apple Pay 域名、证书与商户令牌"),
        ("B55", "全渠道沙箱、认证与契约测试"),
        ("B113", "渠道契约测试与模拟器"),
        ("B122", "生产商户配置与渠道上线"),
    ],
    "production_kubernetes": [
        ("B93", "Kubernetes、GitOps 与策略即代码"),
        ("B123", "上线准备与 Go/No-Go"),
    ],
    "dr_exercise": [
        ("B94", "多区域架构与数据主权"),
        ("B95", "业务连续性、混沌与恢复演练"),
    ],
    "pci_assessor": [
        ("B104", "PCI DSS 4.0.1 范围与控制映射"),
    ],
    "regional_market_approval": [
        ("B105", "中国支付与数据合规配置"),
    ],
    "legal_compliance": [
        ("B106", "GDPR、PSD2/SCA 与全球隐私"),
        ("B107", "AML、KYC、KYB、制裁与监管边界"),
        ("B111", "第三方风险、合同与供应商退出"),
    ],
    "penetration_test": [
        ("B110", "漏洞管理、渗透测试与红队"),
        ("B116", "SAST、DAST、IAST、密钥与依赖测试"),
    ],
    "uat_acceptance": [
        ("B118", "UAT、财务与运营验收"),
        ("B119", "合规证据与独立评审门"),
    ],
    "shadow_rollout": [
        ("B121", "影子流量、双运行与差异验证"),
    ],
    "canary_rollout": [
        ("B124", "分阶段发布、灰度与回滚"),
    ],
    "merchant_acceptance": [
        ("B122", "生产商户配置与渠道上线"),
        ("B123", "上线准备与 Go/No-Go"),
        ("B127", "最终生产认证与发布签署"),
    ],
    "post_launch_reconciliation": [
        ("B125", "上线后监控与日终对账"),
    ],
    "commercial_sla": [
        ("B126", "商业定价、SLA、支持与用量计费"),
    ],
    "go_no_go": [
        ("B123", "上线准备与 Go/No-Go"),
    ],
    "final_release_signoff": [
        ("B127", "最终生产认证与发布签署"),
    ],
    "independent_human_review": [
        ("B00..B127", "每一个批次的 evidence/<batch>/review.json"),
    ],
}


def main() -> int:
    policy = read_json(POLICY)
    # A throwaway replay database: this is a report, not a gate, and it must not
    # touch the real nonce store that the release path depends on.
    with tempfile.TemporaryDirectory() as scratch:
        report = validate_external_evidence(
            policy,
            {"evidence": []},
            {"replayDatabase": str(Path(scratch) / "boundary-nonces.db"), "keys": {}},
            now=datetime.now(timezone.utc),
            expected_binding="0" * 64,
        )

    unmet = sorted(
        reason.split(":", 1)[1] for reason in report.reasons
        if reason.startswith("missing_external_evidence:"))
    known = set(policy["requiredCategories"])
    unmapped = sorted(set(unmet) - set(BLOCKS))

    print("external evidence policy :", POLICY.relative_to(ROOT))
    print("localValidationMayCertify:", policy.get("localValidationMayCertify"))
    print("minimumDistinctVerifiers :", policy.get("minimumDistinctVerifiers"))
    print("release allowed with no external evidence:", report.allowed)
    print()

    blocked: set[str] = set()
    for category in unmet:
        holds = BLOCKS.get(category, [])
        print(f"[{category}] source={policy['requiredCategories'][category]['requiredSource']} "
              f"maxAgeHours={policy['requiredCategories'][category]['maximumAgeHours']}")
        for batch, title in holds:
            blocked.add(batch)
            print(f"    blocks {batch}  {title}")
        if not holds:
            print("    blocks (unmapped — add it to BLOCKS)")
        print()

    concrete = sorted(b for b in blocked if not b.endswith("..B127"))
    print(f"categories unmet={len(unmet)} of {len(known)}   batches held={len(concrete)}")
    print("batches held:", ", ".join(concrete))
    if unmapped:
        print("UNMAPPED CATEGORIES:", unmapped)
    print()
    print("Nothing in this list is a coding task. Each one needs a document signed "
          "outside this repository by a party that is not us.")
    return 2 if unmapped else 0


if __name__ == "__main__":
    raise SystemExit(main())
