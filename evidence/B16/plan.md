# B16 plan — 零信任安全架构

Batch: 零信任安全架构 · Wave W02 · Skill `pay-zero-trust-identity` · depends_on: [B15]

## 1. 范围

零信任最容易变成一句口号。本批次的做法是：**把它写成一个能被执行的判定函数，
然后用测试证明它不看网络位置。**

1. `governance/zero-trust.json`：7 类主体、11 条访问判定、12 条信任边界规则
   （覆盖 B02 威胁模型里全部 12 条边界）、会话与撤销、工作负载身份、审计要求。
2. `tools/paygov/zerotrust.py`：零信任门禁（47 条规则），含跨事实源检查：
   边界必须来自 B02 威胁模型；紧急通道必须与 B13 声明的一致。
3. `libs/zerotrust/reference/decision.py`：**可执行的策略判定点（PDP）**。
4. `tools/paygov/ztgen.py` + `scripts/render-zerotrust.py`，生成
   `contracts/security/zero-trust-matrix.json` 与 `docs/security/ZERO_TRUST.md`。
5. `scripts/zerotrust-smoke.py`：7 组性质、12 项运行期断言。
6. `tools/tests/test_b16_zerotrust.py`：80 个用例。

## 2. 受影响组件

`governance/{zero-trust,ssot-registry}.json`、`tools/paygov/{zerotrust,ztgen,registry}.py`、
`libs/zerotrust/`、`scripts/{render-zerotrust,zerotrust-smoke}.py`、`contracts/security/`、
`docs/security/ZERO_TRUST.md`、`tools/tests/{test_b16_zerotrust.py,support.py}`、
`scripts/negative-controls.py`（扩至 119 个场景）。

## 3. 领域接口与数据契约

- **默认拒绝**，且 `network_location_grants` 必须为**空数组**。
  这一条是零信任与传统边界安全的分水岭：只要有任何一个网段被写成「可信」，
  整套设计就退化成一台带 JSON 的防火墙。判定函数**从不读取** `context.network`，
  测试用同一请求在「内网」与「公网」两个标签下跑两遍，断言结论完全相同。
- **主体**（7 类）：付款人、商户服务端、平台运营、服务工作负载、连接器出站、CI、紧急通道。
  每一类都必须声明身份来源、凭据类型与**有效期**。人的凭据不得长于会话上限（60 分钟）。
- **工作负载身份**：SPIFFE 式身份 over mTLS，证书最长 60 分钟，
  **禁止长期静态服务账号密码**——泄露过一次就永远泄露（NN-07）。
- **访问判定**（11 条）：每条必须至少要求
  `authenticated_identity + authorisation_policy + audit_record`，并命名它发出的审计事件。
- **高风险动作**（退款审批、改风控规则、跨租户读取）必须 step-up + **四眼复核** + 记录理由（NN-11）。
- **管理访问**必须抗钓鱼 MFA + 设备状态。短信 OTP 是钓鱼目标，不是第二因素。
- **租户绑定来自凭据，不来自请求体**。让请求体决定租户，跨租户越权只差改一个字段（NN-09）。
- **信任边界**：我们自己运营的两个区域之间（含边缘），**必须双向 mTLS**。
  「两边都是内网」正是零信任要拆掉的那个假设。
- **审计**：每一次判定——**包括每一次允许**——都要落审计，且审计不可修改。
  只记拒绝的审计，在事后调查里等于没有审计（CTRL-007）。撤销必须 60 秒内全局生效。

## 4. 错误语义

`ZT_UNREADABLE`、`ZT_VERSION_FIELD`、`ZT_SHAPE`、`ZT_PRINCIPLE`、`ZT_DENY_BY_DEFAULT`、
`ZT_NETWORK_TRUST`、`ZT_FACTORS`、`ZT_SESSION`、`ZT_REVOCATION`、`ZT_STATIC_CREDENTIAL`、
`ZT_WORKLOAD_IDENTITY`、`ZT_WORKLOAD_CREDENTIAL`、`ZT_AUDIT_ALLOW_ONLY`、`ZT_AUDIT_MUTABLE`、
`ZT_AUDIT_FIELDS`、`ZT_PRINCIPAL_ID`、`ZT_PRINCIPAL_DUPLICATE`、`ZT_PRINCIPAL_KIND`、
`ZT_PRINCIPAL_NOTES`、`ZT_PRINCIPAL_UNUSED`、`ZT_IDENTITY_SOURCE`、`ZT_CREDENTIAL_LIFETIME`、
`ZT_DECISION_ID`、`ZT_DECISION_DUPLICATE`、`ZT_DECISION_PRINCIPAL`、
`ZT_DECISION_REQUIREMENTS`、`ZT_DECISION_MINIMUM`、`ZT_DECISION_AUDIT`、`ZT_DECISION_NOTES`、
`ZT_FOUR_EYES`、`ZT_STEP_UP`、`ZT_JUSTIFICATION`、`ZT_HIGH_RISK_UNCOVERED`、`ZT_ADMIN_MFA`、
`ZT_DEVICE_POSTURE`、`ZT_TENANT_BINDING`、`ZT_BOUNDARY_UNKNOWN`、`ZT_BOUNDARY_REQUIREMENTS`、
`ZT_BOUNDARY_AUDIT`、`ZT_BOUNDARY_NOTES`、`ZT_BOUNDARY_UNGOVERNED`、`ZT_INTERNAL_TRUST`、
`ZT_BREAK_GLASS_UNGOVERNED`、`ZT_BREAK_GLASS_UNBOUNDED`、`ZT_GENERATED_MISSING`、
`ZT_GENERATED_DRIFT`、`ZT_GENERATED`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify zero-trust --repo .
python3 scripts/render-zerotrust.py --check
python3 scripts/zerotrust-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 11 条判定的 happy path 全部放行；12 条边界全部有规则且都要求审计 |
| **承重** | **逐个拿掉每条判定的每一个必需因素，必须全部被拒**——因素不是装饰 |
| 默认拒绝 | 未声明的访问即使带齐全部 13 个因素也必须被拒 |
| **网络无关** | 同一请求在 `corporate-vpn` 与 `public-internet` 两个标签下判定完全一致（这一条就是整个架构） |
| 会话 | 超过 60 分钟的会话，即使因素齐全也一律被拒 |
| 四眼 | 高风险动作自己批自己必须被拒；缺第二审批人必须被拒；未完成 step-up 必须被拒 |
| 审计 | 每次判定（允许 33 次 / 拒绝 97 次）都产生完整审计记录；字段齐全 |
| 拒绝 | 47 条规则各有用例：信任某个网段、改成默认允许、允许静态凭据、只审计拒绝、去掉四眼、管理访问去掉抗钓鱼 MFA、租户绑定改到请求体、内网之间去掉 mTLS…… |
| 失败关闭 | 策略坏到无法生成矩阵时给出 `ZT_GENERATED` 而非崩溃 |
| 运行期 | `zerotrust-smoke.py` 12 项断言；负向控制新增 10 个 B16 场景，共 119 个场景 |

**本批次门禁抓到的真实问题**：`ZT_BOUNDARY_UNGOVERNED` 发现 B02 威胁模型里的
**TB-04 / TB-06 / TB-09 / TB-12 四条信任边界完全没有零信任规则**——
其中 TB-09（服务到消息层）尤其危险：只靠「能连上 broker」就能读全部主题，
是最常见的横向移动路径。四条已补齐。

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-zerotrust.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **没有任何代码执行这份策略**。`libs/zerotrust/reference/decision.py` 是**判定的形状**，
  不是运行中的 PDP。真实系统需要把它接进网关、服务与数据层，那属于有服务代码的批次。
  换句话说：本批次证明的是「这套规则自洽且每个因素都承重」，
  **不是**「线上真的这么判」。
- **因素只是名字，没有验证逻辑**。`device_posture`、`workload_attestation`、
  `phishing_resistant_mfa` 在模型里只是集合里的字符串。
  它们各自怎么验证是 **B17（身份）、B18（WebAuthn）、B19（RBAC/ABAC）、B20（KMS）** 的事。
  本批次**没有**验证过任何一个因素的真实强度。
- **`ZT_HIGH_RISK` 是一份人工枚举的清单**（4 项，其中 ledger_entry 明确豁免留给 B72）。
  它抓不到「新增了一个高风险动作但没登记」的情况。
  真正的覆盖需要与 B11 的写操作清单做交叉，这是**已知缺口**，建议在 B19 补上。
- **会话与撤销只有数字，没有机制**。60 秒全局撤销是一个**要求**，
  实现它需要令牌吊销列表或短期令牌 + 中心校验，属于 B17。
- **审计只检查了字段齐全**，没有检查审计本身不可篡改的**实现**（哈希链/WORM），
  那属于 B23（不可变审计）。
- **紧急通道的四眼复核在模型里是「approver ≠ requester」**，
  没有建模审批人的权限、审批时效与串谋。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B16/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B15 完成文件哈希。
**W02 首个批次。** 注意剩余风险 `RR-05`（独立审查者由 agent 代填）到本批次仍未解决。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| 服务拆开后「内网调用」大量出现 | 一旦某个网段被当作可信，攻陷任意一个内网组件即可横向移动到全部 | `network_location_grants` 必须为空 + 判定函数从不读网络 + **同一请求换网络标签判定必须一致**的测试 |
| 管理后台是最高价值目标 | 钓鱼拿到运营凭据即可批退款、改风控（AC-05） | 抗钓鱼 MFA + 设备状态 + step-up + 四眼复核 + 操作理由进审计（NN-11） |
| 服务账号密码最容易长期存在 | 三年前泄露的密码今天依然有效（NN-07） | 禁止静态长期凭据；工作负载证书 60 分钟、每天轮换；CI 用 OIDC 换 15 分钟令牌 |
| 租户来自请求体 | 改一个字段就是跨租户越权（NN-09、FF-06） | `ZT_TENANT_BINDING`：租户必须绑定到凭据；与 B13 的强制 RLS 互为纵深 |
| 审计常被简化成「只记失败」 | 事后调查时无法知道攻击者**被允许**做了什么（CTRL-007） | `ZT_AUDIT_ALLOW_ONLY` + 判定函数把审计记录作为返回值的一部分，调用方无法忘记 |
| 紧急通道是唯一能跨租户的路径 | 它最容易被当成「临时方案」长期开着 | 必须时间受限 + 四眼 + 抗钓鱼 MFA + 理由；与 B13 声明的紧急通道强制一致 |
| 消息层常被忽略 | 「能连上 broker」就能读全部租户的事件（TB-09，本批次补上的缺口） | TB-09 要求工作负载证明 + 租户绑定 + 审计 |
