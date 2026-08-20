# B23 plan — 不可抵赖审计与防篡改日志

Batch: 不可抵赖审计与防篡改日志 · Wave W02 · Skill `pay-secure-coding-audit` · depends_on: [B22, B21]

## 1. 范围

审计日志的价值不在于「记了」，而在于**事后没人能改**。一条能被改的记录，在争议里等于没有记录。

1. `governance/audit-log.json`：哈希链、锚定、记录字段、7 类事件、存储、删除、时钟、访问、验证。
2. `tools/paygov/audit.py`：审计门禁（45 条规则码），含三条跨批次校验——
   B19 的双人/提权动作必须全部留痕、锚点签名密钥必须由 B20 托管、
   审计读取角色必须是 B19 声明的不可提权 `auditor`。
3. `libs/audit/reference/chain.py`：**可执行的防篡改链**（含锚点、密码学删除、证明导出）。
4. `tools/paygov/auditgen.py` + `scripts/render-audit.py`。
5. `scripts/audit-smoke.py`：19 项运行期断言（含一条「**证明我们发现不了什么**」）。
6. `tools/tests/test_b23_audit.py`：87 个用例。
7. `tools/negative/b23.py`：16 个负向控制场景。

## 2. 受影响组件

`governance/{audit-log,ssot-registry}.json`、`tools/paygov/{audit,auditgen}.py`、
`libs/audit/`、`scripts/{render-audit,audit-smoke}.py`、
`contracts/security/audit-contract.json`、`docs/security/AUDIT_LOG.md`、
`tools/tests/test_b23_audit.py`、`tools/negative/b23.py`。**未修改任何既有批次的产物。**

## 3. 领域接口与数据契约

三层，每一层都对应一种「静悄悄就没了」的做法：

- **哈希链**。每条记录的哈希覆盖它自己的规范化字节 + 序号 + 前一条的哈希。
  于是：改一条 → 它之后每条都对不上；删一条 → 序号出现空洞；换顺序 → 链断。
  伪造者就算重算自己那条的哈希，**下一条仍然指着旧值**（有专门的测试）。
- **锚定**。哈希链**发现不了自己的尾巴被剪掉**——删掉最后 N 条，剩下的依然自洽。
  这是构造本身的性质，不是实现缺陷。所以每小时把链头签名交给外部见证方；
  **锚定间隔就等于可被否认窗口的大小**，`deniable_window()` 如实返回它，而不是假装为零。
- **密码学删除**。负载单独加密，删除时销毁负载密钥并保留内容哈希：
  记录仍在、位置仍在、完整性仍可验证，而内容不可读。
  这是「不可抵赖」与「被遗忘权」唯一能同时成立的安排。
- **记录必须带规则版本与请求摘要**。没有规则版本，事后只能回答「现在的规则会不会放行」，
  回答不了「当时为什么放行」——而争议问的永远是后者。
- **能删日志的人和被日志监督的人必须是两拨人**：存储 WORM、应用凭据无删除权、
  审计员不可写、不可提权，且**读取审计日志本身要被审计**。
- **按租户分链**，否则任何有权验证的一方都能看出其它租户的活动量与时间分布。

## 4. 错误语义

`AUDIT_UNREADABLE`、`AUDIT_SHAPE`、`AUDIT_VERSION_FIELD`、`AUDIT_PRINCIPLE`、`AUDIT_NO_CHAIN`、
`AUDIT_WEAK_HASH`、`AUDIT_NO_SEQUENCE`、`AUDIT_SHARED_CHAIN`、`AUDIT_NO_CANONICAL_FORM`、
`AUDIT_NO_ANCHOR`、`AUDIT_ANCHOR_INTERVAL`、`AUDIT_NO_WITNESS`、`AUDIT_ANCHOR_RETENTION`、
`AUDIT_ANCHOR_UNSIGNED`、`AUDIT_ANCHOR_KEY_UNMANAGED`、`AUDIT_MISSING_FIELD`、
`AUDIT_FORBIDDEN_FIELD`、`AUDIT_NO_DENIALS`、`AUDIT_ANONYMOUS_ACTOR`、`AUDIT_CLASS_ID`、
`AUDIT_CLASS_DUPLICATE`、`AUDIT_CLASS_SOURCE`、`AUDIT_PII_FLAG`、`AUDIT_CLASS_NOTES`、
`AUDIT_RETENTION_SHORT`、`AUDIT_RETENTION_BELOW_DATA`、`AUDIT_MUTABLE_STORAGE`、`AUDIT_NO_WORM`、
`AUDIT_SHARED_CREDENTIALS`、`AUDIT_DELETABLE`、`AUDIT_NO_SHREDDING`、`AUDIT_SHRED_LOSES_PROOF`、
`AUDIT_SHRED_BREAKS_CHAIN`、`AUDIT_PII_UNSHREDDABLE`、`AUDIT_CLOCK_SOURCE`、`AUDIT_CLOCK_SKEW`、
`AUDIT_READER_WRITES`、`AUDIT_READER_ELEVATABLE`、`AUDIT_READER_UNKNOWN`、
`AUDIT_ACCESS_UNLOGGED`、`AUDIT_UNREHEARSED`、`AUDIT_REHEARSAL_INTERVAL`、
`AUDIT_NO_INDEPENDENT_VERIFIER`、`AUDIT_ACTION_UNLOGGED`、`AUDIT_ACTION_UNKNOWN`、
`AUDIT_GENERATED_MISSING`、`AUDIT_GENERATED_DRIFT`、`AUDIT_GENERATED`。

运行期状态：`OK`、`MODIFIED`、`SEQUENCE_BROKEN`、`LINK_BROKEN`、`TRUNCATED`、`ANCHOR_INVALID`、
`FORBIDDEN_FIELD`、`CLOCK_REVERSED`。

## 5. 命令

```bash
python3 -m tools.paygov.cli verify audit-log --repo .
python3 scripts/render-audit.py --check
python3 scripts/audit-smoke.py
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 干净的链验证通过；空链也验证通过并可锚定；同一时刻的两条记录允许 |
| **改** | 改负载、改头部、**重算自己那条哈希的伪造** —— 三种都被发现，第三种断在下一条 |
| **删/乱序** | 删中间一条 → 序号空洞；调换顺序 → 断链 |
| **截断（诚实的一条）** | 无锚点时截断尾部**验证通过**——测试断言的就是「发现不了」；有锚点时 `TRUNCATED` |
| 锚点 | 伪造锚点被发现；锚点覆盖的头部被改也被发现；可被否认窗口如实计算 |
| 删除权 | 销毁负载后：记录仍在、哈希不变、链仍通过、内容哈希仍绑定原内容 |
| 写入期 | 禁止字段（卡号/CVV/密码/Authorization）在写入时就被拒；时钟倒退被拒 |
| 隔离 | 不同租户的链互相独立；规范化序列化与键序无关 |
| 拒绝 | 45 条规则各有用例：去掉前哈希、去掉序号、共用一条链、关掉锚定、锚点无见证方、锚点密钥不受托管、去掉规则版本、允许卡号、不记拒绝、存储可变、应用可删、去掉密码学删除、审计员可提权、资金动作不留痕…… |
| 跨批次 | B19 的双人/提权动作缺一即 `AUDIT_ACTION_UNLOGGED`；审计保留期短于 B13 的冷数据保留期即 `AUDIT_RETENTION_BELOW_DATA`；`authorization.json` 损坏时门禁**给出发现而不是崩溃** |
| 失败关闭 | 模型坏到无法生成契约时 `AUDIT_GENERATED`；`--budget-seconds 0` 退出码 3 |
| 运行期 | `audit-smoke.py` 19 项断言；负向控制新增 16 个 B23 场景，共 225 个场景 |
| 删除击杀 | 16 个关键规则码逐个删除，16/16 均导致测试失败（load-bearing） |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-audit.py`。无数据迁移。

## 8. 已知限制（诚实声明）

- **锚点用的是 MAC，不是签名**。参考实现里 `Anchor.mac` 是 HMAC，验证需要同一把密钥——
  这意味着**持有密钥的一方可以伪造锚点**，因此它证明不了「外部见证」。
  真实实现必须用非对称签名 + 第三方时间戳机构，否则锚点只是我们对自己的承诺。
- **可被否认窗口是真实存在的残余风险**（`RR` 级）：最近一次锚定之后的记录可以被无痕删除。
  当前策略是 60 分钟。缩短间隔会线性增加锚定成本，这是一个**需要人来定的取舍**，
  不是可以靠代码消除的问题。
- **没有真实存储**。WORM、对象存储对象锁、独立凭据都是**要求**，
  参考实现是内存里的列表——`append_only` 在这里靠约定而不是靠存储引擎。
- **密码学删除只建模到「负载置空 + 保留哈希」**。真正的负载密钥、每租户密钥销毁与
  备份中的副本，属于 B20 与运维批次；`shred()` 不会去销毁任何密钥。
- **`_retention` 的跨批次比较只看 `money.movement` 一类**。其它事件类别与 B13 各表的
  保留期没有逐一比对——已知缺口，建议在有实现层后按表-事件映射逐一校验。
- **时钟只检查了单调性与偏差上限**。跨节点的时钟一致性、闰秒、以及「记录时间」与
  「事件发生时间」的区别都没有建模。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B23/`；执行者 `claude-agent`，独立审查者 `Ethan`。依赖 B22、B21 完成文件哈希。

## 11. 威胁变化

| 变化 | 威胁 | 控制 |
| --- | --- | --- |
| **有写权限的人想改掉一条记录** | 争议时拿不出可信证据（AC-10） | 哈希链覆盖序号与前哈希；重算单条哈希仍会在下一条断链 |
| 有人删掉中间一条 | 关键动作从历史里消失 | 序号空洞 + 断链，双重可见 |
| **有人剪掉尾巴** | 最近的操作从未发生过 | 每小时签名锚定 + 外部见证；未锚定窗口被如实报告而不是掩盖 |
| 应用被攻陷 | 攻击者用应用凭据删日志 | 存储 WORM + 独立凭据 + 删除只能走密钥销毁 |
| 监管要求删除个人信息 | 「不可变」与「被遗忘权」正面冲突，通常牺牲前者 | 负载密码学删除 + 保留内容哈希，两个承诺同时成立 |
| 卡号进了不可变日志 | 最不该留的数据留在最删不掉的地方 | 禁止字段在**写入时**就被拒 |
| 审计员被临时提权「顺手修一下」 | 审计者能改自己审计的对象 | 读取角色不可写、不可提权，且读取本身被审计 |
| 只有我们能验证 | 争议中说服不了对方 | 要求独立验证器 + 定期演练；`proof()` 导出第三方可校验的最小证明 |
