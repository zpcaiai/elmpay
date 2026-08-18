# B05 plan — 持续集成与质量基线

Batch: 持续集成与质量基线 · Wave W00 · Skill `pay-dev-platform-ci` · depends_on: [B03, B04]

## 1. 范围

把编译、静态分析、测试、供应链扫描、镜像签名与证据归档纳入 CI，并使其**不可被悄悄放宽**：

1. `governance/ci-pipeline.json`：12 个阶段、6 条阻断条件、质量门槛、
   权限最小化声明与逐个 SHA 固定的第三方 Action。
2. 生成式 CI：`.github/workflows/ci.yml`、`scripts/sign-artifacts.sh`（`tools/paygov/cigen.py`）。
3. `tools/paygov/ci.py`：阶段图、fail-closed、Action 固定、权限、质量门槛、
   阻断条件与生成漂移的门禁。
4. `scripts/archive-evidence.py`：校验全部已完成批次后打包不可变证据 bundle，
   任一批次不通过则**拒绝出包**。
5. `tools/tests/test_b05_ci.py`：27 个用例。

## 2. 受影响组件

`governance/ci-pipeline.json`、`tools/paygov/{ci,cigen}.py`、`.github/workflows/ci.yml`、
`scripts/{render-ci.py,sign-artifacts.sh,archive-evidence.py}`、`tools/tests/`。

## 3. 领域接口与数据契约

- 阶段契约：`id`、`name`、`purpose`、`needs[]`、`commands[]`、`required`、`fail_closed`、
  `gate`（RG0–RG7）、`artifacts[]`、`timeout_minutes`（0 < t ≤ 120）。
- **不变量**：`required` 的阶段必须 `fail_closed`；阶段图必须无环且引用可解析。
- Action 固定：`ref` 必须是 40 位十六进制 commit SHA；tag 可被移动到任意代码，因此不接受。
- 权限：`contents: read`，任何 `write-all` 均被拒绝；工作流不得出现
  `pull_request_target`、`continue-on-error: true` 或直接内联 `${{ secrets. }}`。
- 质量门槛：`unit_test_failed_max`、`skipped_critical_max`、
  `blocking_security_findings_max`、`governance_problems_max` **必须为 0**——
  没有“通过但有告警”的状态（NN-12）。
- 阻断条件（批次文件要求）：BLOCK-01 严重安全问题、BLOCK-02 账本不平、
  BLOCK-03 不可恢复、BLOCK-04 关键证据缺失，另加 BLOCK-05 关键测试被跳过、
  BLOCK-06 制品未签名；每条必须绑定到确实能检测它的阶段。
- 终局门：`release-gate` job 依赖全部必需阶段，只要有 failure/cancelled/skipped 即失败。

## 4. 错误语义

`CI_STAGE`、`CI_FAIL_OPEN`、`CI_REQUIRED_STAGE`、`CI_NEEDS`、`CI_CYCLE`、`CI_ACTION`、
`CI_ACTION_PIN`、`CI_PERMISSIONS`、`CI_QUALITY_GATE`、`CI_BLOCKING`、`CI_BLOCKING_MISSING`、
`CI_UNSAFE_WORKFLOW`、`CI_DRIFT`、`CI_MISSING`、`CI_DUPLICATE`。

## 5. 命令

```bash
python3 scripts/render-ci.py --check
python3 -m tools.paygov.cli verify ci-pipeline --repo .
python3 scripts/archive-evidence.py --out build/evidence-bundle.tar.gz
python3 -m unittest discover -s tools/tests -t . -v
python3 scripts/negative-controls.py
```

## 6. 测试策略

| 路径 | 覆盖 |
| --- | --- |
| 正常 | 12 阶段全部通过；Action 全部 SHA 固定；终局 release gate 存在；生成确定性 |
| 拒绝 | 必需阶段 fail-open、Action 用 tag、必需阶段缺失、依赖未知阶段、阶段成环、允许非零安全问题、容忍跳过关键测试、contents 写权限、write-all、删除阻断条件、阻断条件无检测者/未知检测者、阶段无命令、超时无界、手改工作流、工作流缺失 |
| 运行期 | 负向控制扩至 39 个场景（新增 6 个 B05 场景），全部以真实 CLI 验证退出码 |
| 归档 | `archive-evidence.py` 在任一批次不通过时**拒绝出包**（本批次实际触发过一次） |
| 超时 | `--budget-seconds 0` 返回 3 |

## 7. 回滚

纯增量 + 生成文件；`git revert` 后重新运行 `scripts/render-ci.py`。

## 8. 已知限制（诚实声明）

本环境无外网且 Maven 仓库不可达，因此 `./gradlew` 相关阶段（build / unit-test /
static-analysis / dependency-scan / sbom）**在本批次未实际执行**；本批次的证据覆盖的是
流水线**声明与生成的正确性**，以及零依赖治理阶段（governance / secret-scan /
iac-scan / negative-controls / evidence-archive）的**真实运行**。
Gradle 阶段的首次真实运行证据将在具备联网构建代理后补齐，并与 `RR-02` 一同复审（B05→B109）。

## 9. 数据迁移

无。

## 10. 证据与审查

`evidence/B05/`；执行者 `claude-agent`，独立审查者 `Ethan`。
依赖 B03、B04 完成文件哈希写入 `evidence/completion/B05.json`。
