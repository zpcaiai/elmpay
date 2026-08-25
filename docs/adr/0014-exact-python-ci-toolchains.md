# ADR-0014: CI 同时固定 Python 参考解释器与兼容地板

- 状态：accepted
- 日期：2026-08-26
- 批次：B05
- 决策者：payment-platform-platform-eng payment-platform-security
- 关联需求：PAY-REQ-0049
- 关联控制：NN-12, CTRL-011, CTRL-018
- 取代：ADR-0013

## 背景

ADR-0013 规定治理工具链保持 Python 3.10 语言与标准库兼容，并在版本目录登记 3.12.7
参考解释器。然而版本声明没有进入 CI 的执行路径：GitHub runner 自带的 `python3` 会随镜像
更新，常规治理 job 与签名 job 实际使用哪个补丁版本不可复现；同时 CI 没有在最旧解释器上
真实执行完整门禁。静态 AST 规则只能覆盖已登记的语法和标准库差异，无法证明导入、文件系统、
序列化及退出码在兼容地板上仍然一致。

## 决策

`python-toolchain.version` 精确固定为 3.12.7，作为常规 CI job（包括签名 job）的参考解释器；
`.tool-versions` 由版本目录生成同一固定值。`minimum_supported` 精确固定为 3.10.12，并新增
必需且 fail-closed 的 `python-floor` job。该 job 使用固定提交的 `actions/setup-python` 安装
3.10.12，运行完整 `verify-all`，原子输出并强制上传 `python-floor-report.json`。

3.10.12 的主次版本继续定义 Python 3.10 的语法和标准库兼容面；补丁号定义实际交付路径上
最旧、可重复安装的运行时。签名 job 必须依赖 `python-floor`，因此任何仅能在参考解释器通过、
却不能在兼容地板形成机器裁决的提交都不能进入签名与证据归档链。setup action 本身固定到
`actions/setup-python` v7.0.0 对应的完整提交 SHA，避免可移动标签改变安装行为。

## 后果

- 常规 job 与兼容地板 job 使用的解释器都可以从提交内容唯一还原；
- CI 增加一次完整治理校验，耗时增加，但它与编译、供应链扫描并行，不延长其依赖链；
- Python 地板的补丁版本也成为受治理输入，修改参考版本、地板或 setup action 必须同时更新
  版本目录、ADR、生成物和拒绝路径测试；
- 本地高于地板的解释器仍可用于开发，但不能替代 CI 中的真实地板执行证据。

## 备选方案

（a）继续依赖 runner 预装 Python：拒绝，因为 runner 镜像更新会在仓库无变更时改变裁决环境；
（b）只固定 3.12.7：拒绝，因为静态兼容扫描不能替代 3.10.12 上的真实完整执行；
（c）只运行 3.10.12：拒绝，因为产出证据的参考环境也需要稳定，且模拟器与治理工具统一在
3.12.7 可减少维护分叉；（d）使用 `3.10` 或 `3.x` 输入：拒绝，因为该输入允许补丁版本漂移。

## 验证

B05 校验器要求 `actions/setup-python` 只出现一次声明且固定到审计提交，要求版本目录中的参考
与地板分别精确为 3.12.7 和 3.10.12，并要求 `python-floor` 直接依赖治理 job、保留 20 分钟
上限、输出唯一机器报告且缺失即失败。生成器为每个 CI stage 注入 setup-python：仅 floor job
使用 3.10.12，其余 stage 使用 3.12.7。突变测试覆盖 action SHA、floor fail-open、签名依赖
移除、报告路径与生成工作流漂移；B03 生成物测试锁定 `.tool-versions` 的参考解释器固定值。
