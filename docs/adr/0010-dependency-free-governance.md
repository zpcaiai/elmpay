# ADR-0010: 治理工具链零第三方依赖

- 状态：accepted
- 日期：2026-08-18
- 批次：B02
- 决策者：payment-platform-platform-eng
- 关联需求：PAY-REQ-0049
- 关联控制：NN-12, CTRL-011
- 取代：无

## 背景

治理门禁必须能在离线构建代理、证据沙箱与灾难恢复环境中运行；任何第三方依赖都会引入供应链风险，并让门禁在包索引不可达时失效。

## 决策

`tools/paygov` 只允许使用 Python 3.10+ 标准库，允许清单在 `tools/paygov/hygiene.py` 中显式维护，越界即构建失败。

## 后果

需要自行实现结构校验、YAML/Markdown 生成等能力，代码量增加；换来的是门禁在任何环境都能运行且自身供应链面积为零。

## 备选方案

（a）使用 jsonschema + PyYAML：拒绝，门禁会依赖包索引可达性；（b）用外部 lint 服务：拒绝，引入网络与保密风险。

## 验证

`test_b00_repo_hygiene.py::test_detects_third_party_import_in_toolchain`。
