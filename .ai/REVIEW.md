# 独立复核签发指引（`evidence/<batch>/review.json`）

执行方是 `claude-agent`，复核方是 `Ethan`（`governance/project-config.json` 的
`evidence` 段）。这份文件是复核方的批准，**不能由执行方代写**——自己签自己的批准，
就是 B25 里 `mark_verified()` 恒抛 `DENY_SELF_VERIFIED` 所禁止的那件事。

## 每个批次三步

1. 让驱动跑到复核边界，它会把该批次的模板连同算好的绑定哈希一起打印出来：

   ```bash
   python3 .ai/rebaseline.py resume --from B00 --to B33 --launch-window-seconds 1
   ```

   输出里的 `expected_review` 就是模板。**不要用旧的副本**：`bindings.git_head` 等字段
   随 HEAD 变化，模板必须现取。

2. 复核后填三个字段，其余原样保留，存为 `evidence/<batch>/review.json`：

   - `reviewed_at`：带时区的 ISO-8601，例如 `2026-08-20T21:30:00+08:00`
   - `scope`：你实际复核了什么
   - `notes`：独立复核意见，不能为空

   `reviewer` 必须是 `Ethan`，`executor` 必须是 `claude-agent`，`decision` 为 `approved`。
   校验器要求键集恰好是这九个，多一个少一个都会被拒。

3. 让 Git 跟踪它（**不必立即 commit**——`git add` 即可，这样 HEAD 不动，
   `bindings.git_head` 不会失效）：

   ```bash
   git add evidence/<batch>/review.json
   ```

   然后继续跑 `resume`，该批次的 traceability 与完成文件才会被原子替换。

## 重签在途时不要 commit

`resume` 的状态绑定 Git HEAD。**在命令重放与复核签发之间新建提交，会让状态整体作废**
（`resume state is stale (git_head)`），必须 `reset` 并把该批次的命令全部重跑一遍。

所以顺序是：先把要提交的代码改动提交干净 → 再跑 `resume` → 期间只 `git add`、不 commit
→ 拿到签发、批次定稿之后，再一次性提交证据与 `review.json`。

## 为什么不能批量预生成

绑定里含 `git_head` 与逐产物 SHA-256。上一个批次定稿会改动证据树，下一个批次的绑定
随之变化。所以是「跑到边界 → 取模板 → 签 → 继续」的逐批循环，不是一次性签 33 份。

## 桥接工作区的注意事项

挂载不允许 `unlink(2)`，Git 写操作后会残留 `.git/index.lock`，下一条命令会报
"Another git process seems to be running"。`.ai/gitsafe.sh` 是同样的 git 调用，
但会在之后把锁文件挪进 `_to_delete/gitlocks/`。在正常文件系统上直接用 `git` 即可。
