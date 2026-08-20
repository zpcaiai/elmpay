# 恢复 git 历史（一次性操作）

- 文档 ID：DOC-REPO-001
- 版本：1.1.0
- 状态：active

## 背景

本仓库所在的目录是通过只读删除策略挂载给自动化执行者的：git 无法在其中删除自己的
`*.lock` 文件，第一次 `git init` 之后仓库即被锁死。为了仍然产生**真实的提交与真实的
commit SHA**（证据完整性依赖于此），git 目录被放在工作目录之外，仓库内的 `.git`
是一个指向它的 gitdir 指针文件。

同时，被锁死的第一个 `.git` 目录被移动到 `_to_delete/git-broken-20260818/`
（执行者没有删除权限）。

## 当前恢复状态（2026-08-20）

历史已经从 `elmpay-history.bundle` 恢复到持久路径
`/Users/stephen/.codex/gitstores/elmpay-recovered-20260820.git`，仓库内 `.git` 已指向该目录。
如果 `git status` 正常，**不要重复执行恢复步骤**。恢复出的 bundle 历史止于 B07；
B08 之后的工作在本工作树中，因此必须先审阅并提交这些文件，随后才能重新签发证据。

## 指针再次失效时恢复

```bash
cd /Users/stephen/Documents/Projects/python/elmpay

# 1. 保留失效指针，便于追查
mv .git .git.stale-$(date +%Y%m%d%H%M%S)

# 2. 从 bundle 恢复完整历史到工作树之外的持久位置
git clone --separate-git-dir=/Users/stephen/.codex/gitstores/elmpay-recovered.git \
  elmpay-history.bundle /tmp/elmpay-restore
printf 'gitdir: /Users/stephen/.codex/gitstores/elmpay-recovered.git\n' > .git
git config core.worktree /Users/stephen/Documents/Projects/python/elmpay
git status

# 3. 校验证据仍然成立
python3 scripts/batch.py status
python3 -m tools.paygov.cli verify-all --repo .
python3 -m unittest discover -s tools/tests -t . 
```

`git log` 应能看到 B00–B07 的提交。完成文件只有在其 `commit_sha` 能通过
`git cat-file -e <sha>^{commit}`、产物摘要与依赖摘要均匹配时才有效；恢复 Git 历史本身
不会使已经漂移的证据重新有效。

## 之后

`elmpay-history.bundle` 恢复后即可删除（或保留作为离线备份）。
后续批次请在你的机器上正常使用 git。
