# 恢复 git 历史（一次性操作）

- 文档 ID：DOC-REPO-001
- 版本：1.0.0
- 状态：active

## 背景

本仓库所在的目录是通过只读删除策略挂载给自动化执行者的：git 无法在其中删除自己的
`*.lock` 文件，第一次 `git init` 之后仓库即被锁死。为了仍然产生**真实的提交与真实的
commit SHA**（证据完整性依赖于此），git 目录被放在执行环境的可写区，仓库内的 `.git`
是一个指向它的 gitdir 指针文件。该指针在执行会话结束后失效。

同时，被锁死的第一个 `.git` 目录被移动到 `_to_delete/git-broken-20260818/`
（执行者没有删除权限）。

## 在你的机器上恢复

```bash
cd /Users/stephen/Documents/Projects/python/elmpay

# 1. 移除失效的 gitdir 指针与损坏的旧目录
rm -f .git
rm -rf _to_delete

# 2. 从 bundle 恢复完整历史（commit SHA 与证据中记录的一致）
git clone elmpay-history.bundle /tmp/elmpay-restore
mv /tmp/elmpay-restore/.git .git
git checkout -- .
git status

# 3. 校验证据仍然成立
python3 scripts/batch.py status
python3 -m tools.paygov.cli verify-all --repo .
python3 -m unittest discover -s tools/tests -t . 
```

`git log` 应能看到 B00–B07 的提交，且 `evidence/completion/*.json` 中的 `commit_sha`
可以用 `git cat-file -e <sha>^{commit}` 验证存在。

## 之后

`elmpay-history.bundle` 恢复后即可删除（或保留作为离线备份）。
后续批次请在你的机器上正常使用 git。
