#!/bin/sh
# The bridge mount forbids unlink(2), so Git cannot remove its own lock files
# after a write and every later command fails on the leftover. Renaming is
# permitted, so the locks are moved aside instead. Only for use from the
# bridge workspace; on a normal filesystem plain git needs none of this.
set -e
cd "$(dirname "$0")/.."
mkdir -p _to_delete/gitlocks
git "$@" || status=$?
for lock in .git/index.lock .git/config.lock .git/HEAD.lock .git/refs/heads/*.lock; do
  [ -e "$lock" ] && mv "$lock" "_to_delete/gitlocks/$(basename "$lock").$$" 2>/dev/null || true
done
exit ${status:-0}
