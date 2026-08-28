#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for tool in java swift dart; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "required mobile SDK test tool is unavailable: $tool" >&2
    exit 1
  }
done

"$repo_root/gradlew" -p "$repo_root" :sdks:mobile:android:test --no-daemon
swift test --package-path "$repo_root/sdks/mobile/ios"
(
  cd "$repo_root/sdks/mobile/flutter"
  dart pub get
  dart test
)
