#!/bin/sh
cd "$(dirname "$0")/.."
timeout 41 python3 .ai/rebaseline.py resume --from B00 --to B33 --launch-window-seconds "${1:-12}" > /tmp/rb.json 2>&1
python3 - <<'PY'
import json
try:
    st = json.load(open(".ai/.state/rebaseline.json"))["progress"]
except Exception as exc:
    st = {"err": str(exc)}
try:
    d = json.load(open("/tmp/rb.json"))
    status, n = d.get("status"), len(d.get("actions", []))
    extra = "" if status in ("ok", "advanced", "in-progress", "complete") else \
        json.dumps({k: v for k, v in d.items() if k not in ("actions", "progress")},
                   ensure_ascii=False)[:700]
except Exception:
    status, n, extra = "killed-mid-slice", 0, ""
print(status, n, json.dumps(st, ensure_ascii=False), extra)
PY
