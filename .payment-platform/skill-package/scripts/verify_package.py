#!/usr/bin/env python3
from __future__ import annotations
import ast, hashlib, json, re, sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parents[1]
errors = []
manifest = json.loads((BASE / "manifest.json").read_text(encoding="utf-8"))

if len(manifest.get("batches", [])) != 128: errors.append("manifest must contain 128 batches")
if len(manifest.get("skills", [])) != 65: errors.append("manifest must contain 65 skills including orchestrator")

ids = [b["id"] for b in manifest["batches"]]
if ids != [f"B{i:02d}" for i in range(128)]: errors.append("batch ids/order invalid")

# DAG and initial ready.
bmap = {b["id"]: b for b in manifest["batches"]}
for b in manifest["batches"]:
    for d in b["depends_on"]:
        if d not in bmap: errors.append(f"unknown dependency {d} in {b['id']}")
        elif bmap[d]["order"] >= b["order"]: errors.append(f"non-forward dependency {b['id']}->{d}")
initial = [b["id"] for b in manifest["batches"] if not b["depends_on"]]
if initial != ["B00"]: errors.append(f"only B00 may be initially ready, got {initial}")

for b in manifest["batches"]:
    p = BASE / "batches" / f"{b['id']}.md"
    if not p.exists() or p.stat().st_size < 1800:
        errors.append(f"batch document missing or too small: {p}")
        continue
    txt = p.read_text(encoding="utf-8")
    if f"id: {b['id']}" not in txt[:500] or f"skill: {b['skill']}" not in txt[:500]:
        errors.append(f"batch frontmatter mismatch: {p}")

frontmatter_re = re.compile(r"^---\n(.*?)\n---\n", re.S)
for s in manifest["skills"]:
    p = BASE / "skills" / s["name"] / "SKILL.md"
    if not p.exists(): errors.append(f"canonical skill missing: {p}"); continue
    txt = p.read_text(encoding="utf-8")
    m = frontmatter_re.match(txt)
    if not m or f"name: {s['name']}" not in m.group(1) or "description:" not in m.group(1): errors.append(f"frontmatter invalid: {p}")
    if len(txt.splitlines()) > 500: errors.append(f"skill exceeds 500 lines: {p}")
    host_roots = [h for h in [ROOT / ".agents" / "skills", ROOT / ".claude" / "skills"] if h.exists()]
    if not host_roots:
        errors.append("at least one host skill directory is required")
    for host in host_roots:
        hp = host / s["name"] / "SKILL.md"
        if not hp.exists(): errors.append(f"host skill missing: {hp}")
        elif hp.read_bytes() != p.read_bytes(): errors.append(f"host mirror differs: {hp}")

for p in (BASE / "schemas").glob("*.json"):
    try: json.loads(p.read_text(encoding="utf-8"))
    except Exception as e: errors.append(f"invalid json schema {p}: {e}")

for p in (BASE / "scripts").glob("*.py"):
    try: ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
    except Exception as e: errors.append(f"invalid python script {p}: {e}")

required_assets = {
    "contracts/openapi.yaml": 4000,
    "contracts/asyncapi.yaml": 1000,
    "contracts/provider-adapter.proto": 1500,
    "sql/reference-schema.sql": 5000,
    "security/THREAT_MODEL.md": 1500,
    "security/ANTI_PHISHING_BLUEPRINT.md": 1000,
    "testing/RELEASE_CERTIFICATION.md": 500,
}
for rel, minimum in required_assets.items():
    p = BASE / rel
    if not p.is_file() or p.stat().st_size < minimum:
        errors.append(f"required asset missing or too small: {p}")

acceptance = (BASE / "testing" / "acceptance-catalog.yaml").read_text(encoding="utf-8")
if len(re.findall(r"(?m)^- id: AT-B\d{2,3}-01$", acceptance)) != 128:
    errors.append("acceptance catalog must contain 128 batch entries")
attacks = (BASE / "security" / "attack-scenarios.yaml").read_text(encoding="utf-8")
if len(re.findall(r"(?m)^- id: [A-Z0-9-]+$", attacks)) < 60:
    errors.append("attack scenario catalog must contain at least 60 entries")

checksum_file = ROOT / "CHECKSUMS.sha256"
if checksum_file.is_file():
    for lineno, line in enumerate(checksum_file.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            expected, rel = line.split("  ", 1)
        except ValueError:
            errors.append(f"invalid checksum line {lineno}")
            continue
        target = ROOT / rel
        if not target.is_file():
            errors.append(f"checksummed file missing: {rel}")
        elif hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            errors.append(f"checksum mismatch: {rel}")

banned = re.compile(r"\b(TODO|FIXME|TBD)\b|lorem ipsum", re.I)
for p in BASE.rglob("*"):
    if p.resolve() == Path(__file__).resolve():
        continue
    if p.is_file() and p.suffix in {".md", ".yaml", ".yml", ".json", ".py", ".sql", ".proto"}:
        txt = p.read_text(encoding="utf-8", errors="ignore")
        if banned.search(txt): errors.append(f"placeholder marker found: {p}")

print(json.dumps({"ok": not errors, "errors": errors, "batches": len(manifest["batches"]), "skills": len(manifest["skills"])}, ensure_ascii=False, indent=2))
sys.exit(0 if not errors else 2)
