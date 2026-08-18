#!/usr/bin/env python3
from pathlib import Path
import shutil
BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parents[1]
for host in [ROOT / ".agents" / "skills", ROOT / ".claude" / "skills"]:
    host.mkdir(parents=True, exist_ok=True)
    for skill in (BASE / "skills").iterdir():
        if skill.is_dir():
            dst = host / skill.name
            if dst.exists(): shutil.rmtree(dst)
            shutil.copytree(skill, dst)
print("host mirrors rendered")
