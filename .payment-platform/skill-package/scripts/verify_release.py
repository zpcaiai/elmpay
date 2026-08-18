#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys
script = Path(__file__).resolve().parent / "orchestrate.py"
repo = sys.argv[1] if len(sys.argv) > 1 else "."
raise SystemExit(subprocess.call([sys.executable, str(script), "release", "--repo", repo]))
