#!/usr/bin/env python3
"""Prove that every validator rule is load-bearing, by deleting it.

The rule-coverage gate (`tools/paygov/rulecov.py`) is a *textual* tripwire: it
checks that a rule code is mentioned somewhere in the tests. This script is the
real proof. For each rule code it builds a throwaway copy of the repository in
which that rule's findings are suppressed, then runs the tests that claim to
cover it. If those tests still pass, the rule is decoration and the script
fails.

The suppression seam exists only in the temporary copy — nothing in the shipped
toolchain can be silenced by an environment variable.

    scripts/rule-knockout.py                 # every rule (slow)
    scripts/rule-knockout.py --codes A,B     # a specific set
    scripts/rule-knockout.py --out report.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.paygov.rulecov import emitted_codes  # noqa: E402

COPY_DIRS = ("tools", "scripts", "governance", "docs", "platform", "gradle", "evidence",
             ".payment-platform", ".github")
COPY_FILES = ("settings.gradle.kts", "build.gradle.kts", ".tool-versions", "README.md",
              "SECURITY.md", "Makefile", "CODEOWNERS", "LICENSE")

SEAM = '''

# --- knockout seam (temporary copy only) -------------------------------------
_paygov_original_validate = validate


def validate(root, budget=None, *args, **kwargs):  # type: ignore[no-redef]
    import os as _os
    suppressed = {c for c in _os.environ.get("PAYGOV_KNOCKOUT", "").split(",") if c}
    return [p for p in _paygov_original_validate(root, budget, *args, **kwargs)
            if p.code not in suppressed]
'''


def build_copy(destination: Path) -> Path:
    root = destination / "repo"
    root.mkdir(parents=True)
    for name in COPY_DIRS:
        source = ROOT / name
        if source.is_dir():
            shutil.copytree(source, root / name, symlinks=False)
    for name in COPY_FILES:
        if (ROOT / name).is_file():
            shutil.copyfile(ROOT / name, root / name)
    for module in sorted((root / "tools" / "paygov").glob("*.py")):
        text = module.read_text(encoding="utf-8")
        if "\ndef validate(" in text:
            module.write_text(text + SEAM, encoding="utf-8")
    return root


def covering_tests(code: str) -> list[str]:
    modules = []
    for path in sorted((ROOT / "tools" / "tests").glob("test_*.py")):
        if code in path.read_text(encoding="utf-8"):
            modules.append(f"tools.tests.{path.stem}")
    return modules


def run(root: Path, modules: list[str], code: str) -> bool:
    """True when the suite still passes with the rule suppressed (i.e. BAD)."""
    env = dict(os.environ, PAYGOV_KNOCKOUT=code)
    proc = subprocess.run([sys.executable, "-m", "unittest", *modules],
                          cwd=root, env=env, capture_output=True, text=True, timeout=600)
    return proc.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codes", help="comma separated subset")
    parser.add_argument("--slice", help="i/n — run shard i of n, for chunked execution")
    parser.add_argument("--out")
    args = parser.parse_args()

    emitted = emitted_codes(ROOT)
    codes = [c.strip() for c in args.codes.split(",")] if args.codes else sorted(emitted)
    if args.slice:
        index, total = (int(x) for x in args.slice.split("/"))
        codes = [c for n, c in enumerate(codes) if n % total == index]

    # The seam wraps a module-level validate(); codes emitted from modules that
    # have none (cli.py, for instance) cannot be suppressed this way, so they are
    # reported separately instead of being miscounted as weak.
    seamless = {name for name in (ROOT / "tools" / "paygov").glob("*.py")
                if "\ndef validate(" not in name.read_text(encoding="utf-8")}
    seamless_names = {p.relative_to(ROOT).as_posix() for p in seamless}

    survivors: list[dict] = []
    not_applicable: list[str] = []
    load_bearing = 0
    with tempfile.TemporaryDirectory(prefix="paygov-knockout-") as tmpdir:
        root = build_copy(Path(tmpdir))
        for code in codes:
            modules = covering_tests(code)
            if not modules:
                survivors.append({"code": code, "reason": "no test module mentions it",
                                  "emitted_at": emitted.get(code, [])})
                print(f"[GAP ] {code}: no test module mentions it")
                continue
            sites = emitted.get(code, [])
            if sites and all(s.split(":")[0] in seamless_names for s in sites):
                not_applicable.append(code)
                print(f"[N/A ] {code}: emitted outside a validate() seam; covered by {modules}")
                continue
            still_green = run(root, modules, code)
            if still_green:
                survivors.append({"code": code, "reason": "tests pass with the rule suppressed",
                                  "tests": modules, "emitted_at": emitted.get(code, [])})
                print(f"[WEAK] {code}: {len(modules)} module(s) still pass without it")
            else:
                load_bearing += 1
                print(f"[OK  ] {code}: removing it breaks {len(modules)} module(s)")

    report = {"codes_checked": len(codes), "load_bearing": load_bearing,
              "seam_not_applicable": sorted(not_applicable),
              "not_load_bearing": survivors}
    if args.out:
        out = ROOT / args.out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
    print(f"\ncodes={len(codes)} load_bearing={load_bearing} "
          f"seam_not_applicable={len(not_applicable)} not_load_bearing={len(survivors)}")
    return 0 if not survivors else 1


if __name__ == "__main__":
    raise SystemExit(main())
