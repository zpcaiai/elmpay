"""B00 — repository hygiene.

Two classes of finding, both fail-closed:

1. *Credential material in version control* (NN-07/NN-14). Detection is
   pattern-based and deliberately noisy-on-the-safe-side; an intentional
   sample must be written as an obvious placeholder.
2. *Floating-point money* (NN-05) in first-party source.

The vendored skill package and generated trees are excluded — they are inputs,
not first-party code.
"""
from __future__ import annotations

import hashlib

import ast
import re
from pathlib import Path

from .errors import Problem
from .repo import Budget, iter_repo_files

TEXT_SUFFIXES = (".py", ".java", ".kt", ".kts", ".ts", ".tsx", ".js", ".json", ".yaml", ".yml",
                 ".toml", ".md", ".sql", ".sh", ".properties", ".conf", ".env", ".xml", ".gradle",
                 ".tf", ".proto", ".txt", ".pem", ".cfg", ".ini", ".ndjson", "")
MAX_SCAN_BYTES = 2 * 1024 * 1024

SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("SECRET_PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "NN-07"),
    ("SECRET_AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b", "NN-07"),
    ("SECRET_STRIPE_LIVE", r"\bsk_live_[0-9A-Za-z]{16,}", "NN-07"),
    ("SECRET_STRIPE_TEST", r"\bsk_test_[0-9A-Za-z]{16,}", "NN-07"),
    ("SECRET_GENERIC_ASSIGN",
     r"(?i)\b(?:api[_-]?key|secret[_-]?key|private[_-]?key|apiv3[_-]?key|app[_-]?secret|password|passwd)\s*[:=]\s*[\"']?[A-Za-z0-9/+=_-]{16,}[\"']?",
     "NN-07"),
    ("SECRET_JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "NN-07"),
)
# A finding is suppressed only when the line is unambiguously a reference or an
# explicitly reviewed exception. Words such as "example" are NOT accepted: real
# leaked credentials frequently carry them.
PLACEHOLDER_HINTS = ("kms://", "vault://", "REPLACE_WITH", "PLACEHOLDER", "<redacted>",
                     "paygov:allow-secret-pattern")

FLOAT_MONEY_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("MONEY_FLOAT_TYPE",
     r"\b(?:float|double|Float|Double)\s+(?:amount|price|fee|total|balance|refund)\w*",
     "NN-05"),
    ("MONEY_FLOAT_LITERAL",
     r"\b(?:amount|price|fee|total|balance|refund)\w*[\"\']?\s*[:=]\s*-?\d+\.\d+",
     "NN-05"),
)

# Source files that legitimately contain the patterns because they define them.
SELF_EXEMPT = ("tools/paygov/hygiene.py", "tools/tests/test_b00_repo_hygiene.py")


# Registered automatically: tools/paygov/registry.py discovers every module in
# this package that declares VALIDATOR. Adding a batch means adding a module,
# not editing a shared file that every earlier batch is pinned to.
VALIDATOR = ("repo-hygiene", "B00")

def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    problems: list[Problem] = []
    for path in iter_repo_files(root, budget, suffixes=TEXT_SUFFIXES):
        rel = path.relative_to(root).as_posix()
        if rel in SELF_EXEMPT:
            continue
        stat = path.stat()
        if stat.st_size > MAX_SCAN_BYTES:
            continue
        budget.check(rel)
        # Identity key first: when size and nanosecond mtime are unchanged the
        # bytes are unchanged, so the file is not even read. This matters
        # because the negative-control harness runs the whole gate 240 times
        # over a ~1000-file tree that differs by one file each time — reading
        # and hashing the other 999 dominated the run.
        stamp = (rel, stat.st_size, stat.st_mtime_ns)
        cached = _STAT_CACHE.get(stamp)
        if cached is not None:
            problems.extend(cached)
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        found = _scan_cached(rel, text)
        if len(_STAT_CACHE) >= _CACHE_LIMIT:
            _STAT_CACHE.clear()
        _STAT_CACHE[stamp] = found
        problems.extend(found)
    problems.extend(_third_party_imports(root, budget))
    return problems


# Content-keyed memo. ``_scan`` and the import check are pure functions of the
# file's bytes, and the negative-control harness runs the whole gate 180+ times
# over trees that differ by exactly one file. Keying on the SHA-256 of the text
# (not on mtime) means identical content can never be judged differently, and
# the harness stops re-scanning ~250 unchanged files per scenario.
_SCAN_CACHE: dict[tuple[str, str], list[Problem]] = {}
_STAT_CACHE: dict[tuple[str, int, int], list[Problem]] = {}
_IMPORT_CACHE: dict[tuple[str, str, str], list[Problem]] = {}
_CACHE_LIMIT = 8192


def _remember(key, found: list[Problem]) -> list[Problem]:
    if len(_IMPORT_CACHE) >= _CACHE_LIMIT:
        _IMPORT_CACHE.clear()
    _IMPORT_CACHE[key] = found
    return list(found)


def _scan_cached(rel: str, text: str) -> list[Problem]:
    key = (rel, hashlib.sha256(text.encode("utf-8")).hexdigest())
    hit = _SCAN_CACHE.get(key)
    if hit is None:
        hit = _scan(rel, text)
        if len(_SCAN_CACHE) >= _CACHE_LIMIT:
            _SCAN_CACHE.clear()
        _SCAN_CACHE[key] = hit
    return list(hit)


def _scan(rel: str, text: str) -> list[Problem]:
    problems: list[Problem] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        if any(hint in line for hint in PLACEHOLDER_HINTS):
            continue
        for code, pattern, rule in SECRET_PATTERNS:
            if re.search(pattern, line):
                problems.append(Problem(code, f"{rel}:{lineno}",
                                        "possible credential material committed to version control",
                                        rule))
        if rel.startswith(("libs/", "services/", "connectors/", "apps/", "governance/")):
            for code, pattern, rule in FLOAT_MONEY_PATTERNS:
                if re.search(pattern, line):
                    problems.append(Problem(code, f"{rel}:{lineno}",
                                            "monetary value expressed as binary floating point",
                                            rule))
    return problems


def _third_party_imports(root: Path, budget: Budget) -> list[Problem]:
    """paygov must stay standard-library only so it runs on offline agents."""
    allowed_roots = {
        "__future__", "json", "re", "time", "pathlib", "typing", "dataclasses", "sys", "os",
        "argparse", "hashlib", "subprocess", "datetime", "collections", "itertools", "unittest",
        "tempfile", "shutil", "textwrap", "contextlib", "io", "string", "math", "copy",
        "threading", "concurrent", "uuid", "secrets", "statistics", "functools", "enum",
        "csv", "abc", "operator", "difflib", "unicodedata", "ast",
        "hmac", "hashlib", "http", "urllib", "socket", "socketserver", "base64",
        "random", "libs", "decimal", "fractions", "importlib", "pkgutil", "multiprocessing",
    }
    problems: list[Problem] = []
    scanned = sorted((root / "tools").rglob("*.py")) + \
        sorted((root / "libs").rglob("*.py"))
    for path in scanned:
        budget.check(str(path))
        rel = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8")
        key = ("imports", rel, hashlib.sha256(source.encode("utf-8")).hexdigest())
        cached = _IMPORT_CACHE.get(key)
        if cached is not None:
            problems.extend(cached)
            continue
        found: list[Problem] = []
        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError as exc:
            found.append(Problem("TOOLCHAIN_SYNTAX", f"{rel}:{exc.lineno or 0}",
                                 f"file does not parse: {exc.msg}", "NN-12"))
            problems.extend(_remember(key, found))
            continue
        # Parse rather than grep: prose in a docstring can begin with "from"
        # or "import", and a false positive in a fail-closed gate is an outage.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # relative import inside the package
                    continue
                names = [(node.module or "").split(".", 1)[0]]
            else:
                continue
            for module in names:
                if module in {"tools", "paygov", ""}:
                    continue
                if module not in allowed_roots:
                    found.append(Problem("TOOLCHAIN_THIRD_PARTY", f"{rel}:{node.lineno}",
                                            f"paygov must be dependency free; '{module}' is not "
                                            f"in the standard-library allow list", "NN-12"))
        problems.extend(_remember(key, found))
    return problems
