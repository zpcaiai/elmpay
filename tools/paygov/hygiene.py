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


def validate(root: Path, budget: Budget | None = None) -> list[Problem]:
    budget = budget or Budget().start()
    problems: list[Problem] = []
    for path in iter_repo_files(root, budget, suffixes=TEXT_SUFFIXES):
        rel = path.relative_to(root).as_posix()
        if rel in SELF_EXEMPT:
            continue
        if path.stat().st_size > MAX_SCAN_BYTES:
            continue
        budget.check(rel)
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        problems.extend(_scan(rel, text))
    problems.extend(_third_party_imports(root, budget))
    return problems


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
        "csv", "abc", "operator", "difflib", "unicodedata",
        "hmac", "hashlib", "http", "urllib", "socket", "socketserver", "base64",
    }
    problems: list[Problem] = []
    import_re = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][\w]*)")
    for path in sorted((root / "tools").rglob("*.py")):
        budget.check(str(path))
        rel = path.relative_to(root).as_posix()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = import_re.match(line)
            if not match:
                continue
            module = match.group(1)
            if module in {"tools", "paygov"} or line.lstrip().startswith("from ."):
                continue
            if module not in allowed_roots:
                problems.append(Problem("TOOLCHAIN_THIRD_PARTY", f"{rel}:{lineno}",
                                        f"paygov must be dependency free; '{module}' is not in the "
                                        f"standard-library allow list", "NN-12"))
    return problems
