"""paygov command line entry point.

Exit codes are contractual, because CI and the batch evidence gate branch on
them:

* ``0`` — every selected validator passed
* ``2`` — at least one governance problem was found
* ``3`` — a validator could not complete (unreadable input, budget exceeded)

There is no exit code that means "passed with warnings"; NN-12 forbids it.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from . import registry
from .errors import GovernanceError, Problem, render
from .repo import Budget, repo_root

EXIT_OK = 0
EXIT_PROBLEMS = 2
EXIT_ERROR = 3


def _write_report(root: Path, destination: str, output: str) -> None:
    """Atomically persist the exact JSON emitted on stdout inside the repo.

    CI uploads these reports as gate evidence.  A missing, redirected, or
    partially written report must therefore fail the command instead of being
    treated as an optional logging concern.
    """
    requested = Path(destination)
    path = requested if requested.is_absolute() else root / requested
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise GovernanceError(f"report path escapes repository: {destination}") from exc

    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise GovernanceError(f"report path contains a symlink: {destination}")
    try:
        path.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise GovernanceError(f"report path resolves outside repository: {destination}") from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise GovernanceError(f"report path is not a regular file: {destination}")

    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            # Findings can describe sensitive paths or configuration. Keep the
            # temporary and published report private to this execution user.
            os.fchmod(stream.fileno(), 0o600)
            stream.write(output)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def run(names: list[str], root: Path, budget_seconds: float) -> tuple[int, str]:
    registry.load_all()
    selected = names or registry.names()
    unknown = [n for n in selected if n not in registry.names()]
    if unknown:
        return EXIT_ERROR, render([Problem("CLI_UNKNOWN_VALIDATOR", "argv",
                                           f"unknown validator(s): {unknown}")])
    problems: list[Problem] = []
    for name in selected:
        budget = Budget(seconds=budget_seconds).start()
        try:
            problems.extend(registry.get(name)(root, budget))
        except GovernanceError as exc:
            return EXIT_ERROR, render([Problem("VALIDATOR_ABORTED", name, str(exc), "NN-12")])
        except Exception as exc:  # noqa: BLE001 - a crashing validator must fail closed
            return EXIT_ERROR, render([Problem(
                "VALIDATOR_CRASHED", name,
                f"{type(exc).__name__}: {exc}", "NN-12")])
    return (EXIT_PROBLEMS if problems else EXIT_OK), render(problems)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="paygov", description="elmpay repository governance gate")
    parser.add_argument("command", choices=["verify-all", "verify", "list-validators"])
    parser.add_argument("names", nargs="*", help="validator names for 'verify'")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--budget-seconds", type=float, default=30.0,
                        help="wall-clock budget per validator; exceeding it fails closed")
    parser.add_argument("--out", help="atomically write the JSON result inside the repository")
    args = parser.parse_args(argv)

    try:
        root = repo_root(Path(args.repo).resolve())
    except GovernanceError as exc:
        print(render([Problem("CLI_NO_REPO", args.repo, str(exc))]))
        return EXIT_ERROR

    if args.command == "list-validators":
        if args.out:
            parser.error("--out is only valid with verify or verify-all")
        registry.load_all()
        for name in registry.names():
            print(f"{registry.batch_of(name)}\t{name}")
        return EXIT_OK

    names = args.names if args.command == "verify" else []
    code, output = run(names, root, args.budget_seconds)
    if args.out:
        try:
            _write_report(root, args.out, output)
        except (GovernanceError, OSError) as exc:
            print(render([Problem("CLI_REPORT_WRITE", args.out, str(exc), "NN-12")]))
            return EXIT_ERROR
    print(output)
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
