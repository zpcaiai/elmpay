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
import sys
from pathlib import Path

from . import registry
from .errors import GovernanceError, Problem, render
from .repo import Budget, repo_root

EXIT_OK = 0
EXIT_PROBLEMS = 2
EXIT_ERROR = 3


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
    return (EXIT_PROBLEMS if problems else EXIT_OK), render(problems)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="paygov", description="elmpay repository governance gate")
    parser.add_argument("command", choices=["verify-all", "verify", "list-validators"])
    parser.add_argument("names", nargs="*", help="validator names for 'verify'")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--budget-seconds", type=float, default=30.0,
                        help="wall-clock budget per validator; exceeding it fails closed")
    args = parser.parse_args(argv)

    try:
        root = repo_root(Path(args.repo).resolve())
    except GovernanceError as exc:
        print(render([Problem("CLI_NO_REPO", args.repo, str(exc))]))
        return EXIT_ERROR

    if args.command == "list-validators":
        registry.load_all()
        for name in registry.names():
            print(f"{registry.batch_of(name)}\t{name}")
        return EXIT_OK

    names = args.names if args.command == "verify" else []
    code, output = run(names, root, args.budget_seconds)
    print(output)
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
