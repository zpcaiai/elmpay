#!/usr/bin/env python3
"""Render B89 default-deny Kubernetes, Cilium and Istio egress controls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


RUNTIME = Path(__file__).resolve().parent / "runtime"
sys.path.insert(0, str(RUNTIME))

from elmpay_runtime.common import ValidationError, read_json  # noqa: E402
from elmpay_runtime.egress_policy import render_egress_controls  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render fail-closed B89 egress controls")
    parser.add_argument("--workload-policy", type=Path, required=True)
    parser.add_argument("--egress-policy", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        workload_policy = read_json(arguments.workload_policy)
        egress_policy = read_json(arguments.egress_policy)
        if not isinstance(workload_policy, dict) or not isinstance(egress_policy, dict):
            raise ValidationError("B89 policies must be JSON objects")
        rendered = render_egress_controls(workload_policy, egress_policy)
        print(json.dumps(rendered, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, TypeError, ValueError, ValidationError) as exception:
        print(json.dumps({"allowed": False, "reasons": [str(exception)]}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
