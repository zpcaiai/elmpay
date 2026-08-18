"""paygov — zero-dependency repository governance toolchain for the elmpay payment platform.

Only the Python 3.10+ standard library may be imported from this package. The
toolchain has to run in offline build agents and in the batch-evidence sandbox
where no package index is reachable, so third-party dependencies are forbidden
and enforced by ``tools/tests/test_b00_repo_hygiene.py``.
"""

__version__ = "1.0.0"
