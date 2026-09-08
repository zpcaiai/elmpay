"""B03 — the governance budget counts work, not waiting (ADR-0015).

The budget used to be wall-clock, which made a verdict a property of whatever
else the machine happened to be doing. Measured on the delivery machine:
``repo-hygiene`` spent 5.9 CPU-seconds inside 23.3 wall-seconds — 25% CPU, the
rest waiting on file reads — against a 30-second wall budget. It aborted twice,
both times minutes after a heavy Gradle build.

These tests pin the four properties that make the new budget worth having, and
the one property the old one had that must not be lost.
"""
from __future__ import annotations

import time
import unittest

from tools.paygov.errors import BudgetExceeded
from tools.paygov.repo import WALL_CEILING_MULTIPLIER, Budget


def _burn(budget: Budget, iterations: int = 20_000_000) -> None:
    """Spend real CPU, checking as a validator would."""
    value = 0
    for _ in range(iterations):
        value += 1
        budget.check("burning cpu")


class GovernanceBudget(unittest.TestCase):
    def test_an_exhausted_budget_still_fails_closed(self) -> None:
        """The shortest proof in the programme: --budget-seconds 0 must never pass.

        Every batch's evidence carries a command that relies on this exact
        behaviour to show the gate exits 3 rather than 0 when it cannot finish.
        """
        budget = Budget(seconds=0).start()
        with self.assertRaises(BudgetExceeded):
            budget.check("anything at all")

    def test_waiting_does_not_consume_the_budget(self) -> None:
        """The defect this ADR fixes: a slow disk is not an expensive validator."""
        budget = Budget(seconds=0.2).start()
        time.sleep(0.6)
        budget.check("after a long read")  # must not raise
        self.assertLess(budget.cpu_elapsed(), 0.2)
        self.assertGreater(budget.elapsed(), 0.5)

    def test_real_work_still_consumes_the_budget(self) -> None:
        """A validator that genuinely runs away must still be stopped."""
        budget = Budget(seconds=0.05).start()
        with self.assertRaises(BudgetExceeded):
            _burn(budget)
        self.assertGreaterEqual(budget.cpu_elapsed(), 0.05)

    def test_a_stalled_validator_is_still_caught(self) -> None:
        """CPU time alone would let a wedged mount hang the gate forever."""
        budget = Budget(seconds=10, wall_ceiling=0.3).start()
        time.sleep(0.5)
        with self.assertRaises(BudgetExceeded) as caught:
            budget.check("a mount that stopped answering")
        self.assertIn("wall-clock ceiling", str(caught.exception))
        self.assertIn("stuck, not working", str(caught.exception))

    def test_the_default_ceiling_is_far_above_any_honest_run(self) -> None:
        """Set the ceiling close to the budget and it becomes the old bug again."""
        self.assertEqual(Budget(seconds=30).ceiling(), 30 * WALL_CEILING_MULTIPLIER)
        self.assertGreaterEqual(WALL_CEILING_MULTIPLIER, 5)

    def test_an_unstarted_budget_never_raises(self) -> None:
        """Validators are sometimes constructed without start(); that is not a failure."""
        Budget(seconds=0).check("never started")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
