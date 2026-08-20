PY ?= python3

.PHONY: help verify skills-verify governance test status ready crosscheck ai-status clean-pyc

help:
	@echo "make skills-verify - verify the vendored skill package and installed mirrors"
	@echo "make governance  - run all repository governance validators (fail closed)"
	@echo "make test        - run the governance test suite"
	@echo "make verify      - skill package + governance + test"
	@echo "make status      - authoritative local batch status"
	@echo "make ready       - batches ready to implement"
	@echo "make crosscheck  - compare local and vendored orchestrators"
	@echo "make ai-status   - inspect the resumable .ai evidence workflow"

skills-verify:
	$(PY) .payment-platform/skill-package/scripts/verify_package.py
	diff -qr .payment-platform/skill-package/skills .agents/skills
	diff -qr .payment-platform/skill-package/skills .claude/skills

governance:
	$(PY) -m tools.paygov.cli verify-all --repo .

test:
	$(PY) -m unittest discover -s tools/tests -t . -v

verify: skills-verify governance test

status:
	$(PY) scripts/batch.py status

ready:
	$(PY) scripts/batch.py ready

crosscheck:
	$(PY) scripts/batch.py crosscheck

ai-status:
	$(PY) .ai/rebaseline.py status

clean-pyc:
	find tools -name '__pycache__' -type d -prune -exec rm -rf {} +
