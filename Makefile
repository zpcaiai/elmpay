PY ?= python3

.PHONY: help verify governance test evidence status ready clean-pyc

help:
	@echo "make governance  - run all repository governance validators (fail closed)"
	@echo "make test        - run the governance test suite"
	@echo "make verify      - governance + test"
	@echo "make status      - batch orchestrator status"
	@echo "make ready       - batches ready to implement"

governance:
	$(PY) -m tools.paygov.cli verify-all --repo .

test:
	$(PY) -m unittest discover -s tools/tests -t . -v

verify: governance test

status:
	$(PY) .payment-platform/skill-package/scripts/orchestrate.py status --repo .

ready:
	$(PY) .payment-platform/skill-package/scripts/orchestrate.py ready --repo .

clean-pyc:
	find tools -name '__pycache__' -type d -prune -exec rm -rf {} +
