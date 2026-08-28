PY ?= python3

.PHONY: help verify skills-verify governance test governance-test product-test web-test server-sdk-test gradle-test mobile-sdk-test quality-metrics-test test-matrix test-matrix-local status ready crosscheck ai-status clean-pyc

help:
	@echo "make skills-verify - verify the vendored skill package and installed mirrors"
	@echo "make governance  - run all repository governance validators (fail closed)"
	@echo "make test        - run governance and every local product/SDK test surface"
	@echo "make product-test - run testing/ and the provider contract matrix"
	@echo "make mobile-sdk-test - run fail-closed iOS and Flutter contract suites"
	@echo "make quality-metrics-test - enforce real Coverage.py, JaCoCo and PIT thresholds"
	@echo "make test-matrix - run the 128-batch SOTA matrix (external cases stay BLOCKED)"
	@echo "make test-matrix-local - run only executable local/CI matrix suites"
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

governance-test:
	$(PY) -m unittest discover -s tools/tests -t . -v

product-test:
	$(PY) -m unittest discover -s testing -p 'test_*.py' -v
	$(PY) scripts/provider-contract-matrix.py

web-test:
	node --test apps/checkout-web/test/*.test.mjs
	node --test apps/admin-web/test/*.test.mjs

server-sdk-test:
	$(PY) scripts/sdk-contract-smoke.py

gradle-test:
	./gradlew --no-daemon test

mobile-sdk-test:
	$(PY) scripts/platform_sdk_test.py ios --out build/mobile-sdk/ios.json --log build/mobile-sdk/ios.log
	$(PY) scripts/platform_sdk_test.py flutter --out build/mobile-sdk/flutter.json --log build/mobile-sdk/flutter.log

quality-metrics-test:
	$(PY) tools/quality_gate.py coverage-mutation

test: governance-test product-test web-test server-sdk-test gradle-test mobile-sdk-test quality-metrics-test

test-matrix:
	$(PY) scripts/run-test-matrix.py --allow-blocked --json-out build/test-matrix/report.json --junit-out build/test-matrix/junit.xml

test-matrix-local:
	$(PY) scripts/run-test-matrix.py --execution local --json-out build/test-matrix/local-report.json --junit-out build/test-matrix/local-junit.xml

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
