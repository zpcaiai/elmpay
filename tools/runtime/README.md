# Runtime policy tools

`control.py` is a dependency-free Python 3 command suite. All gate commands emit
one canonical JSON object and use exit code `0` only for an allowed result; a
policy failure or malformed/missing input exits `2`.

Examples:

```sh
python3 tools/runtime/control.py validate
python3 tools/runtime/control.py render-kubernetes --images /secure/release-images.json
python3 tools/runtime/control.py shadow-diff --baseline baseline.json --candidate shadow.json
python3 tools/runtime/control.py canary --baseline baseline-metrics.json --candidate candidate-metrics.json
python3 tools/runtime/control.py capacity-gate --samples capacity-samples.json
python3 tools/runtime/control.py release-gate --manifest release.json --trust /secure/release-trust.json
python3 tools/runtime/control.py go-no-go --manifest release.json --trust /secure/release-trust.json --shadow-baseline baseline.json --shadow-candidate shadow.json --canary-baseline baseline-metrics.json --canary-candidate candidate-metrics.json --capacity-samples capacity.json --operations operations.json
```

Release trust files name environment variables containing at least 32-character
HMAC verification secrets. Secrets are never stored in this repository. Human
approvals and external evidence are signed over the exact commit, artifact, and
image binding. This provides deterministic tamper detection; it does not turn a
local run into PCI, legal, UAT, penetration-test, or DR certification.
