# RR-02 control-gap remediation

The former exception described missing Java build, SAST/DAST and supply-chain scanning. These controls now execute on standard public-repository GitHub hosted runners. The existing required static-analysis stage includes CodeQL and real sandbox DAST; an independent bootstrap workflow supplies execution evidence before the expired governance exception can be retired.

The original due date **2026-10-17 was not extended**. The complete original record is retained under `remediated_risks[].original_record` in `governance/threat-model.json`, and in Git history. All other active risks, including RR-05's independent-review debt, retain their original owners, controls and deadlines. The original threat, CI, signing and terminal release evaluators are unchanged.

## Executed evidence

- Verified source: `e5bf5975c5ae3c004854720a4f942d1ede749d80`.
- [Full push native security run 40159159386](https://github.com/zpcaiai/elmpay/actions/runs/40159159386), attempt 1; job `121066860893`, runner `1000116005`, conclusion `success`.
- Java, JavaScript and Python CodeQL: 120 + 103 + 50 declared rules, `security-extended`, zero findings. Default queries remain enabled; no exclusions, suppressions or diff-informed filtering were used for this acceptance.
- Fresh Java execution: 459 tests across all 21 governed modules, 119 JUnit reports, zero failures/errors/skips. Includes actual Node-generated credentials verified by Java over HTTP and rejection of relative/unapproved executable paths.
- All 97 Node ingress, admin, checkout and free-demo tests passed.
- Built Java/Node sandbox DAST: 11 probes passed, with `real_payments=false`.
- Aggregate dependency scan: 64 dependencies, zero reported vulnerabilities; CycloneDX SBOM: 82 components.
- Downloaded artifact SHA-256: `303e9c0babb9f7ae4a2ff70975d78e4fdce1042272112fd7c31014eec2824dec`.
- Local receipt verification PID `40888`, exit `0`; raw-output SHA-256 `fe3bf73450fb2a7371306728728a784e7d81b2adb9bf9076d966a91e9150517d`. This verifies the downloaded provider evidence and retains its actual source/run binding.

## Substantive changes

Admin authorization uses the verified operator's tenant independently of query shape. Approval lookups use that tenant and reject records outside it. Query mismatches, stale step-up and insufficient privilege remain denied without protected side effects. Pre-fix regression demonstrated a returned foreign-tenant record could otherwise be disclosed by this boundary.

Generated signing test scripts are private from creation. The release injection test now targets the release-gate job explicitly and retains its original failure assertion. Billing intervals use a finite enum and invalid-input errors no longer echo caller material. Demo credentials use a random per-start salt and PBKDF2-HMAC-SHA256 at 600,000 iterations; Java uses constant-time verifier comparison and rejects malformed or weaker formats. Production continues to reject static API credentials. [OWASP's PBKDF2 parameters](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2) informed the KDF configuration.

## Limits and remaining gates

This retires the missing-controls exception; it does not certify B05/B116, production payments or provider integration. Original full CI must validate this ledger/document change before normal merge. Independent batch review and signed production release evidence remain required by their original gates. No review approval, release opt-in or certification has been fabricated.

Render remains a Free single instance and real payments remain disabled. This source change does not create infrastructure, enable a PSP, change cloud expiry or deploy a production payment service.
