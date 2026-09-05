import { chmodSync, copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const directory = mkdtempSync(join(tmpdir(), "elmpay-admin-policy-"));

function controlledCopy(sourceUrl, name) {
  const path = join(directory, name);
  copyFileSync(fileURLToPath(sourceUrl), path);
  chmodSync(path, 0o400);
  return path;
}

export const policyPaths = Object.freeze({
  authorizationPath: controlledCopy(
    new URL("../../../governance/authorization.json", import.meta.url),
    "authorization.json",
  ),
  actionPolicyPath: controlledCopy(
    new URL("../security/action-policy.json", import.meta.url),
    "action-policy.json",
  ),
});

export function removePolicyFixture() {
  rmSync(directory, { force: true, recursive: true });
}
