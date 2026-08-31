import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createEdgeTransport } from '../src/edge-transport.mjs';
import { TEST_CERTIFICATE, TEST_PRIVATE_KEY } from './tls-fixture.mjs';

function credential(directory, name, value) {
  const path = `${directory}/${name}`;
  writeFileSync(path, value, { mode: 0o400 }); chmodSync(path, 0o400);
  return path;
}

test('production edge transport requires pinned same-origin TLS 1.3 read-only credentials',
  async t => {
    const directory = mkdtempSync(join(tmpdir(), 'elmpay-edge-transport-'));
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    const configuration = {
      apiBaseUrl: 'https://edge-gateway.elmpay.svc.cluster.local:8443/',
      certificateFile: credential(directory, 'client.crt', TEST_CERTIFICATE),
      privateKeyFile: credential(directory, 'client.key', TEST_PRIVATE_KEY),
      trustBundleFile: credential(directory, 'ca.crt', TEST_CERTIFICATE),
      serverName: 'edge-gateway.elmpay.svc.cluster.local',
    };
    const transport = createEdgeTransport(configuration);
    await assert.rejects(() => transport(new URL('https://attacker.example/'), {
      method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(50),
    }), /pinned origin/);
    assert.throws(() => createEdgeTransport({ ...configuration, serverName: 'attacker.example' }),
      /server name/);
  });

test('writable credential mounts fail closed before any connection attempt', t => {
  const directory = mkdtempSync(join(tmpdir(), 'elmpay-edge-transport-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const certificateFile = credential(directory, 'client.crt', TEST_CERTIFICATE);
  chmodSync(certificateFile, 0o600);
  assert.throws(() => createEdgeTransport({
    apiBaseUrl: 'https://edge.example:8443/', certificateFile,
    privateKeyFile: credential(directory, 'client.key', TEST_PRIVATE_KEY),
    trustBundleFile: credential(directory, 'ca.crt', TEST_CERTIFICATE), serverName: 'edge.example',
  }), /read-only/);
});
