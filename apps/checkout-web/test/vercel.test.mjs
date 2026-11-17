import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { TEST_CERTIFICATE, TEST_PRIVATE_KEY } from './tls-fixture.mjs';

async function loadHandler(environment) {
  const previous = { ...process.env };
  try {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('ELMPAY_')) delete process.env[key];
    }
    Object.assign(process.env, environment);
    return (await import(`../api/index.mjs?case=${crypto.randomUUID()}`)).default;
  } finally {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('ELMPAY_')) delete process.env[key];
    }
    for (const [key, value] of Object.entries(previous)) {
      if (key.startsWith('ELMPAY_')) process.env[key] = value;
    }
  }
}

test('Vercel refuses unconfigured production, sandbox flags and direct assets over real HTTP', async () => {
  let handler = await loadHandler({});
  const server = createServer((request, response) => handler(request, response));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const environment of [{}, {
      ELMPAY_CHECKOUT_WEB_MODE: 'local', ELMPAY_ENABLE_LOCAL_SANDBOX: 'true',
    }, { ELMPAY_API_BASE_URL: 'https://edge.example/' }]) {
      handler = await loadHandler(environment);
    for (const path of ['/', '/health/ready', '/checkout.mjs', '/security/script-policy',
      '/api/checkout/sessions/00000000-0000-4000-8000-000000000000/confirm']) {
      const response = await fetch(`${origin}${path}`, {
        method: path.endsWith('/confirm') ? 'POST' : 'GET',
      });
      assert.equal(response.status, 503, path);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.match(response.headers.get('content-security-policy'), /default-src 'none'/);
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
      const body = await response.json();
      assert.equal(body.status, 'NOT_READY');
      assert.equal(body.certification, 'NOT_CERTIFIED');
      assert.equal(body.code, 'production_configuration_unavailable');
      assert.doesNotMatch(JSON.stringify(body), /BEGIN|PRIVATE KEY|127\.0\.0\.1|ENOENT/);
    }
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('valid read-only production mounts preserve checkout CSP and authorization', async t => {
  const directory = mkdtempSync(join(tmpdir(), 'elmpay-vercel-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  function mount(name, contents) {
    const path = join(directory, name);
    writeFileSync(path, contents, { mode: 0o400 });
    chmodSync(path, 0o400);
    return path;
  }
  const handler = await loadHandler({
    ELMPAY_CHECKOUT_WEB_MODE: 'production',
    ELMPAY_API_BASE_URL: 'https://edge.example/',
    ELMPAY_EDGE_TLS_SERVER_NAME: 'edge.example',
    ELMPAY_EDGE_CLIENT_CERTIFICATE_FILE: mount('client.crt', TEST_CERTIFICATE),
    ELMPAY_EDGE_CLIENT_PRIVATE_KEY_FILE: mount('client.key', TEST_PRIVATE_KEY),
    ELMPAY_EDGE_TRUST_BUNDLE_FILE: mount('ca.crt', TEST_CERTIFICATE),
    ELMPAY_PROVIDER_FRAME_TICKET_KEY_FILE: mount('frame-key', Buffer.alloc(32, 42).toString('base64url')),
  });
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const page = await fetch(origin);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-security-policy'), /script-src 'nonce-/);
    assert.doesNotMatch(await page.text(), /__CSP_NONCE__|__SRI_/);
    const unauthorized = await fetch(`${origin}/api/checkout/sessions/00000000-0000-4000-8000-000000000000`);
    assert.equal(unauthorized.status, 401);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('Vercel routes assets through the production gate and bundles runtime assets', () => {
  const config = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url)));
  assert.deepEqual(config.routes, [{ src: '/(.*)', dest: '/api/index.mjs' }]);
  assert.equal(config.functions['api/index.mjs'].includeFiles, '{public,security}/**');
});
