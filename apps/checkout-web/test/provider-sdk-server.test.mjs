import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { ProviderSdkPolicy } from '../src/provider-sdk-policy.mjs';
import { configFromEnvironment, createHandler } from '../src/server.mjs';
import { TEST_CERTIFICATE, TEST_PRIVATE_KEY } from './tls-fixture.mjs';

const SESSION = '00000000-0000-4000-8000-000000000000';
const TOKEN = `${'M'.repeat(48)}.${'A'.repeat(43)}`;
const CHANNEL = 'channel_12345678901234567890';
const INTEGRITY = `sha384-${'A'.repeat(64)}`;
const NOW = Date.parse('2026-08-30T12:00:00Z');

function sdkPolicy() {
  return new ProviderSdkPolicy({
    ticketKey: Buffer.alloc(32, 9), now: () => new Date(NOW),
    manifest: {
      schemaVersion: 1, manifestVersion: 'provider-policy-v1',
      reviewExpiresAt: '2027-02-28T00:00:00Z', externalAssessmentStatus: 'BLOCKED',
      providers: [{
        id: 'provider-a', methods: ['card'], sdkVersion: 'sdk-v1',
        scriptUrl: 'https://sdk.provider.example/v1/isolated.js', integrity: INTEGRITY,
        adapterContract: 'elmpay-isolated-provider-v1', publicParameterKeys: ['publishableKey'],
        connectOrigins: ['https://api.provider.example'],
        frameOrigins: ['https://frames.provider.example'], owner: 'connectors',
        reviewExpiresAt: '2027-02-28T00:00:00Z', enabled: true,
      }],
    },
  });
}

function request(path, { method = 'GET', headers = {} } = {}) {
  const value = Readable.from([]); value.url = path; value.method = method; value.headers = headers;
  return value;
}

function responseCapture() {
  return {
    status: 0, headers: {}, body: Buffer.alloc(0),
    writeHead(status, headers = {}) { this.status = status; this.headers = headers; return this; },
    end(value = '') { this.body = Buffer.concat([this.body, Buffer.from(value)]); },
    on() {}, once() {}, emit() {},
  };
}

test('same-origin config proxy binds the channel and maps only reviewed metadata into a signed frame', async () => {
  const calls = [];
  const transport = async (url, options) => {
    calls.push([url, options]);
    return new Response(JSON.stringify({
      method: 'card', provider: 'provider-a', sdkVersion: 'sdk-v1',
      publicParameters: { publishableKey: 'pk_live_reviewed' },
    }), { status: 200, headers: { 'content-type': 'application/json', 'x-request-id': 'upstream-id' } });
  };
  const handler = createHandler({ apiBaseUrl: 'https://api.example/', transport,
    providerSdkPolicy: sdkPolicy() });
  const configResponse = responseCapture();
  await handler(request(`/api/checkout/sessions/${SESSION}/provider-sdk-config?method=card&channel=${CHANNEL}`,
    { headers: { authorization: `CheckoutSession ${TOKEN}` } }), configResponse);
  assert.equal(configResponse.status, 200);
  assert.equal(calls[0][0].origin, 'https://api.example');
  assert.equal(calls[0][0].search, `?method=card&channel=${CHANNEL}`);
  assert.equal(calls[0][1].redirect, 'manual');
  const configuration = JSON.parse(configResponse.body);
  assert.equal(configuration.scriptUrl, 'https://sdk.provider.example/v1/isolated.js');
  assert.equal(configuration.integrity, INTEGRITY);
  assert.match(configuration.framePath, /^\/security\/provider-sdk-frame\?ticket=/);

  const frameResponse = responseCapture();
  await handler(request(configuration.framePath), frameResponse);
  assert.equal(frameResponse.status, 200);
  assert.match(frameResponse.headers['content-security-policy'], /frame-ancestors 'self'/);
  assert.match(frameResponse.headers['content-security-policy'],
    /script-src 'nonce-[A-Za-z0-9_-]{24}' https:\/\/sdk\.provider\.example\/v1\/isolated\.js/);
  assert.match(frameResponse.headers['content-security-policy'], /connect-src https:\/\/api\.provider\.example/);
  assert.match(frameResponse.body.toString('utf8'), new RegExp(`integrity="${INTEGRITY}"`));
  assert.equal(frameResponse.headers['referrer-policy'], 'no-referrer');
  assert.equal(frameResponse.headers['cache-control'], 'no-store');
});

test('client URL injection and upstream script metadata are rejected without rendering a frame', async () => {
  let calls = 0;
  const handler = createHandler({ apiBaseUrl: 'https://api.example/', providerSdkPolicy: sdkPolicy(),
    transport: async () => {
      calls += 1;
      return new Response(JSON.stringify({
        method: 'card', provider: 'provider-a', sdkVersion: 'sdk-v1',
        publicParameters: { publishableKey: 'pk_live_reviewed' },
        scriptUrl: 'https://evil.example/collect.js',
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    } });
  const injected = responseCapture();
  await handler(request(`/api/checkout/sessions/${SESSION}/provider-sdk-config?method=card&channel=${CHANNEL}&scriptUrl=https://evil.example/x.js`,
    { headers: { authorization: `CheckoutSession ${TOKEN}` } }), injected);
  assert.equal(injected.status, 400); assert.equal(calls, 0);

  const poisoned = responseCapture();
  await handler(request(`/api/checkout/sessions/${SESSION}/provider-sdk-config?method=card&channel=${CHANNEL}`,
    { headers: { authorization: `CheckoutSession ${TOKEN}` } }), poisoned);
  assert.equal(poisoned.status, 503); assert.equal(calls, 1);
  assert.equal(poisoned.body.toString('utf8').includes('evil.example'), false);
});

test('production requires stable frame-ticket and mTLS edge credentials', t => {
  assert.throws(() => configFromEnvironment({
    ELMPAY_CHECKOUT_WEB_MODE: 'production', ELMPAY_API_BASE_URL: 'https://api.example/',
  }), /TICKET_KEY_FILE is required/);
  const directory = mkdtempSync(join(tmpdir(), 'elmpay-provider-sdk-config-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const mounted = (name, value) => {
    const path = join(directory, name); writeFileSync(path, value, { mode: 0o400 });
    chmodSync(path, 0o400); return path;
  };
  assert.throws(() => configFromEnvironment({
    ELMPAY_CHECKOUT_WEB_MODE: 'production',
    ELMPAY_API_BASE_URL: 'https://api.example/attacker-controlled-base',
    ELMPAY_PROVIDER_FRAME_TICKET_KEY_FILE: mounted('rejected-ticket-key',
      Buffer.alloc(32, 4).toString('base64url')),
  }), /one credential-free HTTPS origin/);
  const key = Buffer.alloc(32, 3).toString('base64url');
  const configuration = configFromEnvironment({
    ELMPAY_CHECKOUT_WEB_MODE: 'production', ELMPAY_API_BASE_URL: 'https://api.example/',
    ELMPAY_PROVIDER_FRAME_TICKET_KEY_FILE: mounted('provider-frame-ticket-key', `${key}\n`),
    ELMPAY_EDGE_CLIENT_CERTIFICATE_FILE: mounted('tls.crt', TEST_CERTIFICATE),
    ELMPAY_EDGE_CLIENT_PRIVATE_KEY_FILE: mounted('tls.key', TEST_PRIVATE_KEY),
    ELMPAY_EDGE_TRUST_BUNDLE_FILE: mounted('ca.crt', TEST_CERTIFICATE),
    ELMPAY_EDGE_TLS_SERVER_NAME: 'api.example',
  });
  assert.deepEqual(configuration.providerFrameTicketKey, Buffer.alloc(32, 3));
  assert.equal(typeof configuration.transport, 'function');
  assert.throws(() => configFromEnvironment({
    ELMPAY_CHECKOUT_WEB_MODE: 'production', ELMPAY_API_BASE_URL: 'https://api.example/',
    ELMPAY_PROVIDER_FRAME_TICKET_KEY: key,
  }), /TICKET_KEY is forbidden/);
});
