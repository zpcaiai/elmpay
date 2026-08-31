import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ProviderSdkPolicy } from '../src/provider-sdk-policy.mjs';

const NOW = Date.parse('2026-08-30T12:00:00Z');
const SESSION = '00000000-0000-4000-8000-000000000000';
const TICKET_KEY = Buffer.alloc(32, 7);
const INTEGRITY = `sha384-${'A'.repeat(64)}`;

function manifest(overrides = {}) {
  return {
    schemaVersion: 1,
    manifestVersion: 'provider-policy-v1',
    reviewExpiresAt: '2027-02-28T00:00:00Z',
    providers: [{
      id: 'provider-a', methods: ['card'], sdkVersion: 'sdk-1.2.3',
      scriptUrl: 'https://sdk.provider.example/v1.2.3/isolated.js',
      integrity: INTEGRITY, adapterContract: 'elmpay-isolated-provider-v1',
      publicParameterKeys: ['publishableKey'],
      connectOrigins: ['https://api.provider.example'],
      frameOrigins: ['https://frames.provider.example'],
      owner: 'payment-platform-connectors', reviewExpiresAt: '2027-02-28T00:00:00Z',
      enabled: true,
      ...overrides,
    }],
    externalAssessmentStatus: 'BLOCKED',
  };
}

function policy(overrides = {}) {
  return new ProviderSdkPolicy({
    manifest: manifest(overrides), ticketKey: TICKET_KEY, now: () => new Date(NOW),
  });
}

function upstream(overrides = {}) {
  return {
    method: 'card', provider: 'provider-a', sdkVersion: 'sdk-1.2.3',
    publicParameters: { publishableKey: 'pk_live_reviewed_123' }, ...overrides,
  };
}

test('reviewed SDK metadata issues a short-lived signed frame with SRI and a CSP nonce', () => {
  const runtime = policy();
  const configuration = runtime.authorizeConfiguration({
    checkoutSessionId: SESSION, method: 'card', channel: 'channel_12345678901234567890',
    upstreamConfiguration: upstream(),
  });
  assert.equal(configuration.scriptUrl, 'https://sdk.provider.example/v1.2.3/isolated.js');
  assert.equal(configuration.integrity, INTEGRITY);
  assert.match(configuration.framePath, /^\/security\/provider-sdk-frame\?ticket=/);
  assert.equal(configuration.expiresAt, '2026-08-30T12:00:30.000Z');

  const ticket = new URL(configuration.framePath, 'https://checkout.example').searchParams.get('ticket');
  const frame = runtime.renderFrame(ticket);
  const html = frame.bytes.toString('utf8');
  assert.match(html, /src="https:\/\/sdk\.provider\.example\/v1\.2\.3\/isolated\.js"/);
  assert.match(html, new RegExp(`integrity="${INTEGRITY}"`));
  assert.match(html, /nonce="[A-Za-z0-9_-]{24}"/);
  assert.equal(html.includes('pk_live_reviewed_123'), false);
  assert.deepEqual(frame.connectOrigins, ['https://api.provider.example']);
  assert.deepEqual(frame.frameOrigins, ['https://frames.provider.example']);
});

test('upstream cannot supply or replace a script URL, integrity, method owner, or SDK version', () => {
  const runtime = policy(); const request = { checkoutSessionId: SESSION, method: 'card',
    channel: 'channel_12345678901234567890' };
  assert.throws(() => runtime.authorizeConfiguration({ ...request,
    upstreamConfiguration: { ...upstream(), scriptUrl: 'https://evil.example/steal.js' },
  }), /does not match/);
  assert.throws(() => runtime.authorizeConfiguration({ ...request,
    upstreamConfiguration: upstream({ sdkVersion: 'latest' }),
  }), /does not match/);
  assert.throws(() => runtime.authorizeConfiguration({ ...request,
    upstreamConfiguration: upstream({ provider: 'provider-b' }),
  }), /does not match/);
  assert.throws(() => runtime.authorizeConfiguration({ ...request, method: 'paypal',
    upstreamConfiguration: upstream({ method: 'paypal' }),
  }), /not allowlisted/);
});

test('unsafe URLs, secret-shaped public parameters and unreviewed entries fail closed', () => {
  assert.throws(() => policy({ scriptUrl: 'http://sdk.provider.example/sdk.js' }), /HTTPS/);
  assert.throws(() => policy({ scriptUrl: 'https://127.0.0.1/sdk.js' }), /public DNS/);
  assert.throws(() => policy({ scriptUrl: 'https://[::1]/sdk.js' }), /public DNS/);
  assert.throws(() => policy({ scriptUrl: 'https://sdk.provider.example/sdk.js;script-src *' }), /URL/);
  assert.throws(() => policy({ publicParameterKeys: ['clientSecret'] }), /allowlist entry/);
  const disabled = policy({ enabled: false });
  assert.throws(() => disabled.authorizeConfiguration({
    checkoutSessionId: SESSION, method: 'card', channel: 'channel_12345678901234567890',
    upstreamConfiguration: upstream(),
  }), /not allowlisted/);
});

test('frame tickets reject tampering and expiry instead of falling back to an SDK URL', () => {
  let current = NOW;
  const runtime = new ProviderSdkPolicy({ manifest: manifest(), ticketKey: TICKET_KEY,
    now: () => new Date(current) });
  const configuration = runtime.authorizeConfiguration({
    checkoutSessionId: SESSION, method: 'card', channel: 'channel_12345678901234567890',
    upstreamConfiguration: upstream(),
  });
  const ticket = new URL(configuration.framePath, 'https://checkout.example').searchParams.get('ticket');
  const replacement = ticket.at(-1) === 'A' ? 'B' : 'A';
  assert.throws(() => runtime.renderFrame(`${ticket.slice(0, -1)}${replacement}`), /signature|invalid/);
  current += 30_000;
  assert.throws(() => runtime.renderFrame(ticket), /expired/);
});
