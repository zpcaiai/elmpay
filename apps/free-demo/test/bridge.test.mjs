import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { test } from 'node:test';
import { demoConfiguration, createDemoBridge } from '../src/bridge.mjs';

const enabled = { ELMPAY_DEMO_ENABLED: 'true', ELMPAY_DEMO_REAL_PAYMENTS_DISABLED: 'true',
  ELMPAY_DEMO_PUBLIC_ORIGIN: 'https://elmpay.vercel.app' };
const session = '21000000-0000-4000-8000-000000000004';
const token = `${'A'.repeat(48)}.${'B'.repeat(43)}`;

async function listen(handler) {
  const server = createServer(handler); server.listen(0, '127.0.0.1');
  await once(server, 'listening'); return server;
}
async function close(server) { await new Promise(resolve => server.close(resolve)); }

test('demo configuration requires both explicit flags and refuses production material', () => {
  assert.throws(() => demoConfiguration({}), /demo/);
  assert.throws(() => demoConfiguration({ ...enabled, ELMPAY_RUNTIME_MODE: 'postgres' }), /production/);
  assert.throws(() => demoConfiguration({ ...enabled, ELMPAY_STRIPE_SECRET_KEY: 'not-a-real-key' }), /production/);
  assert.throws(() => demoConfiguration({ ...enabled, ELMPAY_DEMO_PUBLIC_ORIGIN: 'http://example.com' }), /origin/);
  const config = demoConfiguration(enabled);
  assert.equal(config.childEnvironment.ELMPAY_RUNTIME_MODE, 'local');
  assert.equal(config.childEnvironment.ELMPAY_ENABLE_LOCAL_SANDBOX, 'true');
  assert.equal(config.childEnvironment.ELMPAY_LOCAL_RISK_POLICY, 'approve-sandbox');
  assert.equal(config.childEnvironment.PORT, '8500');
  assert.ok(!config.childEnvironment.ELMPAY_API_PRINCIPALS.includes(config.apiToken));
});

test('real HTTP transport keeps credentials private, bounds demo creation and denies generic proxy routes', async () => {
  // Protocol fixture only: the real Java payment state machine is exercised by the final native E2E.
  const calls = [];
  const upstream = await listen(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    calls.push({ url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString() });
    response.writeHead(201, { 'content-type': 'application/json' }).end(JSON.stringify({
      checkout_session_id: session, payment_intent_id: session, status: 'OPEN',
      checkout_url: `https://elmpay.vercel.app/checkout#session=${session}&token=${token}`,
    }));
  });
  const config = demoConfiguration({ ...enabled, ELMPAY_DEMO_GATEWAY_PORT: String(upstream.address().port) });
  const server = await listen(createDemoBridge(config));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const headers = { origin: enabled.ELMPAY_DEMO_PUBLIC_ORIGIN, 'content-type': 'application/json',
    'idempotency-key': 'demo-create-contract-0001' };
  try {
    const result = await fetch(`${origin}/demo/orders`, { method: 'POST', headers,
      body: JSON.stringify({ scenario: 'succeeded' }) });
    assert.equal(result.status, 201);
    const body = await result.json();
    assert.equal(body.demo, true); assert.equal(body.real_payments, false);
    assert.equal(body.checkout_session_id, session);
    assert.ok(!JSON.stringify(body).includes(config.apiToken));
    assert.equal(calls[0].url, '/v1/checkout-sessions');
    assert.equal(calls[0].headers.authorization, `Bearer ${config.apiToken}`);
    assert.equal(JSON.parse(calls[0].body).amount, 1000);
    assert.equal(JSON.parse(calls[0].body).currency, 'USD');
    assert.equal((await fetch(`${origin}/v1/payment_intents`)).status, 404);
    assert.equal((await fetch(`${origin}/demo/orders`, { method: 'POST', headers: { ...headers,
      origin: 'https://evil.example' }, body: '{"scenario":"succeeded"}' })).status, 403);
    assert.equal((await fetch(`${origin}/demo/orders`, { method: 'POST', headers,
      body: '{"scenario":"succeeded","amount":1}' })).status, 400);
    assert.equal((await fetch(`${origin}/demo/orders`, { method: 'POST', headers,
      body: '{"scenario":"declined"}' })).status, 409);
    assert.equal((await fetch(`${origin}/demo/orders?token=unsafe`)).status, 400);
    assert.equal(calls.length, 1);
  } finally { await close(server); await close(upstream); }
});

test('browser confirmation refuses a real PSP reference before any upstream connection', async () => {
  const server = await listen(createDemoBridge(demoConfiguration(enabled)));
  try {
    const result = await fetch(`http://127.0.0.1:${server.address().port}/api/checkout/sessions/${session}/confirm`, {
      method: 'POST', headers: { origin: enabled.ELMPAY_DEMO_PUBLIC_ORIGIN,
        'content-type': 'application/json', authorization: `CheckoutSession ${token}`,
        'idempotency-key': 'demo-confirm-contract-0001' },
      body: JSON.stringify({ method: 'card', payment_method_reference: 'psp://stripe/real-reference',
        provider_parameters: { simulation: 'succeeded' } }),
    });
    assert.equal(result.status, 400);
    assert.equal(result.headers.get('x-elmpay-demo'), 'true');
    assert.match(result.headers.get('content-security-policy'), /default-src 'none'/);
  } finally { await close(server); }
});
