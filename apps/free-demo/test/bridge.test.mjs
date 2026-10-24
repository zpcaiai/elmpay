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
    assert.match(calls[0].headers.traceparent ?? '', /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
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
    assert.equal((await fetch(`${origin}//attacker.example/api/checkout/sessions/${session}`)).status, 400);
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

test('provider-observed decline and unknown remain visible across authoritative rereads', async () => {
  for (const [providerCode, expected] of [['local_declined', 'FAILED'], ['local_unknown', 'PENDING']]) {
    const upstream = await listen((request, response) => {
      request.resume();
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({
        checkoutSessionId: session, status: 'OPEN', messages: { 'status.current': 'Ready' },
        methods: [{ id: 'card', eligible: true, reason: '' }],
        nextAction: request.method === 'POST' ? { provider_code: providerCode } : {},
      }));
    });
    const config = demoConfiguration({ ...enabled, ELMPAY_DEMO_GATEWAY_PORT: String(upstream.address().port) });
    const server = await listen(createDemoBridge(config));
    const path = `http://127.0.0.1:${server.address().port}/api/checkout/sessions/${session}`;
    const headers = { authorization: `CheckoutSession ${token}`, origin: enabled.ELMPAY_DEMO_PUBLIC_ORIGIN,
      'content-type': 'application/json', 'idempotency-key': 'demo-outcome-contract-0001' };
    try {
      assert.equal((await (await fetch(path, { headers })).json()).status, 'OPEN');
      // Deliberately request success: only the observed upstream result may decide the projection.
      const result = await (await fetch(`${path}/confirm`, { method: 'POST', headers,
        body: JSON.stringify({ method: 'card', payment_method_reference: `psp://elmpay-demo/${session}`,
          provider_parameters: { simulation: 'succeeded' } }) })).json();
      assert.equal(result.status, expected);
      assert.equal(result.gateway_status, 'OPEN');
      assert.ok(result.methods.every(method => method.eligible === false));
      const reread = await (await fetch(path, { headers })).json();
      assert.equal(reread.status, expected);
      assert.equal(reread.demo_provider_result, providerCode);
      assert.ok(reread.methods.every(method => method.eligible === false));
      assert.notEqual(reread.messages['status.current'], 'Ready');
      assert.equal((await fetch(path)).status, 401);
    } finally { await close(server); await close(upstream); }
  }
});

test('additional native sandbox scenarios pass only validated synthetic commands upstream', async () => {
  const calls = [];
  const upstream = await listen(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    calls.push({ url: request.url, body: JSON.parse(Buffer.concat(chunks).toString()) });
    const create = request.url === '/v1/checkout-sessions';
    response.writeHead(create ? 201 : 200, { 'content-type': 'application/json' }).end(JSON.stringify(
      create ? { checkout_session_id: session,
        checkout_url: `https://elmpay.vercel.app/checkout#session=${session}&token=${token}` }
        : { checkoutSessionId: session, status: 'PENDING', nextAction: {} }));
  });
  const config = demoConfiguration({ ...enabled, ELMPAY_DEMO_GATEWAY_PORT: String(upstream.address().port) });
  const server = await listen(createDemoBridge(config));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const scenario of ['authorized', 'requires_action']) {
      const headers = { origin: enabled.ELMPAY_DEMO_PUBLIC_ORIGIN, 'content-type': 'application/json',
        'idempotency-key': `demo-extra-${scenario}-0001`, authorization: `CheckoutSession ${token}` };
      const created = await fetch(`${origin}/demo/orders`, { method: 'POST', headers,
        body: JSON.stringify({ scenario }) });
      assert.equal(created.status, 201);
      const result = await fetch(`${origin}/api/checkout/sessions/${session}/confirm`, {
        method: 'POST', headers, body: JSON.stringify({ method: 'card',
          payment_method_reference: `psp://elmpay-demo/${session}`, provider_parameters: { simulation: scenario } }),
      });
      assert.equal(result.status, 200);
      assert.equal((await result.json()).status, 'PENDING');
      assert.equal(calls.at(-1).body.provider_parameters.simulation, scenario);
    }
    const count = calls.length;
    assert.equal((await fetch(`${origin}/demo/orders`, { method: 'POST',
      headers: { origin: enabled.ELMPAY_DEMO_PUBLIC_ORIGIN, 'content-type': 'application/json',
        'idempotency-key': 'demo-live-unsupported-0001' }, body: '{"scenario":"live"}' })).status, 400);
    assert.equal(calls.length, count);
  } finally { await close(server); await close(upstream); }
});

test('WeChat-shaped demo uses a native CNY method and binds replay keys to its profile', async () => {
  const calls = [];
  const upstream = await listen(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    calls.push({ url: request.url, body: JSON.parse(Buffer.concat(chunks).toString()) });
    const create = request.url === '/v1/checkout-sessions';
    response.writeHead(create ? 201 : 200, { 'content-type': 'application/json' }).end(JSON.stringify(
      create ? { checkout_session_id: session,
        checkout_url: `https://elmpay.vercel.app/checkout#session=${session}&token=${token}` }
        : { checkoutSessionId: session, status: 'PENDING', nextAction: {} }));
  });
  const config = demoConfiguration({ ...enabled, ELMPAY_DEMO_GATEWAY_PORT: String(upstream.address().port) });
  const server = await listen(createDemoBridge(config));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const headers = { origin: enabled.ELMPAY_DEMO_PUBLIC_ORIGIN, 'content-type': 'application/json',
    'idempotency-key': 'demo-wechat-profile-0001', authorization: `CheckoutSession ${token}` };
  try {
    assert.deepEqual(config.childEnvironment.ELMPAY_CHECKOUT_ALLOWED_METHODS.split(',').sort(), ['card', 'wechat_native']);
    const body = { scenario: 'unknown', payment_method: 'wechat_native' };
    const created = await fetch(`${origin}/demo/orders`, { method: 'POST', headers, body: JSON.stringify(body) });
    assert.equal(created.status, 201);
    const value = await created.json();
    assert.equal(value.payment_method, 'wechat_native');
    assert.equal(value.currency, 'CNY');
    assert.equal(value.amount, 1000);
    assert.equal(value.simulation_engine, 'local-sandbox');
    assert.equal(value.real_payments, false);
    assert.equal(calls.at(-1).body.payment_method, 'wechat_native');
    assert.equal(calls.at(-1).body.currency, 'CNY');
    assert.equal(calls.at(-1).body.amount, 1000);
    assert.equal((await fetch(`${origin}/demo/orders`, { method: 'POST', headers,
      body: JSON.stringify(body) })).status, 201);
    const count = calls.length;
    assert.equal((await fetch(`${origin}/demo/orders`, { method: 'POST', headers,
      body: JSON.stringify({ ...body, payment_method: 'card' }) })).status, 409);
    for (const extra of [{ payment_method: 'wechat_jsapi' }, { payment_method: '__proto__' },
      { payment_method: null }, { amount: 1 }, { currency: 'USD' }]) {
      assert.equal((await fetch(`${origin}/demo/orders`, { method: 'POST', headers,
        body: JSON.stringify({ ...body, ...extra }) })).status, 400);
    }
    assert.equal(calls.length, count);
    const command = { method: 'wechat_native', payment_method_reference: `psp://elmpay-demo/${session}`,
      provider_parameters: { simulation: 'unknown' } };
    assert.equal((await fetch(`${origin}/api/checkout/sessions/${session}/confirm`, {
      method: 'POST', headers, body: JSON.stringify(command) })).status, 200);
    assert.deepEqual(calls.at(-1).body, command);
    const dispatched = calls.length;
    assert.equal((await fetch(`${origin}/api/checkout/sessions/${session}/confirm`, {
      method: 'POST', headers, body: JSON.stringify({ ...command,
        payment_method_reference: 'psp://wechat/real-provider-reference' }) })).status, 400);
    assert.equal(calls.length, dispatched);
  } finally { await close(server); await close(upstream); }
});
