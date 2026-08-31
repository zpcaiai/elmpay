import assert from 'node:assert/strict'; import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { ApiError, ElmpayClient, InvalidResponseError, MAX_RESPONSE_BYTES,
  ResponseTooLargeError, verifyWebhook } from './elmpay-client.mjs';

const session = JSON.stringify({ checkout_session_id: 'cs_123', expires_at: '2026-08-30T12:00:00Z',
  checkout_url: 'https://checkout.example/cs_123' });
const problem = status => JSON.stringify({ type: 'https://docs.example/problems/unavailable', title: 'Unavailable',
  status, code: 'service_unavailable', trace_id: 'trace-1' });
const response = (body, status, contentType) => new Response(body, { status,
  headers: { 'content-type': contentType, 'x-request-id': 'request-1' } });

test('constructor rejects an unbounded timeout', () => {
  const options = { baseUrl: 'https://api.example/', bearerToken: 'x',
    projectId: '10000000-0000-4000-8000-000000000002' };
  for (const timeoutMs of [0, -1, Infinity, 300_001])
    assert.throws(() => new ElmpayClient({ ...options, timeoutMs }), RangeError);
  for (const baseUrl of ['https://user:pass@api.example/', 'https://api.example/?x=1', 'https://api.example/#fragment'])
    assert.throws(() => new ElmpayClient({ ...options, baseUrl }), TypeError);
});

test('retries bounded idempotent create and returns typed data', async () => {
  let calls = 0; const requests = [];
  const projectId = '10000000-0000-4000-8000-000000000002';
  const client = new ElmpayClient({ baseUrl: 'https://api.example/', bearerToken: 'x', projectId, maximumAttempts: 3,
    transport: async (url, options) => { requests.push([url, options]); calls++;
      return calls < 3 ? response(problem(503), 503, 'application/problem+json') : response(session, 201, 'application/json'); } });
  const created = await client.createCheckoutSession({ businessOrderNo: 'order-1', amount: 100, currency: 'USD', returnRouteId: 'complete' }, 'idempotency-key-0001');
  assert.equal(created.statusCode, 201); assert.equal(created.data.checkoutSessionId, 'cs_123'); assert.equal(calls, 3);
  const paths = requests.map(([url]) => url.pathname);
  assert.deepEqual(paths, Array(3).fill('/v1/checkout-sessions'));
  assert.equal(requests[0][1].headers['x-project-id'], projectId);
  assert.deepEqual(JSON.parse(requests[0][1].body), { business_order_no: 'order-1', amount: 100, currency: 'USD', return_route_id: 'complete' });
});
test('rejects chunked responses over the uniform limit', async () => {
  const client = new ElmpayClient({ baseUrl: 'https://api.example/', bearerToken: 'x',
    projectId: '10000000-0000-4000-8000-000000000002', maximumAttempts: 1,
    transport: async () => response(Buffer.alloc(MAX_RESPONSE_BYTES + 1), 200, 'application/json') });
  await assert.rejects(client.getCheckoutSession('cs_123'), ResponseTooLargeError);
});
test('rejects content type, status, and typed-schema drift', async () => {
  const options = { baseUrl: 'https://api.example/', bearerToken: 'x',
    projectId: '10000000-0000-4000-8000-000000000002', maximumAttempts: 1 };
  await assert.rejects(new ElmpayClient({ ...options,
    transport: async () => response(session, 200, 'text/html') }).getCheckoutSession('cs_123'), InvalidResponseError);
  await assert.rejects(new ElmpayClient({ ...options,
    transport: async () => response('{"checkout_session_id":"cs_123"}', 200, 'application/json') }).getCheckoutSession('cs_123'), InvalidResponseError);
  await assert.rejects(new ElmpayClient({ ...options,
    transport: async () => response(session, 200, 'application/json') }).createCheckoutSession(
      { businessOrderNo: 'order-1', amount: 100, currency: 'USD' }, 'idem-1'), InvalidResponseError);
});
test('maps RFC 9457 problem details and binds HTTP status', async () => {
  const client = new ElmpayClient({ baseUrl: 'https://api.example/', bearerToken: 'x',
    projectId: '10000000-0000-4000-8000-000000000002', maximumAttempts: 1,
    transport: async () => response(problem(402).replace('service_unavailable', 'payment_declined'), 402, 'application/problem+json') });
  await assert.rejects(client.getCheckoutSession('cs_123'), error =>
    error instanceof ApiError && error.statusCode === 402 && error.problem.code === 'payment_declined' && error.requestId === 'request-1');
});
test('webhook verifies raw bytes and freshness', () => {
  const vector = JSON.parse(readFileSync(new URL('../../../contracts/webhooks/signing-v1.json', import.meta.url)));
  const secret = Buffer.from(vector.secret_base64url, 'base64url');
  const rawBody = Buffer.from(vector.raw_body_utf8);
  assert.equal(verifyWebhook({ secret, rawBody, signatureHeader: vector.signature_header,
    now: vector.timestamp * 1000 }), true);
  assert.equal(verifyWebhook({ secret, rawBody: Buffer.from('{"x":2}'),
    signatureHeader: vector.signature_header, now: vector.timestamp * 1000 }), false);
});

test('webhook rejects duplicate and malformed signature fields', () => {
  const vector = JSON.parse(readFileSync(new URL('../../../contracts/webhooks/signing-v1.json', import.meta.url)));
  const secret = Buffer.from(vector.secret_base64url, 'base64url');
  const rawBody = Buffer.from(vector.raw_body_utf8);
  const now = vector.timestamp * 1000;
  assert.equal(verifyWebhook({ secret, rawBody,
    signatureHeader: `${vector.signature_header},t=${vector.timestamp}`, now }), false);
  assert.equal(verifyWebhook({ secret, rawBody,
    signatureHeader: `${vector.signature_header},v1=bad`, now }), false);
  assert.equal(verifyWebhook({ secret, rawBody,
    signatureHeader: vector.signature_header.replace('t=', 't=+'), now }), false);
});
