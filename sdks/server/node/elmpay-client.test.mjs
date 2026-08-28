import assert from 'node:assert/strict'; import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { ElmpayClient, verifyWebhook } from './elmpay-client.mjs';

test('retries bounded idempotent create', async () => {
  let calls = 0; const requests = []; const headers = new Map([['x-request-id', 'r1']]);
  const projectId = '10000000-0000-4000-8000-000000000002';
  const client = new ElmpayClient({ baseUrl: 'https://api.example/', bearerToken: 'x', projectId, maximumAttempts: 3,
    transport: async (url, options) => { requests.push([url, options]); return { status: ++calls < 3 ? 503 : 200, headers, text: async () => '{}' }; } });
  assert.equal((await client.createCheckoutSession({ businessOrderNo: 'order-1', amount: 100, currency: 'USD', returnRouteId: 'complete' }, 'idempotency-key-0001')).statusCode, 200); assert.equal(calls, 3);
  const paths = requests.map(([url]) => url.pathname);
  assert.deepEqual(paths, Array(3).fill('/v1/checkout-sessions'));
  assert.equal(requests[0][1].headers['x-project-id'], projectId);
  assert.deepEqual(JSON.parse(requests[0][1].body), { business_order_no: 'order-1', amount: 100, currency: 'USD', return_route_id: 'complete' });
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
