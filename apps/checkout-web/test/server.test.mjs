import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { createHandler, handler } from '../src/server.mjs';

function responseCapture() {
  return {
    status: 0, headers: {}, body: '',
    writeHead(status, headers = {}) { this.status = status; this.headers = headers; return this; },
    end(value = '') { this.body += value; },
    on() {}, once() {}, emit() {},
  };
}

test('rejects traversal and applies fail-closed CSP to missing assets', () => {
  const response = responseCapture();
  handler({ url: '/..%2fsecret' }, response);
  assert.equal(response.status, 400);
  assert.match(response.headers['content-security-policy'], /default-src 'none'/);
  assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
});

test('browser route forwards only the signed checkout credential to the agreed API path', async () => {
  const session = '00000000-0000-4000-8000-000000000000'; const token = `${'M'.repeat(48)}.${'A'.repeat(43)}`;
  const calls = [];
  const proxy = createHandler({ apiBaseUrl: 'https://api.example/internal/', transport: async (url, options) => {
    calls.push([url, options]); return new Response('{"status":"OPEN"}', { status: 200,
      headers: { 'content-type': 'application/json', 'x-request-id': 'upstream-request' } });
  } });
  const request = Readable.from([]); request.url = `/api/checkout/sessions/${session}`; request.method = 'GET';
  request.headers = { authorization: `CheckoutSession ${token}`,
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.5' };
  const response = responseCapture(); await proxy(request, response);
  assert.equal(response.status, 200);
  assert.equal(calls[0][0].pathname, `/api/checkout/sessions/${session}`);
  assert.equal(calls[0][0].search, '');
  assert.equal(calls[0][1].headers.authorization, `CheckoutSession ${token}`);
  assert.equal(calls[0][1].headers['accept-language'], 'zh-CN,zh;q=0.9,en;q=0.5');
  assert.equal('referer' in calls[0][1].headers, false);
  assert.equal(calls[0][1].headers.authorization.toLowerCase().includes('bearer'), false);
});

test('invalid locale metadata is replaced instead of being forwarded upstream', async () => {
  const session = '00000000-0000-4000-8000-000000000000';
  const token = `${'M'.repeat(48)}.${'A'.repeat(43)}`; const calls = [];
  const proxy = createHandler({ apiBaseUrl: 'https://api.example/', transport: async (url, options) => {
    calls.push([url, options]); return new Response('{"status":"OPEN"}', { status: 200,
      headers: { 'content-type': 'application/json' } });
  } });
  const request = Readable.from([]); request.url = `/api/checkout/sessions/${session}`;
  request.method = 'GET'; request.headers = { authorization: `CheckoutSession ${token}`,
    'accept-language': 'en\r\nx-injected: yes' };
  await proxy(request, responseCapture());
  assert.equal(calls[0][1].headers['accept-language'], 'en');
});

test('browser route rejects missing signed checkout credential without contacting upstream', async () => {
  const session = '00000000-0000-4000-8000-000000000000'; let called = false;
  const proxy = createHandler({ apiBaseUrl: 'https://api.example/', transport: async () => { called = true; } });
  const request = Readable.from([]); request.url = `/api/checkout/sessions/${session}`; request.method = 'GET'; request.headers = {};
  const response = responseCapture(); await proxy(request, response);
  assert.equal(response.status, 401); assert.equal(called, false);
});
