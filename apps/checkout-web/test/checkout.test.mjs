import assert from 'node:assert/strict';
import { test } from 'node:test';

globalThis.__ELMPAY_TEST__ = true;
const { CheckoutController } = await import('../public/checkout.mjs');
const TOKEN = `${'M'.repeat(48)}.${'A'.repeat(43)}`;
const SESSION = '00000000-0000-4000-8000-000000000000';

const element = () => ({ textContent: '', hidden: true, disabled: false, attrs: {}, children: [],
  setAttribute(k, v) { this.attrs[k] = v; }, replaceChildren(...v) { this.children = v; }, append(...v) { this.children.push(...v); } });

function fakeDocument() {
  const nodes = new Map(['#checkout','#amount','#methods','#continue','#status','#error'].map(id => [id, element()]));
  return { documentElement: {}, querySelector: id => nodes.get(id), createElement: () => element(), createTextNode: value => value, nodes };
}

test('never maps an unknown client callback to success', async () => {
  const document = fakeDocument();
  const storage = new Map(); storage.getItem = storage.get.bind(storage); storage.setItem = storage.set.bind(storage); storage.removeItem = storage.delete.bind(storage);
  const controller = new CheckoutController({ document, storage, history: { replaceState() {} }, location: { href: `https://x/#session=${SESSION}&token=${TOKEN}` },
    api: async () => ({ ok: true, json: async () => ({ status: 'CLIENT_RETURNED', displayAmount: '$1.00', locale: 'en', direction: 'ltr', methods: [] }) }) });
  await controller.start();
  assert.match(document.nodes.get('#status').textContent, /unknown/);
  clearTimeout(controller.timer);
});

test('network failure is fail closed', async () => {
  const document = fakeDocument();
  const storage = new Map(); storage.getItem = storage.get.bind(storage); storage.setItem = storage.set.bind(storage); storage.removeItem = storage.delete.bind(storage);
  const controller = new CheckoutController({ document, storage, history: { replaceState() {} }, location: { href: `https://x/#session=${SESSION}&token=${TOKEN}` }, api: async () => { throw new Error('offline'); } });
  await controller.start();
  assert.match(document.nodes.get('#error').textContent, /No payment result has been assumed/);
});

test('confirmation reuses a stable idempotency key and remains server-authoritative', async () => {
  const document = fakeDocument(); const storage = new Map(); storage.getItem = storage.get.bind(storage); storage.setItem = storage.set.bind(storage); storage.removeItem = storage.delete.bind(storage);
  const calls = []; const controller = new CheckoutController({ document, storage, location: { href: 'https://x/' }, history: { replaceState() {} }, api: async (url, options) => {
    calls.push([url, options]);
    if (options.method === 'POST') return { ok: true };
    return { ok: true, json: async () => ({ status: 'SUCCEEDED', displayAmount: '$1.00', locale: 'en', direction: 'ltr', methods: [] }) };
  } }); controller.sessionId = SESSION; controller.accessToken = TOKEN;
  await controller.confirm('card'); const first = calls[0][1].headers['idempotency-key']; calls.length = 0;
  await controller.confirm('card'); assert.equal(calls[0][1].headers['idempotency-key'], first);
  assert.equal(document.nodes.get('#status').textContent, 'Payment verified by the server.');
  assert.equal(calls[0]?.[1]?.headers?.authorization, `CheckoutSession ${TOKEN}`);
});

test('reads the bearer from the URL fragment and clears browser history before API use', async () => {
  const document = fakeDocument();
  const storage = new Map(); storage.getItem = storage.get.bind(storage); storage.setItem = storage.set.bind(storage); storage.removeItem = storage.delete.bind(storage);
  const historyCalls = []; const apiCalls = [];
  const controller = new CheckoutController({ document, storage,
    location: { href: `https://checkout.example/pay?brand=x#session=${SESSION}&token=${TOKEN}` },
    history: { replaceState(...args) { historyCalls.push(args); } },
    api: async (url, options) => { apiCalls.push([url, options]); return { ok: true, json: async () => ({ status: 'OPEN', displayAmount: '$1.00', locale: 'en', direction: 'ltr', methods: [] }) }; } });
  await controller.start(); clearTimeout(controller.timer);
  assert.equal(historyCalls[0][2], '/pay?brand=x');
  assert.equal(apiCalls[0][0], `/api/checkout/sessions/${SESSION}`);
  assert.equal(apiCalls[0][1].headers.authorization, `CheckoutSession ${TOKEN}`);
  assert.equal(apiCalls[0][1].referrerPolicy, 'no-referrer');
});

test('rejects a query-string token because it would reach HTTP logs', async () => {
  const document = fakeDocument();
  const storage = new Map(); storage.getItem = storage.get.bind(storage); storage.setItem = storage.set.bind(storage); storage.removeItem = storage.delete.bind(storage);
  let called = false;
  const controller = new CheckoutController({ document, storage, history: { replaceState() {} },
    location: { href: `https://checkout.example/?session=${SESSION}&token=${TOKEN}` },
    api: async () => { called = true; } });
  await controller.start();
  assert.equal(called, false);
  assert.match(document.nodes.get('#error').textContent, /invalid/);
});
