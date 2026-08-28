import assert from 'node:assert/strict';
import { test } from 'node:test';

globalThis.__ELMPAY_TEST__ = true;
const { CheckoutController } = await import('../public/checkout.mjs');
const TOKEN = `${'M'.repeat(48)}.${'A'.repeat(43)}`;
const SESSION = '00000000-0000-4000-8000-000000000000';

const element = () => ({ textContent: '', hidden: true, disabled: false, attrs: {}, children: [],
  setAttribute(k, v) { this.attrs[k] = v; }, replaceChildren(...v) { this.children = v; }, append(...v) { this.children.push(...v); } });

function fakeDocument() {
  const nodes = new Map(['#checkout','#amount','#methods','#continue','#status','#error',
    '#page-title','#method-legend'].map(id => [id, element()]));
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
  const calls = []; const controller = new CheckoutController({ document, storage, location: { href: 'https://x/' }, history: { replaceState() {} },
    tokenizer: async () => ({ paymentMethodReference: 'psp://stripe/pm_test_1', fingerprint: 'fp_test_1' }), api: async (url, options) => {
    calls.push([url, options]);
    if (options.method === 'POST') return { ok: true };
    return { ok: true, json: async () => ({ status: 'SUCCEEDED', displayAmount: '$1.00', locale: 'en', direction: 'ltr', methods: [] }) };
  } }); controller.sessionId = SESSION; controller.accessToken = TOKEN;
  await controller.confirm('card'); const first = calls[0][1].headers['idempotency-key']; calls.length = 0;
  await controller.confirm('card'); assert.equal(calls[0][1].headers['idempotency-key'], first);
  assert.equal(document.nodes.get('#status').textContent, 'Payment verified by the server.');
  assert.equal(calls[0]?.[1]?.headers?.authorization, `CheckoutSession ${TOKEN}`);
  assert.deepEqual(JSON.parse(calls[0][1].body), { method: 'card',
    payment_method_reference: 'psp://stripe/pm_test_1', fingerprint: 'fp_test_1' });
});

test('production confirmation fails closed without an official tokenizer', async () => {
  const document = fakeDocument(); const storage = new Map(); storage.getItem = storage.get.bind(storage); storage.setItem = storage.set.bind(storage); storage.removeItem = storage.delete.bind(storage);
  let called = false; const controller = new CheckoutController({ document, storage,
    location: { href: 'https://x/' }, history: { replaceState() {} },
    api: async () => { called = true; return { ok: true }; } });
  controller.sessionId = SESSION; controller.accessToken = TOKEN;
  await controller.confirm('card');
  assert.equal(called, false);
  assert.match(document.nodes.get('#error').textContent, /outcome remains unverified/);
});

test('rejects PAN-shaped tokenizer output before it reaches the API', async () => {
  const document = fakeDocument(); const storage = new Map(); storage.getItem = storage.get.bind(storage); storage.setItem = storage.set.bind(storage); storage.removeItem = storage.delete.bind(storage);
  let called = false; const controller = new CheckoutController({ document, storage,
    location: { href: 'https://x/' }, history: { replaceState() {} },
    tokenizer: async () => ({ paymentMethodReference: 'psp://unsafe/4111111111111111' }),
    api: async () => { called = true; return { ok: true }; } });
  controller.sessionId = SESSION; controller.accessToken = TOKEN;
  await controller.confirm('card');
  assert.equal(called, false);
});

test('passes nextAction only to an explicit handler then refreshes server state', async () => {
  const document = fakeDocument(); const storage = new Map(); storage.getItem = storage.get.bind(storage); storage.setItem = storage.set.bind(storage); storage.removeItem = storage.delete.bind(storage);
  const actions = []; const controller = new CheckoutController({ document, storage,
    location: { href: 'https://x/' }, history: { replaceState() {} },
    tokenizer: async () => ({ paymentMethodReference: 'wallet://apple-pay/token-1' }),
    nextActionHandler: async (action, context) => actions.push([action, context]),
    api: async (url, options) => options.method === 'POST'
      ? { ok: true, json: async () => ({ status: 'PENDING', nextAction: { action: 'wallet_authorize' } }) }
      : { ok: true, json: async () => ({ status: 'SUCCEEDED', displayAmount: '$1.00', locale: 'en', direction: 'ltr', methods: [] }) } });
  controller.sessionId = SESSION; controller.accessToken = TOKEN;
  await controller.confirm('apple_pay');
  assert.deepEqual(actions, [[{ action: 'wallet_authorize' }, { checkoutSessionId: SESSION }]]);
  assert.equal(document.nodes.get('#status').textContent, 'Payment verified by the server.');
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

test('renders the server-selected versioned RTL and accessibility catalog', () => {
  const document = fakeDocument();
  const controller = new CheckoutController({ document, storage: new Map(),
    history: { replaceState() {} }, location: { href: 'https://checkout.example/' } });
  controller.render({ status: 'OPEN', displayAmount: '١٢٫٣٤ US$', locale: 'ar',
    direction: 'rtl', methods: [{ id: 'card', label: 'بطاقة', eligible: true, reason: '' }],
    catalogVersion: 'checkout-catalog-2026-08-v1', messages: {
      'ui.pageTitle': 'دفع آمن', 'ui.methodLegend': 'اختر طريقة الدفع',
      'ui.continueAction': 'متابعة آمنة', 'status.current': 'جاهز للدفع،',
      'error.unknown': 'الحالة غير معروفة',
    } });
  assert.equal(document.documentElement.lang, 'ar');
  assert.equal(document.documentElement.dir, 'rtl');
  assert.equal(document.nodes.get('#page-title').textContent, 'دفع آمن');
  assert.equal(document.nodes.get('#method-legend').textContent, 'اختر طريقة الدفع');
  assert.equal(document.nodes.get('#status').textContent, 'جاهز للدفع،');
  assert.equal(document.nodes.get('#methods').children[0].children[1], 'بطاقة');
  clearTimeout(controller.timer);
});
