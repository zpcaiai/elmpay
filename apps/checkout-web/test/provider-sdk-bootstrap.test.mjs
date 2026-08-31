import assert from 'node:assert/strict';
import { test } from 'node:test';

globalThis.__ELMPAY_TEST__ = true;
const {
  ProviderSdkBootstrap, installIsolatedProviderHandlers,
} = await import('../public/provider-sdk-bootstrap.mjs');

const SESSION = '00000000-0000-4000-8000-000000000000';
const TOKEN = `${'M'.repeat(48)}.${'A'.repeat(43)}`;
const INTEGRITY = `sha384-${'A'.repeat(64)}`;

class MessageTarget {
  constructor() { this.listeners = new Set(); }
  addEventListener(type, listener) { if (type === 'message') this.listeners.add(listener); }
  removeEventListener(type, listener) { if (type === 'message') this.listeners.delete(listener); }
  emit(event) { for (const listener of [...this.listeners]) listener(event); }
}

function fixture({ framePath = '/security/provider-sdk-frame?ticket=signed.ticket',
  scriptUrl = 'https://sdk.provider.example/v1/sdk.js' } = {}) {
  const target = new MessageTarget(); const sent = [];
  const container = {
    hidden: true, children: [],
    replaceChildren(...children) { this.children = children; },
  };
  const contentWindow = { postMessage(message, origin) { sent.push([message, origin]); } };
  const frame = {
    attrs: {}, contentWindow, removed: false,
    setAttribute(name, value) { this.attrs[name] = value; },
    addEventListener() {}, removeEventListener() {},
    remove() { this.removed = true; container.children = []; },
  };
  const document = {
    querySelector(selector) { return selector === '#provider-sdk-container' ? container : null; },
    createElement(name) { assert.equal(name, 'iframe'); return frame; },
  };
  const storage = new Map([[`elmpay.checkout.token.${SESSION}`, TOKEN]]);
  storage.getItem = storage.get.bind(storage);
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push([url, options]);
    return {
      ok: true, headers: { get: name => name === 'content-type' ? 'application/json' : null },
      async json() {
        return {
          schemaVersion: 1, policyVersion: 'policy-v1', method: 'card', provider: 'provider-a',
          sdkVersion: 'sdk-v1', scriptUrl, integrity: INTEGRITY,
          publicParameters: { publishableKey: 'pk_live_reviewed' }, framePath,
          expiresAt: '2026-08-30T12:00:30.000Z',
        };
      },
    };
  };
  let sequence = 0;
  const cryptoImpl = { randomUUID() { sequence += 1;
    return sequence === 1 ? '11111111-1111-4111-8111-111111111111'
      : '22222222-2222-4222-8222-222222222222'; } };
  return { target, sent, container, frame, document, storage, calls, fetchImpl, cryptoImpl };
}

function configurationResponse(base, overrides = {}) {
  const original = base.fetchImpl;
  base.fetchImpl = async (url, options) => {
    const response = await original(url, options); const value = await response.json();
    return { ...response, json: async () => ({ ...value, ...overrides }) };
  };
}

test('same-origin server config creates only a sandboxed opaque-origin frame', async () => {
  const value = fixture();
  const runtime = new ProviderSdkBootstrap({
    ...value, location: { href: 'https://checkout.example/pay' }, messageTarget: value.target,
    now: () => Date.parse('2026-08-30T12:00:00Z'),
  });
  const pending = runtime.prepare({ method: 'card', checkoutSessionId: SESSION });
  await new Promise(resolve => setImmediate(resolve));
  const configUrl = new URL(value.calls[0][0], 'https://checkout.example');
  const channel = configUrl.searchParams.get('channel');
  assert.equal(configUrl.origin, 'https://checkout.example');
  assert.equal(value.calls[0][1].redirect, 'error');
  assert.equal(value.calls[0][1].credentials, 'same-origin');
  assert.equal(value.frame.attrs.sandbox, 'allow-scripts');
  assert.equal(value.frame.attrs.sandbox.includes('allow-same-origin'), false);
  assert.equal(value.frame.attrs.credentialless, '');
  assert.equal(value.frame.src, '/security/provider-sdk-frame?ticket=signed.ticket');
  assert.equal(value.frame.src.includes('sdk.provider.example'), false);

  value.target.emit({ source: value.frame.contentWindow, origin: 'null', data: {
    protocol: 'elmpay-provider-sdk-v1', channel, type: 'BOOTED',
  } });
  assert.equal(value.sent[0][1], '*');
  assert.deepEqual(Object.keys(value.sent[0][0].configuration).sort(),
    ['method', 'provider', 'publicParameters', 'sdkVersion']);
  value.target.emit({ source: value.frame.contentWindow, origin: 'null', data: {
    protocol: 'elmpay-provider-sdk-v1', channel, type: 'READY',
  } });
  await pending;
  runtime.close();
});

test('cross-origin config bases and cross-origin frame paths are rejected before DOM injection', async () => {
  const first = fixture();
  assert.throws(() => new ProviderSdkBootstrap({
    ...first, location: { href: 'https://checkout.example/pay' }, messageTarget: first.target,
    configurationBase: 'https://evil.example/api/checkout/sessions/',
  }), /same-origin/);

  const second = fixture();
  configurationResponse(second, { framePath: 'https://evil.example/provider-frame?ticket=x' });
  const runtime = new ProviderSdkBootstrap({
    ...second, location: { href: 'https://checkout.example/pay' }, messageTarget: second.target,
    now: () => Date.parse('2026-08-30T12:00:00Z'),
  });
  await assert.rejects(runtime.prepare({ method: 'card', checkoutSessionId: SESSION }), /same-origin/);
  assert.equal(second.container.children.length, 0);
});

test('arbitrary script metadata is never used as a script or iframe source', async () => {
  const value = fixture({ scriptUrl: 'https://attacker.example/arbitrary.js' });
  const runtime = new ProviderSdkBootstrap({
    ...value, location: { href: 'https://checkout.example/pay' }, messageTarget: value.target,
    now: () => Date.parse('2026-08-30T12:00:00Z'),
  });
  const pending = runtime.prepare({ method: 'card', checkoutSessionId: SESSION });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(value.frame.src, '/security/provider-sdk-frame?ticket=signed.ticket');
  assert.equal(JSON.stringify(value.frame).includes('attacker.example'), false);
  const channel = new URL(value.calls[0][0], 'https://checkout.example').searchParams.get('channel');
  value.target.emit({ source: value.frame.contentWindow, origin: 'null', data: {
    protocol: 'elmpay-provider-sdk-v1', channel, type: 'ERROR', code: 'SDK_CONTRACT_UNAVAILABLE',
  } });
  await assert.rejects(pending, /rejected initialization/);
  assert.equal(value.frame.removed, true);
});

test('wrong source and origin cannot complete the handshake; timeout removes the frame', async () => {
  const value = fixture(); const timers = new Map(); let nextTimer = 0;
  const setTimer = callback => { nextTimer += 1; timers.set(nextTimer, callback); return nextTimer; };
  const clearTimer = id => timers.delete(id);
  const runtime = new ProviderSdkBootstrap({
    ...value, location: { href: 'https://checkout.example/pay' }, messageTarget: value.target,
    now: () => Date.parse('2026-08-30T12:00:00Z'), setTimer, clearTimer,
    handshakeTimeoutMilliseconds: 100, operationTimeoutMilliseconds: 100,
  });
  const pending = runtime.prepare({ method: 'card', checkoutSessionId: SESSION });
  await new Promise(resolve => setImmediate(resolve));
  const channel = new URL(value.calls[0][0], 'https://checkout.example').searchParams.get('channel');
  value.target.emit({ source: {}, origin: 'null', data: {
    protocol: 'elmpay-provider-sdk-v1', channel, type: 'READY',
  } });
  value.target.emit({ source: value.frame.contentWindow, origin: 'https://checkout.example', data: {
    protocol: 'elmpay-provider-sdk-v1', channel, type: 'READY',
  } });
  assert.equal(value.sent.length, 0);
  timers.get(1)();
  await assert.rejects(pending, /timed out/);
  assert.equal(value.frame.removed, true);
  assert.equal(value.target.listeners.size, 0);
});

test('an in-flight provider operation timeout rejects and destroys the isolated context', async () => {
  const value = fixture(); const timers = new Map(); let nextTimer = 0;
  const setTimer = callback => { nextTimer += 1; timers.set(nextTimer, callback); return nextTimer; };
  const clearTimer = id => timers.delete(id);
  const runtime = new ProviderSdkBootstrap({
    ...value, location: { href: 'https://checkout.example/pay' }, messageTarget: value.target,
    now: () => Date.parse('2026-08-30T12:00:00Z'), setTimer, clearTimer,
    handshakeTimeoutMilliseconds: 100, operationTimeoutMilliseconds: 100,
  });
  const prepared = runtime.prepare({ method: 'card', checkoutSessionId: SESSION });
  await new Promise(resolve => setImmediate(resolve));
  const channel = new URL(value.calls[0][0], 'https://checkout.example').searchParams.get('channel');
  value.target.emit({ source: value.frame.contentWindow, origin: 'null', data: {
    protocol: 'elmpay-provider-sdk-v1', channel, type: 'BOOTED',
  } });
  value.target.emit({ source: value.frame.contentWindow, origin: 'null', data: {
    protocol: 'elmpay-provider-sdk-v1', channel, type: 'READY',
  } });
  await prepared;
  const tokenizing = runtime.tokenize({ method: 'card', checkoutSessionId: SESSION });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(value.sent.at(-1)[0].operation, 'tokenize');
  timers.get(2)();
  await assert.rejects(tokenizing, /timed out/);
  assert.equal(value.frame.removed, true);
  assert.equal(value.target.listeners.size, 0);
});

test('existing provider handler API is preserved while calls are delegated to isolation', async () => {
  const calls = [];
  const runtime = {
    async prepare(context) { calls.push(['prepare', context]); },
    async tokenize(context) { calls.push(['tokenize', context]);
      return { paymentMethodReference: 'psp://provider/reference-1' }; },
    async handleAction(method, action, context) { calls.push(['action', method, action, context]); },
  };
  const target = {};
  installIsolatedProviderHandlers({ target, runtime });
  await target.ElmPayPaymentMethodTokenizer.prepare({ method: 'card', checkoutSessionId: SESSION });
  assert.deepEqual(await target.ElmPayPaymentMethodTokenizer.tokenize({
    method: 'card', checkoutSessionId: SESSION,
  }), { paymentMethodReference: 'psp://provider/reference-1' });
  await target.ElmPayNextActionHandler.handle({ method: 'card', action: 'authorize' },
    { checkoutSessionId: SESSION });
  assert.deepEqual(calls.map(call => call[0]), ['prepare', 'tokenize', 'action']);
});
