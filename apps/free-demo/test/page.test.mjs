import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { renderDemoPage, demoAsset } from '../src/page.mjs';
import { demoReference } from '../src/demo.mjs';
import * as demo from '../src/demo.mjs';
import { scenarios } from '../src/bridge.mjs';

test('standalone page visibly forbids real funds and never offers card-data inputs', () => {
  const first = renderDemoPage(); const second = renderDemoPage();
  assert.match(first.html, /免费演示/); assert.match(first.html, /不发生真实扣款/);
  assert.match(first.html, /重启后清空/);
  assert.match(first.html, /id="create-demo"/); assert.match(first.html, /id="continue"/);
  assert.doesNotMatch(first.html, /type="(?:password|number)"|name="(?:pan|cvv|card_number)"/);
  assert.notEqual(first.headers['content-security-policy'], second.headers['content-security-policy']);
  assert.match(first.headers['content-security-policy'], /default-src 'none'/);
  assert.match(first.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.match(first.headers['permissions-policy'], /payment=\(\)/);
  assert.equal(first.headers['cache-control'], 'no-store');
  const bytes = readFileSync(new URL('../src/demo.mjs', import.meta.url));
  const digest = `sha384-${createHash('sha384').update(bytes).digest('base64')}`;
  assert.ok(first.html.includes(`integrity="${digest}"`));
});

test('demo reference adapter only emits synthetic references and selected local outcomes', () => {
  const id = '21000000-0000-4000-8000-000000000004';
  assert.deepEqual(demoReference(id, 'declined'), {
    paymentMethodReference: `psp://elmpay-demo/${id}`,
    providerParameters: { simulation: 'declined' },
  });
  assert.throws(() => demoReference(id, 'real-payment'), /invalid demo/);
  assert.throws(() => demoReference('4111111111111111', 'succeeded'), /invalid demo/);
});

test('only reviewed demo/controller/style assets are served, with no filesystem traversal', () => {
  assert.equal(demoAsset('/demo.mjs').type, 'text/javascript; charset=utf-8');
  assert.equal(demoAsset('/checkout.mjs').type, 'text/javascript; charset=utf-8');
  assert.equal(demoAsset('/styles.css').type, 'text/css; charset=utf-8');
  assert.equal(demoAsset('/../../.env'), null);
  assert.equal(demoAsset('/provider-sdk-bootstrap.mjs'), null);
  assert.equal(demoAsset('/src/bridge.mjs'), null);
});

test('browser API transport preserves the native fetch Window receiver', async () => {
  const original = globalThis.fetch;
  const expected = { ok: true };
  globalThis.fetch = function (url, options) {
    if (this !== globalThis) throw new TypeError('Illegal invocation');
    assert.equal(url, '/api/checkout/sessions/example');
    assert.equal(options.cache, 'no-store');
    return Promise.resolve(expected);
  };
  try {
    const controller = { api: demo.demoApi };
    assert.equal(await controller.api('/api/checkout/sessions/example', { cache: 'no-store' }), expected);
  } finally { globalThis.fetch = original; }
});

test('all native demo scenarios have labeled choices and synthetic-only references', () => {
  assert.deepEqual(demo.demoScenarios.map(value => value.id), scenarios);
  const html = renderDemoPage().html;
  for (const scenario of scenarios) {
    assert.ok(html.includes(`value="${scenario}"`));
    assert.equal(demoReference('21000000-0000-4000-8000-000000000004', scenario)
      .providerParameters.simulation, scenario);
  }
});

test('UI presentation follows authoritative state and never treats pending or unknown as success', () => {
  for (const status of ['OPEN', 'PENDING', 'FAILED', 'EXPIRED', 'CANCELED', 'not-a-state']) {
    const value = demo.demoPresentation({ status, scenario: 'succeeded' });
    assert.notEqual(value.tone, 'success');
    assert.doesNotMatch(value.heading, /已成功/);
  }
  assert.equal(demo.demoPresentation({ status: 'SUCCEEDED', scenario: 'declined' }).tone, 'success');
  assert.match(demo.demoPresentation({ status: 'PENDING' }).description, /未.*成功|不会.*成功/);
});

test('closed-state display hides internal codes without changing server status or method eligibility', () => {
  const original = { status: 'PENDING', methods: [{ id: 'card', label: '银行卡', eligible: false,
    reason: 'SESSION_NOT_OPEN' }] };
  const view = demo.demoDisplayView(original);
  assert.equal(view.status, original.status);
  assert.equal(view.methods[0].eligible, false);
  assert.equal(view.methods[0].reason, '');
  assert.equal(original.methods[0].reason, 'SESSION_NOT_OPEN');
  const open = { ...original, status: 'OPEN' };
  assert.equal(demo.demoDisplayView(open), open);
});

test('create retry keys stay with one scenario and rotate for a changed scenario', () => {
  const values = new Map();
  const storage = { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
  const first = demo.demoCreateRequest(storage, 'succeeded');
  assert.deepEqual(demo.demoCreateRequest(storage, 'succeeded'), first);
  assert.notEqual(demo.demoCreateRequest(storage, 'declined').key, first.key);
  assert.throws(() => demo.demoCreateRequest(storage, 'live'), /invalid demo/);
});

test('WeChat simulation is explicit and profile changes cannot reuse card order keys', () => {
  const html = renderDemoPage().html;
  assert.match(html, /微信支付（模拟）/);
  assert.match(html, /￥10\.00/);
  assert.match(html, /不生成真实支付二维码/);
  assert.match(html, /id="demo-method"/);
  assert.equal(demo.demoProfiles[0].method, 'wechat_native');
  assert.equal(demo.demoProfiles[0].currency, 'CNY');
  const values = new Map();
  const storage = { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
  const card = demo.demoCreateRequest(storage, 'unknown', 'card');
  const wechat = demo.demoCreateRequest(storage, 'unknown', 'wechat_native');
  assert.notEqual(wechat.key, card.key);
  assert.deepEqual(demo.demoCreateRequest(storage, 'unknown', 'wechat_native'), wechat);
  assert.notEqual(demo.demoCreateRequest(storage, 'declined', 'wechat_native').key, wechat.key);
  assert.throws(() => demo.demoCreateRequest(storage, 'unknown', 'wechat_jsapi'), /invalid demo/);
});

test('WeChat display retains actual server method, amount, state and eligibility', () => {
  const original = { amount: 1000, currency: 'CNY', displayAmount: '￥10.00', status: 'PENDING',
    methods: [{ id: 'wechat_native', label: '微信支付', eligible: false, reason: 'SESSION_NOT_OPEN' }] };
  const result = demo.demoDisplayView(original);
  assert.equal(result.methods[0].id, 'wechat_native');
  assert.equal(result.methods[0].label, '微信支付（模拟）');
  assert.equal(result.methods[0].eligible, false);
  assert.equal(result.currency, 'CNY');
  assert.equal(result.amount, 1000);
  assert.equal(result.displayAmount, original.displayAmount);
  assert.equal(result.status, 'PENDING');
  assert.equal(original.methods[0].label, '微信支付');
  assert.equal(demo.demoDisplayView({ ...original, status: 'OPEN' }).methods[0].label, '微信支付（模拟）');
});

test('page provides semantic progress, recovery, skip navigation and readable contrast', () => {
  const html = renderDemoPage().html;
  assert.match(html, /href="#main"/);
  assert.match(html, /aria-label="演示进度"/);
  assert.match(html, /id="order-summary-title"/);
  assert.match(html, /id="retry-status"/);
  assert.match(html, /:focus-visible/);
  assert.match(html, /min-height:48px/);
  const colors = Object.fromEntries([...html.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6})/g)]
    .map(match => [match[1], match[2]]));
  function luminance(hex) {
    const channels = hex.slice(1).match(/../g).map(value => parseInt(value, 16) / 255)
      .map(value => value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4);
    return channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722;
  }
  for (const [foreground, background] of [['ink', 'surface'], ['muted', 'surface'],
    ['surface', 'brand'], ['warning', 'warning-bg'], ['danger', 'surface']]) {
    assert.ok(colors[foreground] && colors[background]);
    const values = [luminance(colors[foreground]), luminance(colors[background])].sort((a, b) => b - a);
    assert.ok((values[0] + .05) / (values[1] + .05) >= 4.5, foreground + ' contrast too low');
  }
});
