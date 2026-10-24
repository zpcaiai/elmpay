import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { renderDemoPage, demoAsset } from '../src/page.mjs';
import { demoReference } from '../src/demo.mjs';

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
