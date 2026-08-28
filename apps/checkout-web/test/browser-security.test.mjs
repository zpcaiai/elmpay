import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { BrowserSecurityRuntime } from '../src/browser-security.mjs';
import { createHandler } from '../src/server.mjs';

globalThis.__ELMPAY_TEST__ = true;
const { installIntegrityMonitor } = await import('../public/integrity.mjs');

const publicRoot = fileURLToPath(new URL('../public/', import.meta.url));
const manifestPath = fileURLToPath(new URL('../security/script-allowlist.json', import.meta.url));

function responseCapture() {
  return {
    status: 0, headers: {}, body: Buffer.alloc(0),
    writeHead(status, headers = {}) { this.status = status; this.headers = headers; return this; },
    end(value = '') { this.body = Buffer.concat([this.body, Buffer.from(value)]); },
    on() {}, once() {}, emit() {},
  };
}

function request(path, { method = 'GET', body = '', headers = {} } = {}) {
  const value = Readable.from(body === '' ? [] : [Buffer.from(body)]);
  value.url = path; value.method = method; value.headers = headers;
  return value;
}

test('checkout page is rendered with per-response CSP nonce, SRI and Trusted Types', async () => {
  const handler = createHandler(); const first = responseCapture(); const second = responseCapture();
  await handler(request('/'), first); await handler(request('/'), second);
  assert.equal(first.status, 200); assert.equal(second.status, 200);
  assert.match(first.headers['content-security-policy'], /script-src 'nonce-[A-Za-z0-9_-]{24}' 'strict-dynamic'/);
  assert.match(first.headers['content-security-policy'], /require-trusted-types-for 'script'/);
  assert.match(first.headers['content-security-policy'], /trusted-types elmpay-checkout/);
  assert.match(first.headers['content-security-policy'], /report-uri \/security\/csp-report/);
  assert.notEqual(first.headers['content-security-policy'], second.headers['content-security-policy']);
  const html = first.body.toString('utf8');
  assert.doesNotMatch(html, /__SRI_|__CSP_NONCE__/);
  assert.match(html, /integrity="sha384-[A-Za-z0-9+/]{64}"/);
  assert.match(html, /nonce="[A-Za-z0-9_-]{24}"/);
});

test('script bytes are rechecked on every request and unlisted modules fail closed', () => {
  const security = new BrowserSecurityRuntime({ publicRoot, manifestPath, now: new Date('2026-08-28T00:00:00Z') });
  assert.ok(security.verifyScript('/checkout.mjs').byteLength > 100);
  assert.throws(() => security.verifyScript('/marketing-tag.mjs'), /not allowlisted/);
});

test('public policy exposes only source and SRI and integrity reports are sanitized', async () => {
  const reports = []; const handler = createHandler({ securityReportSink: async report => reports.push(report) });
  const policyResponse = responseCapture(); await handler(request('/security/script-policy'), policyResponse);
  assert.equal(policyResponse.status, 200);
  const policy = JSON.parse(policyResponse.body);
  assert.deepEqual(Object.keys(policy).sort(), ['manifestVersion', 'scripts', 'trustedTypesPolicy']);
  assert.ok(policy.scripts.every(item => Object.keys(item).sort().join(',') === 'source,sri'));

  const reportResponse = responseCapture();
  await handler(request('/security/integrity-report', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'PAGE_MUTATION', policyVersion: policy.manifestVersion,
      reasons: ['UNAUTHORIZED_SCRIPT_ELEMENT'] }),
  }), reportResponse);
  assert.equal(reportResponse.status, 204);
  assert.equal(reports[0].category, 'BROWSER_INTEGRITY');
  assert.equal(JSON.stringify(reports[0]).includes('authorization'), false);

  const cspResponse = responseCapture();
  await handler(request('/security/csp-report', {
    method: 'POST', body: JSON.stringify({ 'csp-report': {
      'effective-directive': 'script-src-elem', disposition: 'enforce',
      'document-uri': 'https://checkout.example/pay?token=sensitive',
      'blocked-uri': 'https://evil.example/skimmer.js?card=4111111111111111',
      'script-sample': 'sensitive customer text',
    } }),
  }), cspResponse);
  assert.equal(cspResponse.status, 204);
  assert.equal(reports[1].document, 'https://checkout.example/pay');
  assert.equal(reports[1].blocked, 'https://evil.example/skimmer.js');
  assert.equal(JSON.stringify(reports[1]).includes('4111111111111111'), false);
  assert.equal(JSON.stringify(reports[1]).includes('sensitive customer text'), false);

  const reportingApiResponse = responseCapture();
  await handler(request('/security/csp-report', {
    method: 'POST', body: JSON.stringify([{ type: 'csp-violation',
      url: 'https://checkout.example/pay?credential=secret', body: {
        effectiveDirective: 'script-src-elem', disposition: 'enforce',
        blockedURL: 'https://evil.example/modern-skimmer.js?token=secret',
      } }]),
  }), reportingApiResponse);
  assert.equal(reportingApiResponse.status, 204);
  assert.equal(reports[2].document, 'https://checkout.example/pay');
  assert.equal(reports[2].blocked, 'https://evil.example/modern-skimmer.js');
});

function fakeDocument(scripts) {
  const nodes = {
    status: { textContent: '' }, error: { textContent: '', hidden: true },
    button: { disabled: false },
  };
  return {
    scripts,
    documentElement: { dataset: {} },
    querySelector(value) { return value === '#status' ? nodes.status : value === '#error' ? nodes.error : null; },
    querySelectorAll() { return [nodes.button]; },
    nodes,
  };
}

test('browser monitor blocks unauthorized DOM script mutation and reports without raw URLs', async () => {
  const security = new BrowserSecurityRuntime({ publicRoot, manifestPath, now: new Date('2026-08-28T00:00:00Z') });
  const policy = security.publicPolicy();
  const scripts = policy.scripts.map(item => ({ src: `https://checkout.example${item.source}`, integrity: item.sri }));
  const document = fakeDocument(scripts); const calls = []; let observerCallback;
  class Observer {
    constructor(callback) { observerCallback = callback; }
    observe() {} disconnect() {}
  }
  const result = await installIntegrityMonitor({
    document, location: { href: 'https://checkout.example/pay#secret' }, MutationObserverImpl: Observer,
    fetchImpl: async (url, options) => {
      calls.push([url, options]);
      if (url === '/security/script-policy') return { ok: true, json: async () => policy };
      return { ok: true };
    },
  });
  assert.equal(result.allowed, true);
  scripts.push({ src: 'https://evil.example/skimmer.js?secret=value', integrity: '' });
  observerCallback(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(document.documentElement.dataset.integrity, 'blocked');
  assert.equal(document.nodes.button.disabled, true);
  assert.match(document.nodes.error.textContent, /blocked before payment data/);
  const report = JSON.parse(calls.find(([url]) => url === '/security/integrity-report')[1].body);
  assert.deepEqual(report.reasons, ['UNAUTHORIZED_SCRIPT_ELEMENT']);
  assert.equal(JSON.stringify(report).includes('evil.example'), false);
});

test('browser monitor fails closed when the policy endpoint is unavailable', async () => {
  const document = fakeDocument([]); const reports = [];
  const result = await installIntegrityMonitor({
    document, location: { href: 'https://checkout.example/' }, MutationObserverImpl: class {},
    fetchImpl: async (url, options) => {
      if (url === '/security/script-policy') return { ok: false };
      reports.push(JSON.parse(options.body)); return { ok: true };
    },
  });
  assert.equal(result.allowed, false);
  assert.equal(document.nodes.button.disabled, true);
  assert.deepEqual(reports[0].reasons, ['POLICY_UNAVAILABLE']);
});
