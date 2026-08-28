const policyPath = '/security/script-policy';
const reportPath = '/security/integrity-report';

function normalizedScript(script, origin) {
  let url;
  try { url = new URL(script.src, origin); } catch { return null; }
  if (url.origin !== origin || url.search || url.hash) return null;
  return { source: url.pathname, sri: script.integrity ?? '' };
}

function validatePolicy(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || typeof value.manifestVersion !== 'string'
      || value.trustedTypesPolicy !== 'elmpay-checkout'
      || !Array.isArray(value.scripts) || value.scripts.length === 0) {
    throw new Error('browser integrity policy is invalid');
  }
  const entries = new Map();
  for (const item of value.scripts) {
    if (!item || Object.getPrototypeOf(item) !== Object.prototype
        || Object.keys(item).sort().join(',') !== 'source,sri'
        || !/^\/[A-Za-z0-9._/-]+\.mjs$/.test(item.source)
        || !/^sha384-[A-Za-z0-9+/]{64}$/.test(item.sri)
        || entries.has(item.source)) throw new Error('browser integrity policy is invalid');
    entries.set(item.source, item.sri);
  }
  return { version: value.manifestVersion, entries };
}

function inspect(document, origin, expected) {
  const seen = new Set(); const reasons = [];
  for (const script of Array.from(document.scripts ?? [])) {
    const item = normalizedScript(script, origin);
    if (item === null || !expected.has(item.source)) {
      reasons.push('UNAUTHORIZED_SCRIPT_ELEMENT');
      continue;
    }
    if (seen.has(item.source)) reasons.push('DUPLICATE_SCRIPT_ELEMENT');
    seen.add(item.source);
    if (item.sri !== expected.get(item.source)) reasons.push('SCRIPT_SRI_MISMATCH');
  }
  for (const source of expected.keys()) {
    if (!seen.has(source)) reasons.push('ALLOWLISTED_SCRIPT_MISSING');
  }
  return [...new Set(reasons)].sort();
}

function lockDown(document) {
  if (document.documentElement?.dataset) document.documentElement.dataset.integrity = 'blocked';
  for (const control of Array.from(document.querySelectorAll?.('button,input,select,textarea') ?? [])) {
    control.disabled = true;
  }
  const status = document.querySelector?.('#status');
  if (status) status.textContent = 'Checkout integrity could not be verified.';
  const error = document.querySelector?.('#error');
  if (error) {
    error.hidden = false;
    error.textContent = 'This checkout has been blocked before payment data was requested.';
  }
}

async function emitReport(fetchImpl, report) {
  try {
    await fetchImpl(reportPath, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      referrerPolicy: 'no-referrer', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(report),
    });
  } catch { /* A reporting outage must not unlock the checkout. */ }
}

export async function installIntegrityMonitor({
  document = globalThis.document,
  location = globalThis.location,
  fetchImpl = globalThis.fetch,
  MutationObserverImpl = globalThis.MutationObserver,
} = {}) {
  const origin = new URL(location.href).origin;
  let policy;
  try {
    const response = await fetchImpl(policyPath, {
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      headers: { accept: 'application/json' },
    });
    if (!response.ok) throw new Error('policy unavailable');
    policy = validatePolicy(await response.json());
  } catch {
    lockDown(document);
    await emitReport(fetchImpl, { type: 'POLICY_UNAVAILABLE', reasons: ['POLICY_UNAVAILABLE'] });
    return { allowed: false, reasons: ['POLICY_UNAVAILABLE'], disconnect() {} };
  }
  const initial = inspect(document, origin, policy.entries);
  if (initial.length > 0) {
    lockDown(document);
    await emitReport(fetchImpl, { type: 'PAGE_INTEGRITY', policyVersion: policy.version, reasons: initial });
    return { allowed: false, reasons: initial, disconnect() {} };
  }
  let blocked = false;
  const observer = typeof MutationObserverImpl === 'function' ? new MutationObserverImpl(() => {
    const reasons = inspect(document, origin, policy.entries);
    if (reasons.length > 0 && !blocked) {
      blocked = true;
      lockDown(document);
      void emitReport(fetchImpl, { type: 'PAGE_MUTATION', policyVersion: policy.version, reasons });
    }
  }) : null;
  observer?.observe?.(document.documentElement, {
    subtree: true, childList: true, attributes: true, attributeFilter: ['src', 'integrity'],
  });
  return {
    allowed: true,
    reasons: [],
    disconnect() { observer?.disconnect?.(); },
  };
}

if (typeof window !== 'undefined' && !globalThis.__ELMPAY_TEST__) {
  globalThis.__ELMPAY_INTEGRITY_READY__ = installIntegrityMonitor();
}
