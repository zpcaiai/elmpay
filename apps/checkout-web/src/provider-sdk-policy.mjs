import {
  createHash, createHmac, randomBytes, timingSafeEqual,
} from 'node:crypto';
import { readFileSync } from 'node:fs';

const methodPattern = /^[a-z0-9._-]{1,64}$/;
const checkoutSessionPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const channelPattern = /^[A-Za-z0-9_-]{20,128}$/;
const identifierPattern = /^[A-Za-z0-9._:-]{1,128}$/;
const sriPattern = /^sha384-[A-Za-z0-9+/]{64}$/;
const parameterNamePattern = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
const parameterValuePattern = /^[\x20-\x7e]{1,512}$/;
const deniedParameterNames = /(?:secret|private|password|credential|token|pan|cvv|cvc|authorization)/i;
const ticketLifetimeMilliseconds = 30_000;

function exactKeys(value, expected) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

function requirePublicDnsName(hostname) {
  if (typeof hostname !== 'string' || hostname.length > 253 || hostname.endsWith('.')
      || hostname === 'localhost' || hostname.endsWith('.local') || hostname.includes(':')
      // Numeric IPv4 literals are not public DNS names and can resolve to loopback,
      // link-local or private addresses.  Require a DNS label with alphabetic content.
      || /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname)
      || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(hostname)) {
    throw new Error('provider SDK host must be a canonical public DNS name');
  }
}

function exactHttpsOrigin(value) {
  if (typeof value !== 'string') throw new Error('provider SDK origin is invalid');
  const url = new URL(value);
  requirePublicDnsName(url.hostname);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/'
      || url.search || url.hash || value !== url.origin) {
    throw new Error('provider SDK origins must be canonical credential-free HTTPS origins');
  }
  return url.origin;
}

function exactSdkUrl(value) {
  if (typeof value !== 'string' || value.length > 2048 || value.includes('\\')
      || /[\s'";]/.test(value)) {
    throw new Error('provider SDK URL is invalid');
  }
  const url = new URL(value);
  requirePublicDnsName(url.hostname);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash
      || url.hostname.endsWith('.') || url.pathname.length < 2 || url.href !== value) {
    throw new Error('provider SDK URL must be canonical credential-free HTTPS');
  }
  return url.href;
}

function canonicalConfiguration(value) {
  const parameters = {};
  for (const key of Object.keys(value.publicParameters).sort()) parameters[key] = value.publicParameters[key];
  return JSON.stringify({
    method: value.method,
    provider: value.provider,
    sdkVersion: value.sdkVersion,
    publicParameters: parameters,
  });
}

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function safeJson(value) {
  return JSON.stringify(value)
    .replaceAll('<', '\\u003c').replaceAll('>', '\\u003e').replaceAll('&', '\\u0026')
    .replaceAll('\u2028', '\\u2028').replaceAll('\u2029', '\\u2029');
}

function escapeAttribute(value) {
  return value.replaceAll('&', '&amp;').replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

function normalizeOrigins(values) {
  if (!Array.isArray(values) || values.length > 32) throw new Error('provider SDK origin list is invalid');
  const origins = values.map(exactHttpsOrigin);
  if (new Set(origins).size !== origins.length) throw new Error('provider SDK origin list contains duplicates');
  return Object.freeze(origins);
}

function normalizeEntry(value, now) {
  const keys = ['id', 'methods', 'sdkVersion', 'scriptUrl', 'integrity', 'adapterContract',
    'publicParameterKeys', 'connectOrigins', 'frameOrigins', 'owner', 'reviewExpiresAt', 'enabled'];
  if (!exactKeys(value, keys) || !identifierPattern.test(value.id ?? '')
      || !identifierPattern.test(value.sdkVersion ?? '')
      || value.adapterContract !== 'elmpay-isolated-provider-v1'
      || typeof value.owner !== 'string' || value.owner.length < 1 || value.owner.length > 128
      || typeof value.enabled !== 'boolean' || !sriPattern.test(value.integrity ?? '')
      || !Number.isFinite(Date.parse(value.reviewExpiresAt))
      || Date.parse(value.reviewExpiresAt) <= now.getTime()
      || !Array.isArray(value.methods) || value.methods.length < 1 || value.methods.length > 32
      || value.methods.some(method => !methodPattern.test(method))
      || new Set(value.methods).size !== value.methods.length
      || !Array.isArray(value.publicParameterKeys) || value.publicParameterKeys.length > 32
      || value.publicParameterKeys.some(key => !parameterNamePattern.test(key)
        || deniedParameterNames.test(key))
      || new Set(value.publicParameterKeys).size !== value.publicParameterKeys.length) {
    throw new Error('provider SDK allowlist entry is invalid or expired');
  }
  const scriptUrl = exactSdkUrl(value.scriptUrl);
  return Object.freeze({
    id: value.id,
    methods: Object.freeze([...value.methods]),
    sdkVersion: value.sdkVersion,
    scriptUrl,
    integrity: value.integrity,
    adapterContract: value.adapterContract,
    publicParameterKeys: Object.freeze([...value.publicParameterKeys].sort()),
    connectOrigins: normalizeOrigins(value.connectOrigins),
    frameOrigins: normalizeOrigins(value.frameOrigins),
    owner: value.owner,
    reviewExpiresAt: value.reviewExpiresAt,
    enabled: value.enabled,
  });
}

function parseManifest(value, now) {
  if (!exactKeys(value, ['schemaVersion', 'manifestVersion', 'reviewExpiresAt', 'providers',
    'externalAssessmentStatus']) || value.schemaVersion !== 1
      || !identifierPattern.test(value.manifestVersion ?? '')
      || !Number.isFinite(Date.parse(value.reviewExpiresAt))
      || Date.parse(value.reviewExpiresAt) <= now.getTime()
      || !Array.isArray(value.providers) || value.providers.length > 64
      || !['BLOCKED', 'VERIFIED'].includes(value.externalAssessmentStatus)) {
    throw new Error('provider SDK allowlist is invalid or expired');
  }
  const entries = value.providers.map(entry => normalizeEntry(entry, now));
  const providers = new Set(); const methods = new Map();
  for (const entry of entries) {
    if (providers.has(entry.id)) throw new Error('provider SDK allowlist contains duplicate providers');
    providers.add(entry.id);
    for (const method of entry.methods) {
      if (methods.has(method)) throw new Error('provider SDK method has multiple owners');
      methods.set(method, entry);
    }
  }
  return Object.freeze({
    manifestVersion: value.manifestVersion,
    reviewExpiresAt: value.reviewExpiresAt,
    externalAssessmentStatus: value.externalAssessmentStatus,
    entries: Object.freeze(entries),
    methods,
  });
}

function normalizeTicketKey(value) {
  const key = Buffer.from(value ?? []);
  if (key.byteLength < 32) throw new Error('provider frame ticket key must contain at least 32 bytes');
  return key;
}

function validatePublicConfiguration(entry, value) {
  if (!exactKeys(value, ['method', 'provider', 'sdkVersion', 'publicParameters'])
      || !entry.methods.includes(value.method) || value.provider !== entry.id
      || value.sdkVersion !== entry.sdkVersion
      || !value.publicParameters
      || Object.getPrototypeOf(value.publicParameters) !== Object.prototype
      || Object.keys(value.publicParameters).sort().join(',') !== entry.publicParameterKeys.join(',')) {
    throw new Error('upstream provider SDK configuration does not match the reviewed allowlist');
  }
  const parameters = {};
  for (const name of entry.publicParameterKeys) {
    const parameter = value.publicParameters[name];
    if (typeof parameter !== 'string' || !parameterValuePattern.test(parameter)
        || /[\r\n<>]/.test(parameter)) {
      throw new Error('provider SDK public parameter is invalid');
    }
    parameters[name] = parameter;
  }
  return Object.freeze({
    method: value.method,
    provider: value.provider,
    sdkVersion: value.sdkVersion,
    publicParameters: Object.freeze(parameters),
  });
}

function frameProgram({ channel, configurationDigest, adapterContract }) {
  return `(() => {
  'use strict';
  const PROTOCOL = 'elmpay-provider-sdk-v1';
  const CHANNEL = ${safeJson(channel)};
  const EXPECTED_DIGEST = ${safeJson(configurationDigest)};
  const CONTRACT = ${safeJson(adapterContract)};
  const container = document.querySelector('#provider-sdk-container');
  let initialized = false;
  let failed = false;
  let activeRequest = false;

  const send = value => parent.postMessage(value, '*');
  const exactKeys = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
  const canonical = config => {
    const parameters = {};
    for (const key of Object.keys(config.publicParameters).sort()) parameters[key] = config.publicParameters[key];
    return JSON.stringify({ method: config.method, provider: config.provider,
      sdkVersion: config.sdkVersion, publicParameters: parameters });
  };
  const digest = async value => {
    const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
    return Array.from(new Uint8Array(bytes), item => item.toString(16).padStart(2, '0')).join('');
  };
  const bounded = (operation, milliseconds = 15000) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), milliseconds);
    Promise.resolve().then(operation).then(value => { clearTimeout(timer); resolve(value); },
      error => { clearTimeout(timer); reject(error); });
  });
  const fail = code => {
    if (failed) return;
    failed = true; initialized = false;
    container.replaceChildren();
    container.textContent = 'Payment provider unavailable.';
    send({ protocol: PROTOCOL, channel: CHANNEL, type: 'ERROR', code });
  };
  const sdk = globalThis.ElmPayIsolatedProviderSdk;
  if (!sdk || Object.getPrototypeOf(sdk) !== Object.prototype
      || sdk.integrationType !== CONTRACT || typeof sdk.initialize !== 'function'
      || typeof sdk.tokenize !== 'function' || typeof sdk.handleAction !== 'function') {
    fail('SDK_CONTRACT_UNAVAILABLE');
    return;
  }
  send({ protocol: PROTOCOL, channel: CHANNEL, type: 'BOOTED' });
  addEventListener('message', async event => {
    if (failed || event.source !== parent || activeRequest) return;
    const message = event.data;
    if (!message || message.protocol !== PROTOCOL || message.channel !== CHANNEL) return;
    if (message.type === 'INIT') {
      if (initialized || !exactKeys(message, ['protocol', 'channel', 'type', 'configuration'])
          || !exactKeys(message.configuration, ['method', 'provider', 'sdkVersion', 'publicParameters'])
          || !message.configuration.publicParameters
          || Object.getPrototypeOf(message.configuration.publicParameters) !== Object.prototype) {
        fail('INVALID_INITIALIZATION'); return;
      }
      activeRequest = true;
      try {
        if (await digest(canonical(message.configuration)) !== EXPECTED_DIGEST) {
          throw new Error('configuration digest mismatch');
        }
        await bounded(() => sdk.initialize(Object.freeze(message.configuration), container));
        initialized = true;
        send({ protocol: PROTOCOL, channel: CHANNEL, type: 'READY' });
      } catch { fail('INITIALIZATION_FAILED'); }
      finally { activeRequest = false; }
      return;
    }
    if (message.type !== 'CALL' || !initialized
        || !exactKeys(message, ['protocol', 'channel', 'type', 'requestId', 'operation', 'payload'])
        || !/^[A-Za-z0-9_-]{20,128}$/.test(message.requestId)
        || !['tokenize', 'handleAction'].includes(message.operation)) {
      fail('INVALID_CALL'); return;
    }
    activeRequest = true;
    try {
      const value = await bounded(() => sdk[message.operation](Object.freeze(message.payload)));
      send({ protocol: PROTOCOL, channel: CHANNEL, type: 'RESULT', requestId: message.requestId,
        value: message.operation === 'handleAction' ? null : value });
    } catch {
      send({ protocol: PROTOCOL, channel: CHANNEL, type: 'CALL_ERROR', requestId: message.requestId,
        code: 'PROVIDER_OPERATION_FAILED' });
    } finally { activeRequest = false; }
  });
})();`;
}

export class ProviderSdkPolicy {
  constructor({ manifestPath = null, manifest = null, ticketKey, now = () => new Date() }) {
    if ((manifestPath === null) === (manifest === null) || typeof now !== 'function') {
      throw new Error('exactly one provider SDK manifest source is required');
    }
    let value = manifest;
    if (manifestPath !== null) {
      try { value = JSON.parse(readFileSync(manifestPath, 'utf8')); }
      catch { throw new Error('provider SDK allowlist is unavailable'); }
    }
    this.now = now;
    this.policy = parseManifest(value, now());
    this.ticketKey = normalizeTicketKey(ticketKey);
  }

  get manifestVersion() { return this.policy.manifestVersion; }

  get enabledProviderCount() {
    return this.policy.entries.filter(entry => entry.enabled).length;
  }

  authorizeConfiguration({ checkoutSessionId, method, channel, upstreamConfiguration }) {
    if (!checkoutSessionPattern.test(checkoutSessionId ?? '')
        || !methodPattern.test(method ?? '') || !channelPattern.test(channel ?? '')) {
      throw new Error('provider SDK request is invalid');
    }
    const entry = this.policy.methods.get(method);
    if (!entry || !entry.enabled) throw new Error('provider SDK method is not allowlisted');
    const configuration = validatePublicConfiguration(entry, upstreamConfiguration);
    const issuedAt = this.now().getTime();
    const expiresAt = issuedAt + ticketLifetimeMilliseconds;
    const payload = {
      version: 1,
      policyVersion: this.policy.manifestVersion,
      checkoutSessionId,
      method,
      channel,
      configurationDigest: sha256(canonicalConfiguration(configuration)),
      issuedAt,
      expiresAt,
    };
    const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const signature = createHmac('sha256', this.ticketKey).update(encoded, 'ascii').digest('base64url');
    const ticket = `${encoded}.${signature}`;
    return Object.freeze({
      schemaVersion: 1,
      policyVersion: this.policy.manifestVersion,
      method,
      provider: entry.id,
      sdkVersion: entry.sdkVersion,
      scriptUrl: entry.scriptUrl,
      integrity: entry.integrity,
      publicParameters: configuration.publicParameters,
      framePath: `/security/provider-sdk-frame?ticket=${encodeURIComponent(ticket)}`,
      expiresAt: new Date(expiresAt).toISOString(),
    });
  }

  renderFrame(ticket) {
    const payload = this.verifyTicket(ticket);
    const entry = this.policy.methods.get(payload.method);
    if (!entry || !entry.enabled) throw new Error('provider SDK method is no longer allowlisted');
    const nonce = randomBytes(18).toString('base64url');
    const program = frameProgram({
      channel: payload.channel,
      configurationDigest: payload.configurationDigest,
      adapterContract: entry.adapterContract,
    });
    const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Payment provider</title></head>
<body><main id="provider-sdk-container" aria-live="polite"></main>
<script src="${escapeAttribute(entry.scriptUrl)}" integrity="${entry.integrity}" crossorigin="anonymous" nonce="${nonce}"></script>
<script nonce="${nonce}">${program}</script></body></html>`;
    return Object.freeze({
      bytes: Buffer.from(html, 'utf8'),
      nonce,
      scriptUrl: entry.scriptUrl,
      connectOrigins: entry.connectOrigins,
      frameOrigins: entry.frameOrigins,
    });
  }

  verifyTicket(ticket) {
    if (typeof ticket !== 'string' || ticket.length < 80 || ticket.length > 2048
        || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(ticket)) {
      throw new Error('provider frame ticket is invalid');
    }
    const separator = ticket.indexOf('.');
    const encoded = ticket.slice(0, separator); const provided = ticket.slice(separator + 1);
    const expected = createHmac('sha256', this.ticketKey).update(encoded, 'ascii').digest();
    let supplied;
    try { supplied = Buffer.from(provided, 'base64url'); } catch { throw new Error('provider frame ticket is invalid'); }
    // Base64url decoders ignore non-significant trailing bits.  Re-encoding makes
    // the signature representation canonical, so changing the final character can
    // never alias the original HMAC bytes.
    if (supplied.toString('base64url') !== provided
        || supplied.byteLength !== expected.byteLength || !timingSafeEqual(supplied, expected)) {
      throw new Error('provider frame ticket signature is invalid');
    }
    let payload;
    try { payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); }
    catch { throw new Error('provider frame ticket payload is invalid'); }
    if (!exactKeys(payload, ['version', 'policyVersion', 'checkoutSessionId', 'method', 'channel', 'configurationDigest',
      'issuedAt', 'expiresAt']) || payload.version !== 1
        || payload.policyVersion !== this.policy.manifestVersion
        || !checkoutSessionPattern.test(payload.checkoutSessionId ?? '')
        || !methodPattern.test(payload.method ?? '') || !channelPattern.test(payload.channel ?? '')
        || !/^[0-9a-f]{64}$/.test(payload.configurationDigest ?? '')
        || !Number.isSafeInteger(payload.issuedAt) || !Number.isSafeInteger(payload.expiresAt)
        || payload.expiresAt - payload.issuedAt !== ticketLifetimeMilliseconds
        || this.now().getTime() < payload.issuedAt - 5_000
        || this.now().getTime() >= payload.expiresAt) {
      throw new Error('provider frame ticket is invalid or expired');
    }
    return Object.freeze(payload);
  }
}
