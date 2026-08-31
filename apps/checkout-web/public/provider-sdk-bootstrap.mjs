import {
  OfficialProviderHandlers, SUPPORTED_PROVIDER_METHODS,
} from './provider-handlers.mjs';

const protocol = 'elmpay-provider-sdk-v1';
const sessionPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const tokenPattern = /^[A-Za-z0-9_-]{48}\.[A-Za-z0-9_-]{43}$/;
const methodPattern = /^[a-z0-9._-]{1,64}$/;
const identifierPattern = /^[A-Za-z0-9._:-]{1,128}$/;
const sriPattern = /^sha384-[A-Za-z0-9+/]{64}$/;
const requestPattern = /^[A-Za-z0-9_-]{20,128}$/;

function exactKeys(value, expected) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

function sameOriginBase(value, location) {
  const page = new URL(location.href);
  const base = new URL(value, page.origin);
  if (base.origin !== page.origin || base.username || base.password || base.search || base.hash
      || base.pathname !== '/api/checkout/sessions/') {
    throw new Error('provider SDK configuration must use the fixed same-origin endpoint');
  }
  return base;
}

function validatePublicParameters(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).length > 32) {
    throw new Error('provider SDK public configuration is invalid');
  }
  const result = {};
  for (const [key, parameter] of Object.entries(value)) {
    if (!/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(key)
        || /(?:secret|private|password|credential|token|pan|cvv|cvc|authorization)/i.test(key)
        || typeof parameter !== 'string' || parameter.length < 1 || parameter.length > 512
        || /[^\x20-\x7e]|[\r\n<>]/.test(parameter)) {
      throw new Error('provider SDK public configuration is invalid');
    }
    result[key] = parameter;
  }
  return Object.freeze(result);
}

function validateConfiguration(value, { method, origin, now }) {
  const keys = ['schemaVersion', 'policyVersion', 'method', 'provider', 'sdkVersion', 'scriptUrl',
    'integrity', 'publicParameters', 'framePath', 'expiresAt'];
  if (!exactKeys(value, keys) || value.schemaVersion !== 1 || value.method !== method
      || !identifierPattern.test(value.policyVersion ?? '')
      || !identifierPattern.test(value.provider ?? '') || !identifierPattern.test(value.sdkVersion ?? '')
      || typeof value.scriptUrl !== 'string' || value.scriptUrl.length > 2048
      || typeof value.framePath !== 'string' || value.framePath.length > 2048
      || !sriPattern.test(value.integrity ?? '') || !Number.isFinite(Date.parse(value.expiresAt))) {
    throw new Error('provider SDK server configuration is invalid');
  }
  const expiresAt = Date.parse(value.expiresAt);
  if (expiresAt <= now() || expiresAt > now() + 60_000) {
    throw new Error('provider SDK server configuration is expired');
  }
  const script = new URL(value.scriptUrl);
  if (script.protocol !== 'https:' || script.username || script.password || script.hash
      || script.href !== value.scriptUrl || /[\s'";\\]/.test(value.scriptUrl)) {
    throw new Error('provider SDK server script metadata is invalid');
  }
  const frame = new URL(value.framePath, origin);
  if (frame.origin !== origin || frame.username || frame.password || frame.hash
      || frame.pathname !== '/security/provider-sdk-frame' || frame.searchParams.size !== 1
      || frame.searchParams.getAll('ticket').length !== 1 || !frame.searchParams.get('ticket')) {
    throw new Error('provider SDK frame URL is not same-origin');
  }
  return Object.freeze({
    schemaVersion: 1,
    policyVersion: value.policyVersion,
    method,
    provider: value.provider,
    sdkVersion: value.sdkVersion,
    scriptUrl: script.href,
    integrity: value.integrity,
    publicParameters: validatePublicParameters(value.publicParameters),
    framePath: `${frame.pathname}${frame.search}`,
    expiresAt: value.expiresAt,
  });
}

function createRequestId(cryptoImpl) {
  const value = cryptoImpl.randomUUID().replaceAll('-', '');
  if (!requestPattern.test(value)) throw new Error('secure provider SDK request ID is unavailable');
  return value;
}

class IsolatedFrameSession {
  constructor({ frame, channel, configuration, messageTarget, setTimer, clearTimer,
    handshakeTimeoutMilliseconds, operationTimeoutMilliseconds, container }) {
    this.frame = frame;
    this.channel = channel;
    this.configuration = configuration;
    this.messageTarget = messageTarget;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.operationTimeoutMilliseconds = operationTimeoutMilliseconds;
    this.container = container;
    this.phase = 'BOOTING';
    this.pending = new Map();
    this.onMessage = this.onMessage.bind(this);
    this.onFrameError = () => this.fail(new Error('provider SDK frame failed to load'));
    this.messageTarget.addEventListener('message', this.onMessage);
    this.frame.addEventListener?.('error', this.onFrameError, { once: true });
    this.ready = new Promise((resolve, reject) => {
      this.resolveReady = resolve; this.rejectReady = reject;
      this.handshakeTimer = this.setTimer(() => {
        this.fail(new Error('provider SDK frame initialization timed out'));
      }, handshakeTimeoutMilliseconds);
    });
  }

  mount() {
    this.container.hidden = false;
    this.container.replaceChildren(this.frame);
  }

  onMessage(event) {
    if (event.source !== this.frame.contentWindow || event.origin !== 'null') return;
    const message = event.data;
    if (!message || message.protocol !== protocol || message.channel !== this.channel) return;
    if (message.type === 'BOOTED') {
      if (this.phase !== 'BOOTING'
          || !exactKeys(message, ['protocol', 'channel', 'type'])) {
        this.fail(new Error('provider SDK frame protocol violation')); return;
      }
      this.phase = 'INITIALIZING';
      this.frame.contentWindow.postMessage({
        protocol, channel: this.channel, type: 'INIT',
        configuration: Object.freeze({
          method: this.configuration.method,
          provider: this.configuration.provider,
          sdkVersion: this.configuration.sdkVersion,
          publicParameters: this.configuration.publicParameters,
        }),
      }, '*');
      return;
    }
    if (message.type === 'READY') {
      if (this.phase !== 'INITIALIZING'
          || !exactKeys(message, ['protocol', 'channel', 'type'])) {
        this.fail(new Error('provider SDK frame protocol violation')); return;
      }
      this.phase = 'READY'; this.clearTimer(this.handshakeTimer); this.resolveReady(this);
      return;
    }
    if (message.type === 'ERROR') {
      if (!exactKeys(message, ['protocol', 'channel', 'type', 'code'])
          || !identifierPattern.test(message.code ?? '')) {
        this.fail(new Error('provider SDK frame protocol violation')); return;
      }
      this.fail(new Error(`provider SDK frame rejected initialization (${message.code})`));
      return;
    }
    if (message.type === 'RESULT' || message.type === 'CALL_ERROR') {
      const expected = message.type === 'RESULT'
        ? ['protocol', 'channel', 'type', 'requestId', 'value']
        : ['protocol', 'channel', 'type', 'requestId', 'code'];
      if (this.phase !== 'READY' || !exactKeys(message, expected)
          || !requestPattern.test(message.requestId ?? '') || !this.pending.has(message.requestId)
          || (message.type === 'CALL_ERROR' && !identifierPattern.test(message.code ?? ''))) {
        this.fail(new Error('provider SDK frame protocol violation')); return;
      }
      const pending = this.pending.get(message.requestId); this.pending.delete(message.requestId);
      this.clearTimer(pending.timer);
      if (message.type === 'RESULT') pending.resolve(message.value);
      else {
        pending.reject(new Error(`provider SDK operation failed (${message.code})`));
        this.dispose(new Error('provider SDK frame closed after provider error'));
      }
      return;
    }
    this.fail(new Error('provider SDK frame protocol violation'));
  }

  async call(operation, payload, cryptoImpl) {
    await this.ready;
    if (this.phase !== 'READY' || !['tokenize', 'handleAction'].includes(operation)) {
      throw new Error('provider SDK frame is unavailable');
    }
    const requestId = createRequestId(cryptoImpl);
    return new Promise((resolve, reject) => {
      const timer = this.setTimer(() => {
        this.pending.delete(requestId);
        reject(new Error('provider SDK operation timed out'));
        this.dispose(new Error('provider SDK frame closed after timeout'));
      }, this.operationTimeoutMilliseconds);
      this.pending.set(requestId, { resolve, reject, timer });
      try {
        this.frame.contentWindow.postMessage({
          protocol, channel: this.channel, type: 'CALL', requestId, operation, payload,
        }, '*');
      } catch {
        this.pending.delete(requestId); this.clearTimer(timer);
        reject(new Error('provider SDK operation could not be sent'));
        this.dispose(new Error('provider SDK frame closed after messaging failure'));
      }
    });
  }

  fail(error) {
    if (this.phase === 'CLOSED') return;
    if (this.phase !== 'READY') this.rejectReady(error);
    this.dispose(error);
  }

  dispose(error = new Error('provider SDK frame closed')) {
    if (this.phase === 'CLOSED') return;
    this.phase = 'CLOSED'; this.clearTimer(this.handshakeTimer);
    this.messageTarget.removeEventListener('message', this.onMessage);
    this.frame.removeEventListener?.('error', this.onFrameError);
    for (const pending of this.pending.values()) {
      this.clearTimer(pending.timer); pending.reject(error);
    }
    this.pending.clear(); this.frame.remove?.();
    if (this.container.replaceChildren && this.container.children?.length === 0) this.container.hidden = true;
  }
}

export class ProviderSdkBootstrap {
  constructor({
    fetchImpl = globalThis.fetch,
    storage = globalThis.sessionStorage,
    location = globalThis.location,
    document = globalThis.document,
    cryptoImpl = globalThis.crypto,
    messageTarget = globalThis,
    configurationBase = '/api/checkout/sessions/',
    setTimer = globalThis.setTimeout.bind(globalThis),
    clearTimer = globalThis.clearTimeout.bind(globalThis),
    now = () => Date.now(),
    handshakeTimeoutMilliseconds = 10_000,
    operationTimeoutMilliseconds = 15_000,
  } = {}) {
    if (typeof fetchImpl !== 'function' || !storage || !document || !cryptoImpl
        || typeof cryptoImpl.randomUUID !== 'function'
        || typeof messageTarget?.addEventListener !== 'function'
        || typeof messageTarget?.removeEventListener !== 'function'
        || !Number.isInteger(handshakeTimeoutMilliseconds) || handshakeTimeoutMilliseconds < 100
        || handshakeTimeoutMilliseconds > 60_000
        || !Number.isInteger(operationTimeoutMilliseconds) || operationTimeoutMilliseconds < 100
        || operationTimeoutMilliseconds > 120_000) {
      throw new Error('provider SDK bootstrap dependencies are invalid');
    }
    const page = new URL(location.href);
    this.origin = page.origin;
    this.configurationBase = sameOriginBase(configurationBase, location);
    this.fetchImpl = fetchImpl; this.storage = storage; this.document = document;
    this.cryptoImpl = cryptoImpl; this.messageTarget = messageTarget;
    this.setTimer = setTimer; this.clearTimer = clearTimer; this.now = now;
    this.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds;
    this.operationTimeoutMilliseconds = operationTimeoutMilliseconds;
    this.sessions = new Map();
  }

  async prepare({ method, checkoutSessionId }) {
    if (!methodPattern.test(method ?? '') || !sessionPattern.test(checkoutSessionId ?? '')) {
      throw new Error('provider SDK context is invalid');
    }
    const key = `${checkoutSessionId}:${method}`;
    const existing = this.sessions.get(key);
    if (existing) return existing;
    const pending = this.createSession({ method, checkoutSessionId });
    this.sessions.set(key, pending);
    try { return await pending; }
    catch (error) { this.sessions.delete(key); throw error; }
  }

  async createSession({ method, checkoutSessionId }) {
    const accessToken = this.storage.getItem(`elmpay.checkout.token.${checkoutSessionId}`);
    if (!tokenPattern.test(accessToken ?? '')) throw new Error('checkout authorization is unavailable');
    const channel = createRequestId(this.cryptoImpl);
    const url = new URL(`${encodeURIComponent(checkoutSessionId)}/provider-sdk-config`,
      this.configurationBase);
    url.searchParams.set('method', method); url.searchParams.set('channel', channel);
    const response = await this.fetchImpl(`${url.pathname}${url.search}`, {
      method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      referrerPolicy: 'no-referrer',
      headers: { accept: 'application/json', authorization: `CheckoutSession ${accessToken}` },
    });
    if (!response.ok || !response.headers?.get?.('content-type')?.startsWith('application/json')) {
      throw new Error('provider SDK configuration is unavailable');
    }
    const configuration = validateConfiguration(await response.json(), {
      method, origin: this.origin, now: this.now,
    });
    const container = this.document.querySelector('#provider-sdk-container');
    if (!container || typeof container.replaceChildren !== 'function') {
      throw new Error('isolated provider SDK container is unavailable');
    }
    const frame = this.document.createElement('iframe');
    frame.setAttribute('sandbox', 'allow-scripts');
    frame.setAttribute('title', `Secure ${configuration.provider} payment provider`);
    frame.setAttribute('aria-label', 'Secure payment provider input');
    frame.setAttribute('allow', '');
    frame.setAttribute('credentialless', '');
    frame.referrerPolicy = 'no-referrer';
    frame.src = configuration.framePath;
    const session = new IsolatedFrameSession({
      frame, channel, configuration, messageTarget: this.messageTarget,
      setTimer: this.setTimer, clearTimer: this.clearTimer,
      handshakeTimeoutMilliseconds: this.handshakeTimeoutMilliseconds,
      operationTimeoutMilliseconds: this.operationTimeoutMilliseconds,
      container,
    });
    session.mount();
    try { await session.ready; return session; }
    catch (error) { session.dispose(error); throw error; }
  }

  async tokenize(context) {
    const session = await this.prepare(context);
    return session.call('tokenize', Object.freeze({ ...context }), this.cryptoImpl);
  }

  async handleAction(method, action, context) {
    const session = await this.prepare({ method, checkoutSessionId: context.checkoutSessionId });
    await session.call('handleAction', Object.freeze({
      action: Object.freeze({ ...action }), context: Object.freeze({ ...context }),
    }), this.cryptoImpl);
  }

  close() {
    for (const session of this.sessions.values()) {
      void Promise.resolve(session).then(value => value.dispose()).catch(() => {});
    }
    this.sessions.clear();
  }
}

export function installIsolatedProviderHandlers({ target = globalThis, runtime = null } = {}) {
  const bootstrap = runtime ?? new ProviderSdkBootstrap();
  const adapters = {};
  for (const method of SUPPORTED_PROVIDER_METHODS) {
    adapters[method] = Object.freeze({
      integrationType: 'official-provider-sdk',
      prepare: context => bootstrap.prepare(context),
      tokenize: context => bootstrap.tokenize(context),
      handleAction: (action, context) => bootstrap.handleAction(method, action, context),
    });
  }
  new OfficialProviderHandlers({ adapters, allowedRedirectOrigins: [] }).install(target);
  return bootstrap;
}

if (typeof window !== 'undefined' && !globalThis.__ELMPAY_TEST__) {
  try {
    const runtime = installIsolatedProviderHandlers();
    Object.defineProperty(globalThis, '__ELMPAY_PROVIDER_SDK_READY__', {
      value: Promise.resolve(Object.freeze({ allowed: true, runtime })), configurable: false,
      enumerable: false, writable: false,
    });
  } catch {
    Object.defineProperty(globalThis, '__ELMPAY_PROVIDER_SDK_READY__', {
      value: Promise.resolve(Object.freeze({ allowed: false })), configurable: false,
      enumerable: false, writable: false,
    });
  }
}
