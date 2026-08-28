const referencePattern = /^(psp|wallet|mandate):\/\/[^\s]{1,500}$/;
const providerMethods = new Set([
  'card', 'stripe_card', 'paypal', 'apple_pay', 'wechat_jsapi', 'wechat_h5',
  'wechat_app', 'alipay_web', 'alipay_wap', 'alipay_app',
]);

/**
 * First-party boundary around official PSP/wallet SDKs. Adapters execute in the
 * browser and must exchange wallet payloads directly for opaque provider
 * references; this module never accepts PAN/CVV or a raw Apple Pay token.
 */
export class OfficialProviderHandlers {
  constructor({ adapters, allowedRedirectOrigins = [] }) {
    if (!adapters || Object.getPrototypeOf(adapters) !== Object.prototype) {
      throw new Error('official provider adapters are required');
    }
    this.adapters = new Map();
    for (const [method, adapter] of Object.entries(adapters)) {
      if (!providerMethods.has(method) || !adapter
        || adapter.integrationType !== 'official-provider-sdk'
        || typeof adapter.tokenize !== 'function'
        || typeof adapter.handleAction !== 'function') {
        throw new Error('provider adapter is not an official SDK boundary');
      }
      this.adapters.set(method, Object.freeze(adapter));
    }
    if (this.adapters.size === 0) throw new Error('at least one official provider adapter is required');
    this.allowedRedirectOrigins = new Set(allowedRedirectOrigins.map(value => {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/') {
        throw new Error('redirect allowlist entries must be credential-free HTTPS origins');
      }
      return url.origin;
    }));
  }

  async tokenize(context) {
    exactContext(context, ['method', 'checkoutSessionId']);
    const adapter = this.adapters.get(context.method);
    if (!adapter) throw new Error('official tokenizer is unavailable for this method');
    const value = await adapter.tokenize(Object.freeze({ ...context }));
    return validateReference(value);
  }

  async handle(action, context) {
    exactContext(context, ['checkoutSessionId']);
    if (!action || Object.getPrototypeOf(action) !== Object.prototype) {
      throw new Error('provider action is invalid');
    }
    const keys = Object.keys(action);
    if (keys.length < 1 || keys.length > 32
      || keys.some(key => !/^[A-Za-z0-9._-]{1,64}$/.test(key)
        || typeof action[key] !== 'string' || action[key].length > 4096
        || containsPan(action[key]))) throw new Error('provider action is invalid');
    if (action.action === 'redirect') {
      const target = new URL(action.redirect_url);
      if (target.protocol !== 'https:' || target.username || target.password
        || !this.allowedRedirectOrigins.has(target.origin)) {
        throw new Error('provider redirect is not allowlisted');
      }
      const adapter = this.adapters.get(action.method);
      if (!adapter) throw new Error('official action handler is unavailable');
      return adapter.handleAction(Object.freeze({ ...action }), Object.freeze({ ...context }));
    }
    const adapter = this.adapters.get(action.method);
    if (!adapter) throw new Error('official action handler is unavailable');
    return adapter.handleAction(Object.freeze({ ...action }), Object.freeze({ ...context }));
  }

  install(target = globalThis) {
    Object.defineProperty(target, 'ElmPayPaymentMethodTokenizer', {
      value: Object.freeze({ tokenize: this.tokenize.bind(this) }), configurable: false,
      enumerable: false, writable: false,
    });
    Object.defineProperty(target, 'ElmPayNextActionHandler', {
      value: Object.freeze({ handle: this.handle.bind(this) }), configurable: false,
      enumerable: false, writable: false,
    });
  }
}

export function stripeOfficialAdapter(stripe, elements) {
  if (!stripe || typeof stripe.createPaymentMethod !== 'function' || !elements
    || typeof elements.getElement !== 'function') throw new Error('Stripe.js is unavailable');
  return Object.freeze({
    integrationType: 'official-provider-sdk',
    async tokenize() {
      const card = elements.getElement('card');
      if (!card) throw new Error('Stripe hosted element is unavailable');
      const result = await stripe.createPaymentMethod({ type: 'card', card });
      if (result?.error || !/^pm_[A-Za-z0-9_]{3,200}$/.test(result?.paymentMethod?.id ?? '')) {
        throw new Error('Stripe tokenization failed');
      }
      return { paymentMethodReference: `psp://stripe/${result.paymentMethod.id}`,
        fingerprint: result.paymentMethod.card?.fingerprint };
    },
    async handleAction(action) {
      if (action.action !== 'stripe_next_action' || typeof stripe.handleNextAction !== 'function') {
        throw new Error('unsupported Stripe action');
      }
      const result = await stripe.handleNextAction({ clientSecret: action.client_secret });
      if (result?.error) throw new Error('Stripe authorization was not completed');
    },
  });
}

function validateReference(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error('official tokenizer result is invalid');
  }
  const allowed = new Set(['paymentMethodReference', 'fingerprint', 'providerParameters']);
  if (Object.keys(value).some(key => !allowed.has(key))
    || typeof value.paymentMethodReference !== 'string'
    || !referencePattern.test(value.paymentMethodReference)
    || containsPan(value.paymentMethodReference)) throw new Error('opaque provider reference is required');
  if (value.fingerprint !== undefined && (typeof value.fingerprint !== 'string'
    || !/^[A-Za-z0-9._:-]{1,128}$/.test(value.fingerprint)
    || containsPan(value.fingerprint))) throw new Error('provider fingerprint is invalid');
  if (value.providerParameters !== undefined) {
    if (!value.providerParameters || Object.getPrototypeOf(value.providerParameters) !== Object.prototype
      || Object.keys(value.providerParameters).length > 32
      || Object.entries(value.providerParameters).some(([key, parameter]) =>
        !/^[A-Za-z0-9._-]{1,64}$/.test(key) || typeof parameter !== 'string'
        || parameter.length > 1024 || containsPan(parameter))) {
      throw new Error('provider parameters are invalid');
    }
  }
  return Object.freeze({ ...value,
    ...(value.providerParameters === undefined ? {}
      : { providerParameters: Object.freeze({ ...value.providerParameters }) }) });
}

function exactContext(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')
    || Object.values(value).some(item => typeof item !== 'string' || item.length < 1
      || item.length > 256)) throw new Error('provider SDK context is invalid');
}

function containsPan(value) {
  for (const match of value.matchAll(/(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g)) {
    const digits = match[0].replaceAll(' ', '').replaceAll('-', '');
    let sum = 0; let doubled = false;
    for (let index = digits.length - 1; index >= 0; index -= 1) {
      let digit = Number(digits[index]);
      if (doubled && (digit *= 2) > 9) digit -= 9;
      sum += digit; doubled = !doubled;
    }
    if (sum % 10 === 0) return true;
  }
  return false;
}

Object.defineProperty(globalThis, 'ElmPayOfficialProviderHandlersFactory', {
  value: Object.freeze({
    install(configuration) { new OfficialProviderHandlers(configuration).install(globalThis); },
    stripe: stripeOfficialAdapter,
  }),
  configurable: false, enumerable: false, writable: false,
});

if (globalThis.ElmPayOfficialProviderConfiguration !== undefined) {
  new OfficialProviderHandlers(globalThis.ElmPayOfficialProviderConfiguration).install(globalThis);
}
