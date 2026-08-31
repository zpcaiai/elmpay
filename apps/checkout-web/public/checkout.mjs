const terminal = new Set(['SUCCEEDED', 'FAILED', 'EXPIRED', 'CANCELED']);
const sessionPattern = /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i;
const tokenPattern = /^[A-Za-z0-9_-]{48}\.[A-Za-z0-9_-]{43}$/;
const referencePattern = /^(psp|wallet|mandate):\/\/[^\s]{1,500}$/;
const deniedFields = new Set(['pan', 'card_number', 'cardnumber', 'cvv', 'cvc', 'cid',
  'track1', 'track2', 'pin', 'private_key', 'privatekey', 'api_key', 'apikey',
  'authorization', 'apple_pay_token', 'paymentdata']);

export class CheckoutController {
  constructor({ api = fetch, storage = sessionStorage, location = window.location,
    history = window.history, document = window.document, tokenizer = null,
    providerPrepare = null, nextActionHandler = null } = {}) {
    this.api = api;
    this.storage = storage;
    this.location = location;
    this.history = history;
    this.document = document;
    this.tokenizer = tokenizer ?? globalThis.ElmPayPaymentMethodTokenizer?.tokenize?.bind(
      globalThis.ElmPayPaymentMethodTokenizer) ?? null;
    this.providerPrepare = providerPrepare ?? globalThis.ElmPayPaymentMethodTokenizer?.prepare?.bind(
      globalThis.ElmPayPaymentMethodTokenizer) ?? null;
    this.nextActionHandler = nextActionHandler ?? globalThis.ElmPayNextActionHandler?.handle?.bind(
      globalThis.ElmPayNextActionHandler) ?? null;
    this.sessionId = null;
    this.accessToken = null;
    this.timer = null;
    this.messages = Object.freeze({});
  }

  async start() {
    const url = new URL(this.location.href);
    const fragment = new URLSearchParams(url.hash.slice(1));
    const requested = fragment.get('session');
    const requestedToken = fragment.get('token');
    const restored = this.storage.getItem('elmpay.checkout.session');
    this.sessionId = requested || restored;
    if (!sessionPattern.test(this.sessionId ?? '')) return this.fail('This checkout link is invalid.');
    const tokenKey = `elmpay.checkout.token.${this.sessionId}`;
    this.accessToken = requestedToken || this.storage.getItem(tokenKey);
    if (!tokenPattern.test(this.accessToken ?? '')) return this.fail('This checkout link is invalid or expired.');
    this.storage.setItem('elmpay.checkout.session', this.sessionId);
    this.storage.setItem(tokenKey, this.accessToken);
    if (url.hash) this.history?.replaceState?.(null, '', `${url.pathname}${url.search}`);
    this.document.querySelector('#continue').addEventListener?.('click', () => {
      const method = this.document.querySelector('input[name="method"]:checked')?.value;
      if (method) this.confirm(method);
      else this.fail(this.text('error.chooseMethod', 'Choose an available payment method.'));
    });
    this.document.querySelector('#methods').addEventListener?.('change', event => {
      const method = event?.target?.value;
      if (!/^[a-z0-9._-]{1,64}$/i.test(method ?? '') || typeof this.providerPrepare !== 'function') return;
      void this.providerPrepare({ method, checkoutSessionId: this.sessionId }).catch(() => {
        this.fail(this.text('error.providerUnavailable',
          'The selected payment provider could not be loaded securely.'));
      });
    });
    await this.refresh();
  }

  async confirm(methodId) {
    if (!/^[a-z0-9._-]{1,64}$/i.test(methodId)) {
      return this.fail(this.text('error.invalidMethod', 'The selected payment method is invalid.'));
    }
    const storageKey = `elmpay.checkout.idempotency.${this.sessionId}`;
    const idempotencyKey = this.storage.getItem(storageKey) ?? crypto.randomUUID();
    this.storage.setItem(storageKey, idempotencyKey);
    this.document.querySelector('#continue').disabled = true;
    this.document.querySelector('#status').textContent = this.text(
      'ui.requesting', 'Requesting payment securely…');
    try {
      if (typeof this.tokenizer !== 'function') throw new Error('tokenizer unavailable');
      const paymentMethod = this.normalizePaymentMethod(await this.tokenizer({
        method: methodId, checkoutSessionId: this.sessionId,
      }));
      const response = await this.api(`/api/checkout/sessions/${encodeURIComponent(this.sessionId)}/confirm`, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: { accept: 'application/json', authorization: `CheckoutSession ${this.accessToken}`,
          'content-type': 'application/json', 'idempotency-key': idempotencyKey },
        body: JSON.stringify({ method: methodId, ...paymentMethod }),
      });
      if (!response.ok) throw new Error(`confirmation rejected (${response.status})`);
      this.document.querySelector('#status').textContent = this.text(
        'ui.pendingConfirmation', 'Payment is pending server verification.');
      if (typeof response.json === 'function') {
        const confirmed = await response.json();
        await this.handleNextAction(confirmed?.nextAction);
      }
      await this.refresh();
    } catch {
      this.fail(this.text('error.confirm',
        'Payment could not be confirmed. Its outcome remains unverified.'));
    }
  }

  normalizePaymentMethod(value) {
    if (!value || Object.getPrototypeOf(value) !== Object.prototype) {
      throw new Error('invalid tokenizer result');
    }
    const allowed = new Set(['paymentMethodReference', 'fingerprint', 'providerParameters']);
    if (Object.keys(value).some(key => !allowed.has(key))) throw new Error('invalid tokenizer result');
    const reference = value.paymentMethodReference;
    if (typeof reference !== 'string' || !referencePattern.test(reference)
      || containsPan(reference)) throw new Error('invalid token reference');
    const result = { payment_method_reference: reference };
    if (value.fingerprint !== undefined) {
      if (typeof value.fingerprint !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(value.fingerprint)
        || containsPan(value.fingerprint)) throw new Error('invalid token fingerprint');
      result.fingerprint = value.fingerprint;
    }
    if (value.providerParameters !== undefined) {
      if (!value.providerParameters || Object.getPrototypeOf(value.providerParameters) !== Object.prototype
        || Object.keys(value.providerParameters).length > 32) throw new Error('invalid provider parameters');
      result.provider_parameters = {};
      for (const [key, parameter] of Object.entries(value.providerParameters)) {
        const normalizedKey = key.toLowerCase().replaceAll('-', '_');
        if (!/^[A-Za-z0-9._-]{1,64}$/.test(key) || deniedFields.has(normalizedKey)
          || typeof parameter !== 'string' || parameter.length > 1024 || containsPan(parameter)) {
          throw new Error('invalid provider parameters');
        }
        result.provider_parameters[key] = parameter;
      }
    }
    return result;
  }

  async handleNextAction(action) {
    if (action === undefined || action === null) return;
    if (Object.getPrototypeOf(action) !== Object.prototype || Object.keys(action).length > 32
      || Object.entries(action).some(([key, value]) => !/^[A-Za-z0-9._-]{1,64}$/.test(key)
        || typeof value !== 'string' || value.length > 4096 || containsPan(value))) {
      throw new Error('invalid next action');
    }
    if (Object.keys(action).length === 0) return;
    if (typeof this.nextActionHandler !== 'function') {
      this.document.querySelector('#status').textContent =
        this.text('ui.nextActionRequired',
          'Additional payment authorization is required; no result has been assumed.');
      return;
    }
    await this.nextActionHandler(Object.freeze({ ...action }), {
      checkoutSessionId: this.sessionId,
    });
  }

  async refresh() {
    try {
      const response = await this.api(`/api/checkout/sessions/${encodeURIComponent(this.sessionId)}`, {
        headers: { accept: 'application/json', authorization: `CheckoutSession ${this.accessToken}` },
        credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer',
      });
      if (!response.ok) throw new Error(`checkout unavailable (${response.status})`);
      const view = await response.json();
      this.render(view);
      if (!terminal.has(view.status)) this.timer = setTimeout(() => this.refresh(), 1500);
    } catch {
      this.fail('We could not verify payment status. No payment result has been assumed.');
    }
  }

  render(view) {
    if (view.messages !== undefined) {
      if (!view.messages || Object.getPrototypeOf(view.messages) !== Object.prototype
        || Object.keys(view.messages).length > 64
        || Object.entries(view.messages).some(([key, value]) => !/^[A-Za-z0-9._-]{1,64}$/.test(key)
          || typeof value !== 'string' || value.length < 1 || value.length > 512)) {
        throw new Error('checkout localization catalog is invalid');
      }
      this.messages = Object.freeze({ ...view.messages });
    }
    const main = this.document.querySelector('#checkout');
    main.setAttribute('aria-busy', 'false');
    this.document.querySelector('#amount').textContent = view.displayAmount;
    this.document.documentElement.lang = view.locale;
    this.document.documentElement.dir = view.direction === 'rtl' ? 'rtl' : 'ltr';
    const pageTitle = this.document.querySelector('#page-title');
    if (pageTitle) pageTitle.textContent = this.text('ui.pageTitle', 'Secure checkout');
    const legend = this.document.querySelector('#method-legend');
    if (legend) legend.textContent = this.text('ui.methodLegend', 'Choose a payment method');
    const continueAction = this.document.querySelector('#continue');
    continueAction.textContent = this.text('ui.continueAction', 'Continue securely');
    const fieldset = this.document.querySelector('#methods');
    fieldset.replaceChildren(...view.methods.map(method => {
      const label = this.document.createElement('label');
      const input = this.document.createElement('input');
      input.type = 'radio'; input.name = 'method'; input.value = method.id; input.disabled = !method.eligible;
      label.append(input, this.document.createTextNode(method.label));
      if (!method.eligible && method.reason) label.append(this.document.createTextNode(` — ${method.reason}`));
      return label;
    }));
    fieldset.disabled = view.status !== 'OPEN';
    this.document.querySelector('#continue').disabled = view.status !== 'OPEN';
    this.document.querySelector('#status').textContent = this.statusText(view.status);
    if (terminal.has(view.status)) {
      this.storage.removeItem('elmpay.checkout.session');
      this.storage.removeItem(`elmpay.checkout.token.${this.sessionId}`);
    }
  }

  statusText(status) {
    const fallback = ({ OPEN: 'Ready for payment.', PENDING: 'Payment is still being verified.',
      SUCCEEDED: 'Payment verified by the server.', FAILED: 'Payment was not completed.',
      EXPIRED: 'This checkout session expired.', CANCELED: 'Payment was canceled.' })[status];
    if (['OPEN', 'PENDING', 'SUCCEEDED', 'FAILED', 'EXPIRED', 'CANCELED'].includes(status)
      && this.messages['status.current']) return this.messages['status.current'];
    if (fallback) return fallback;
    return this.text('error.unknown',
      'Payment status is unknown and will not be treated as successful.');
  }

  fail(message) {
    this.document.querySelector('#checkout').setAttribute('aria-busy', 'false');
    const error = this.document.querySelector('#error');
    error.textContent = message; error.hidden = false;
    this.document.querySelector('#status').textContent = this.text(
      'error.notVerified', 'Payment status not verified.');
  }

  text(key, fallback) {
    const value = this.messages[key];
    return typeof value === 'string' && value.length > 0 ? value : fallback;
  }
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

if (typeof window !== 'undefined' && !globalThis.__ELMPAY_TEST__) {
  const integrityReady = globalThis.__ELMPAY_INTEGRITY_READY__;
  if (integrityReady && typeof integrityReady.then === 'function') {
    void integrityReady.then(result => {
      if (result?.allowed === true) return new CheckoutController().start();
      return undefined;
    });
  }
}
