const terminal = new Set(['SUCCEEDED', 'FAILED', 'EXPIRED', 'CANCELED']);
const sessionPattern = /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i;
const tokenPattern = /^[A-Za-z0-9_-]{48}\.[A-Za-z0-9_-]{43}$/;

export class CheckoutController {
  constructor({ api = fetch, storage = sessionStorage, location = window.location,
    history = window.history, document = window.document } = {}) {
    this.api = api;
    this.storage = storage;
    this.location = location;
    this.history = history;
    this.document = document;
    this.sessionId = null;
    this.accessToken = null;
    this.timer = null;
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
      else this.fail('Choose an available payment method.');
    });
    await this.refresh();
  }

  async confirm(methodId) {
    if (!/^[a-z0-9._-]{1,64}$/i.test(methodId)) return this.fail('The selected payment method is invalid.');
    const storageKey = `elmpay.checkout.idempotency.${this.sessionId}`;
    const idempotencyKey = this.storage.getItem(storageKey) ?? crypto.randomUUID();
    this.storage.setItem(storageKey, idempotencyKey);
    this.document.querySelector('#continue').disabled = true;
    this.document.querySelector('#status').textContent = 'Requesting payment securely…';
    try {
      const response = await this.api(`/api/checkout/sessions/${encodeURIComponent(this.sessionId)}/confirm`, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: { accept: 'application/json', authorization: `CheckoutSession ${this.accessToken}`,
          'content-type': 'application/json', 'idempotency-key': idempotencyKey },
        body: JSON.stringify({ method: methodId }),
      });
      if (!response.ok) throw new Error(`confirmation rejected (${response.status})`);
      this.document.querySelector('#status').textContent = 'Payment is pending server verification.';
      await this.refresh();
    } catch {
      this.fail('Payment could not be confirmed. Its outcome remains unverified.');
    }
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
    const main = this.document.querySelector('#checkout');
    main.setAttribute('aria-busy', 'false');
    this.document.querySelector('#amount').textContent = view.displayAmount;
    this.document.documentElement.lang = view.locale;
    this.document.documentElement.dir = view.direction === 'rtl' ? 'rtl' : 'ltr';
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
    return ({ OPEN: 'Ready for payment.', PENDING: 'Payment is still being verified.', SUCCEEDED: 'Payment verified by the server.',
      FAILED: 'Payment was not completed.', EXPIRED: 'This checkout session expired.', CANCELED: 'Payment was canceled.' })[status]
      ?? 'Payment status is unknown and will not be treated as successful.';
  }

  fail(message) {
    this.document.querySelector('#checkout').setAttribute('aria-busy', 'false');
    const error = this.document.querySelector('#error');
    error.textContent = message; error.hidden = false;
    this.document.querySelector('#status').textContent = 'Payment status not verified.';
  }
}

if (typeof window !== 'undefined' && !globalThis.__ELMPAY_TEST__) new CheckoutController().start();
