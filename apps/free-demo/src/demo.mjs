const allowed = new Set(['succeeded', 'declined', 'unknown']);

// Native browser fetch requires its Window receiver when called as a method.
export function demoApi(...args) { return globalThis.fetch(...args); }

export function demoReference(sessionId, scenario) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(sessionId)
      || !allowed.has(scenario)) throw new Error('invalid demo reference');
  return { paymentMethodReference: `psp://elmpay-demo/${sessionId}`,
    providerParameters: { simulation: scenario } };
}

async function initialize() {
  const url = new URL(location.href);
  const session = new URLSearchParams(url.hash.slice(1)).get('session')
    ?? sessionStorage.getItem('elmpay.checkout.session');
  if (location.pathname === '/checkout' && session) {
    document.querySelector('#demo-start').hidden = true;
    document.querySelector('#checkout').hidden = false;
    const { CheckoutController } = await import('/checkout.mjs');
    const controller = new CheckoutController({
      api: demoApi,
      tokenizer: async ({ checkoutSessionId }) => demoReference(checkoutSessionId,
        sessionStorage.getItem(`elmpay.demo.scenario.${checkoutSessionId}`)),
    });
    const render = controller.render.bind(controller);
    controller.render = view => {
      const selected = document.querySelector('input[name="method"]:checked')?.value;
      render(view);
      if (view.status === 'OPEN' && view.methods.some(method => method.id === selected && method.eligible)) {
        for (const input of document.querySelectorAll('input[name="method"]')) {
          if (input.value === selected && !input.disabled) input.checked = true;
        }
      }
      document.querySelector('#checkout').dataset.state = view.status;
      document.querySelector('#status').textContent = `模拟状态 · ${controller.statusText(view.status)}`;
      document.querySelector('#continue').textContent = '确认模拟支付（不扣款）';
    };
    window.addEventListener('pagehide', () => clearTimeout(controller.timer), { once: true });
    await controller.start();
    return;
  }
  document.querySelector('#create-demo').addEventListener('click', async () => {
    const button = document.querySelector('#create-demo');
    const output = document.querySelector('#create-status');
    button.disabled = true;
    output.textContent = '正在创建演示订单…';
    try {
      const scenario = document.querySelector('#scenario').value;
      if (!allowed.has(scenario)) throw new Error('invalid scenario');
      const key = sessionStorage.getItem('elmpay.demo.create-key') ?? `demo-${crypto.randomUUID()}`;
      sessionStorage.setItem('elmpay.demo.create-key', key);
      const response = await fetch('/demo/orders', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: { 'content-type': 'application/json', 'idempotency-key': key },
        body: JSON.stringify({ scenario }),
      });
      if (response.status !== 201) throw new Error('creation unavailable');
      const created = await response.json();
      const target = new URL(created.checkout_url);
      if (created.demo !== true || created.real_payments !== false || target.pathname !== '/checkout') {
        throw new Error('not a demo session');
      }
      sessionStorage.setItem(`elmpay.demo.scenario.${created.checkout_session_id}`, scenario);
      sessionStorage.removeItem('elmpay.demo.create-key');
      // Keep the short-lived credential in the fragment and on the current demo origin.
      location.assign(`/checkout${target.hash}`);
    } catch {
      output.textContent = '演示订单暂时无法创建。未发起真实支付；可以使用同一请求重试。';
      button.disabled = false;
    }
  });
}

if (typeof window !== 'undefined') {
  void initialize().catch(() => {
    const output = document.querySelector('#error');
    output.textContent = '无法验证演示状态；不会将未知结果当作成功。';
    output.hidden = false;
  });
}
