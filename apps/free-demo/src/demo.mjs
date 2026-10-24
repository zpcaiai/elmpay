export const demoScenarios = Object.freeze([
  { id: 'succeeded', label: '模拟成功', hint: '服务器确认成功后展示完成结果，不发生真实扣款。' },
  { id: 'declined', label: '模拟拒绝', hint: '体验支付被拒绝后的结果提示，可以另建演示订单。' },
  { id: 'unknown', label: '模拟未知结果', hint: '服务器尚不能确认结果时保持待确认，不会视为成功。' },
  { id: 'authorized', label: '模拟仅授权', hint: '体验授权后的待完成状态；授权不等于支付成功。' },
  { id: 'requires_action', label: '模拟需要进一步操作', hint: '体验需要额外操作的待确认状态，不跳转真实认证页面。' },
]);
const allowed = new Set(demoScenarios.map(value => value.id));
export const demoProfiles = Object.freeze([
  { method: 'wechat_native', label: '微信支付（模拟）', currency: 'CNY', displayAmount: '￥10.00' },
  { method: 'card', label: '银行卡（模拟）', currency: 'USD', displayAmount: 'US$10.00' },
]);

// Native browser fetch requires its Window receiver when called as a method.
export function demoApi(url, options = {}) {
  return globalThis.fetch(url, { ...options, signal: options.signal ?? AbortSignal.timeout(15000) });
}

export function demoPresentation(view) {
  switch (view.status) {
    case 'OPEN': return { tone: 'neutral', heading: '确认演示订单',
      description: '选择模拟支付方式后继续。本次演示不发生真实扣款。', step: 'confirm' };
    case 'SUCCEEDED': return { tone: 'success', heading: '模拟支付已成功',
      description: '服务器已确认这笔演示订单的模拟结果，没有发生真实扣款。', step: 'result' };
    case 'FAILED': return { tone: 'danger', heading: '本次模拟支付未完成',
      description: '服务器返回拒绝或失败结果。未扣款，可以创建新的演示订单。', step: 'result' };
    case 'PENDING': return { tone: 'warning', heading: '模拟结果仍待确认',
      description: '授权、额外操作或未知结果仍需服务器确认，未确认前不会视为成功。', step: 'result' };
    case 'EXPIRED': return { tone: 'warning', heading: '演示订单已过期',
      description: '此演示链接已失效，请重新创建订单。没有发生真实扣款。', step: 'result' };
    case 'CANCELED': return { tone: 'neutral', heading: '演示订单已取消',
      description: '这笔演示订单已结束，可以重新选择场景。没有发生真实扣款。', step: 'result' };
    default: return { tone: 'warning', heading: '状态尚未验证',
      description: '没有服务器确认的结果，不会视为支付成功。请重新查询或创建订单。', step: 'confirm' };
  }
}

export function demoDisplayView(view) {
  if (view.status === 'OPEN' && !view.methods.some(method => method.id === 'wechat_native')) return view;
  return { ...view, methods: view.methods.map(method => ({ ...method,
    label: method.id === 'wechat_native' ? '微信支付（模拟）' : method.label,
    reason: view.status === 'OPEN' ? method.reason : '',
  })) };
}

export function demoCreateRequest(storage, scenario, method = 'card') {
  if (!allowed.has(scenario) || !demoProfiles.some(profile => profile.method === method)) {
    throw new Error('invalid demo scenario or method');
  }
  let stored;
  try { stored = JSON.parse(storage.getItem('elmpay.demo.create-request') ?? 'null'); } catch { stored = null; }
  if (stored?.scenario === scenario && (stored.method ?? 'card') === method
      && /^demo-[0-9a-f-]{36}$/.test(stored.key ?? '')) return stored;
  const request = { key: `demo-${crypto.randomUUID()}`, scenario, method };
  storage.setItem('elmpay.demo.create-request', JSON.stringify(request));
  return request;
}

function progress(step) {
  for (const item of document.querySelectorAll('[data-step]')) {
    if (item.dataset.step === step) item.setAttribute('aria-current', 'step');
    else item.removeAttribute('aria-current');
  }
}

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
    let lastStatus = 0; let confirming = false;
    const controller = new CheckoutController({
      api: async (...args) => { const response = await demoApi(...args); lastStatus = response.status; return response; },
      tokenizer: async ({ checkoutSessionId }) => demoReference(checkoutSessionId,
        sessionStorage.getItem(`elmpay.demo.scenario.${checkoutSessionId}`)),
    });
    const render = controller.render.bind(controller);
    const fail = controller.fail.bind(controller);
    const refresh = controller.refresh.bind(controller);
    const confirm = controller.confirm.bind(controller);
    controller.refresh = async () => { clearTimeout(controller.timer); await refresh(); };
    controller.confirm = async method => {
      if (confirming) return;
      confirming = true;
      try { await confirm(method); } finally { confirming = false; }
    };
    controller.render = view => {
      const selected = document.querySelector('input[name="method"]:checked')?.value;
      const focused = document.activeElement?.matches('input[name="method"]')
        ? document.activeElement.value : null;
      const displayed = demoDisplayView(view);
      render(displayed);
      if (view.status === 'OPEN' && view.methods.some(method => method.id === selected && method.eligible)) {
        for (const input of document.querySelectorAll('input[name="method"]')) {
          if (input.value === selected && !input.disabled) input.checked = true;
        }
      }
      const presentation = demoPresentation(view);
      document.querySelector('#checkout').dataset.state = view.status;
      document.querySelector('#checkout').dataset.tone = presentation.tone;
      document.querySelector('#page-title').textContent = presentation.heading;
      document.querySelector('#result-description').textContent = presentation.description;
      document.querySelector('#summary-amount').textContent = view.displayAmount;
      document.querySelector('#summary-original-amount').textContent = view.displayAmount;
      document.querySelector('#summary-method').textContent = displayed.methods.map(method => method.label).join(' / ');
      document.querySelector('#order-session').textContent = `演示订单 · ${view.checkoutSessionId.slice(-8)}`;
      document.querySelector('#status').textContent = `模拟状态 · ${controller.statusText(view.status)}`;
      document.querySelector('#continue').textContent = '确认模拟支付（不扣款）';
      document.querySelector('#error').hidden = true;
      document.querySelector('#retry-status').hidden = view.status !== 'PENDING';
      if (confirming && view.status === 'OPEN') {
        document.querySelector('#continue').disabled = true;
        document.querySelector('#methods').disabled = true;
      }
      if (!confirming && view.status === 'OPEN' && focused) {
        for (const input of document.querySelectorAll('input[name="method"]')) {
          if (input.value === focused && !input.disabled) input.focus({ preventScroll: true });
        }
      }
      progress(presentation.step);
    };
    controller.fail = message => {
      fail(message);
      const expired = [401, 403, 404, 410].includes(lastStatus) || !controller.accessToken;
      document.querySelector('#checkout').dataset.state = 'UNVERIFIED';
      document.querySelector('#checkout').dataset.tone = 'warning';
      document.querySelector('#page-title').textContent = expired ? '演示链接已失效' : '暂时无法确认结果';
      document.querySelector('#result-description').textContent = '没有服务器确认的结果，不会视为支付成功。';
      document.querySelector('#status').textContent = '模拟状态 · 尚未验证';
      document.querySelector('#error').textContent = expired
        ? '请创建新的演示订单。没有发生真实扣款。'
        : '连接暂时不可用，请重新查询状态；不要将网络错误视为支付成功。';
      document.querySelector('#retry-status').hidden = expired;
      document.querySelector('#continue').disabled = true;
      document.querySelector('#methods').disabled = true;
      progress('confirm');
    };
    document.querySelector('#retry-status').addEventListener('click', async () => {
      const button = document.querySelector('#retry-status'); button.disabled = true;
      try { await controller.refresh(); } finally { button.disabled = false; }
    });
    window.addEventListener('pagehide', () => clearTimeout(controller.timer), { once: true });
    await controller.start();
    return;
  }
  if (location.pathname === '/checkout') {
    document.querySelector('#create-status').textContent = '演示链接不完整或已失效，请重新创建订单。';
  }
  const scenarioInput = document.querySelector('#scenario');
  const methodInput = document.querySelector('#demo-method');
  const describeMethod = () => {
    const profile = demoProfiles.find(value => value.method === methodInput.value);
    if (!profile) return;
    document.querySelector('#summary-original-amount').textContent = profile.displayAmount;
    document.querySelector('#summary-amount').textContent = profile.displayAmount;
    document.querySelector('#summary-method').textContent = profile.label;
  };
  methodInput.addEventListener('change', describeMethod); describeMethod();
  const describeScenario = () => {
    document.querySelector('#scenario-description').textContent =
      demoScenarios.find(value => value.id === scenarioInput.value)?.hint ?? '请选择支持的演示场景。';
  };
  scenarioInput.addEventListener('change', describeScenario); describeScenario();
  document.querySelector('#create-demo').addEventListener('click', async () => {
    const button = document.querySelector('#create-demo');
    const output = document.querySelector('#create-status');
    button.disabled = true;
    output.textContent = '正在创建演示订单…';
    try {
      const scenario = document.querySelector('#scenario').value;
      const method = methodInput.value;
      if (!allowed.has(scenario)) throw new Error('invalid scenario');
      const { key } = demoCreateRequest(sessionStorage, scenario, method);
      const response = await demoApi('/demo/orders', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: { 'content-type': 'application/json', 'idempotency-key': key },
        body: JSON.stringify({ scenario, payment_method: method }),
      });
      if (response.status !== 201) throw new Error('creation unavailable');
      const created = await response.json();
      const target = new URL(created.checkout_url);
      if (created.demo !== true || created.real_payments !== false || target.pathname !== '/checkout'
          || created.payment_method !== method || created.simulation_engine !== 'local-sandbox') {
        throw new Error('not a demo session');
      }
      sessionStorage.setItem(`elmpay.demo.scenario.${created.checkout_session_id}`, scenario);
      sessionStorage.removeItem('elmpay.demo.create-request');
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
