import { createHash, randomBytes, randomUUID } from 'node:crypto';

export const scenarios = Object.freeze(['succeeded', 'declined', 'unknown']);
const sessionPattern = /^\/api\/checkout\/sessions\/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(\/confirm)?$/;
const bearerPattern = /^CheckoutSession [A-Za-z0-9_-]{48}\.[A-Za-z0-9_-]{43}$/;
const keyPattern = /^[A-Za-z0-9._:-]{16,100}$/;
export const demoHeaders = Object.freeze({
  'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer', 'x-elmpay-demo': 'true',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
});

function port(value, fallback) {
  const number = Number(value ?? fallback);
  if (!Number.isInteger(number) || number < 1024 || number > 65535) throw new Error('invalid demo port');
  return number;
}

export function demoConfiguration(environment) {
  if (environment.ELMPAY_DEMO_ENABLED !== 'true'
      || environment.ELMPAY_DEMO_REAL_PAYMENTS_DISABLED !== 'true') {
    throw new Error('demo requires explicit enablement and real-payments-disabled flags');
  }
  for (const key of Object.keys(environment)) {
    if (key.startsWith('ELMPAY_') && !key.startsWith('ELMPAY_DEMO_')
        && !(key === 'ELMPAY_RUNTIME_MODE' && environment[key] === 'local')) {
      throw new Error('production configuration is forbidden in the free demo');
    }
  }
  const publicUrl = new URL(environment.ELMPAY_DEMO_PUBLIC_ORIGIN ?? 'https://elmpay.vercel.app');
  if (publicUrl.protocol !== 'https:' || publicUrl.username || publicUrl.password
      || publicUrl.pathname !== '/' || publicUrl.search || publicUrl.hash) {
    throw new Error('demo public origin must be a credential-free HTTPS origin');
  }
  const gatewayPort = port(environment.ELMPAY_DEMO_GATEWAY_PORT, 8500);
  const healthPort = port(environment.ELMPAY_DEMO_HEALTH_PORT, 8501);
  if (gatewayPort === healthPort) throw new Error('demo ports must differ');
  const apiToken = randomBytes(32).toString('base64url');
  const digest = createHash('sha256').update(apiToken).digest('hex');
  const tenant = '21000000-0000-4000-8000-000000000001';
  const project = '21000000-0000-4000-8000-000000000002';
  const merchant = '21000000-0000-4000-8000-000000000003';
  const origins = new Set([publicUrl.origin]);
  if (environment.RENDER_EXTERNAL_URL) {
    const render = new URL(environment.RENDER_EXTERNAL_URL);
    if (render.protocol !== 'https:' || render.username || render.password || render.pathname !== '/'
        || render.search || render.hash) {
      throw new Error('Render origin is invalid');
    }
    origins.add(render.origin);
  }
  return Object.freeze({ apiToken, project, gatewayPort, healthPort, origins,
    publicOrigin: publicUrl.origin,
    gatewayOrigin: `http://127.0.0.1:${gatewayPort}`,
    healthOrigin: `http://127.0.0.1:${healthPort}`,
    childEnvironment: Object.freeze({
      PATH: environment.PATH ?? '/usr/local/bin:/usr/bin:/bin',
      ELMPAY_RUNTIME_MODE: 'local', ELMPAY_ENABLE_LOCAL_SANDBOX: 'true',
      ELMPAY_LOCAL_RISK_POLICY: 'approve-sandbox', PORT: String(gatewayPort),
      ELMPAY_HEALTH_PORT: String(healthPort),
      ELMPAY_API_PRINCIPALS: `${digest}|free-demo|${tenant}|${project}|${merchant}|payments.read+payments.write`,
      ELMPAY_CHECKOUT_PUBLIC_BASE_URL: `${publicUrl.origin}/checkout`,
      ELMPAY_CHECKOUT_RETURN_ROUTES: `demo-complete=${publicUrl.origin}/complete`,
      ELMPAY_CHECKOUT_DEFAULT_RETURN_ROUTE_ID: 'demo-complete',
      ELMPAY_CHECKOUT_ALLOWED_METHODS: 'card',
    }),
  });
}

function respond(response, status, body) {
  response.writeHead(status, { ...demoHeaders, 'content-type': 'application/json; charset=utf-8' })
    .end(JSON.stringify({ ...body, demo: true, real_payments: false }));
}

async function jsonBody(request) {
  if (!request.headers['content-type']?.startsWith('application/json')) {
    throw Object.assign(new Error('JSON required'), { status: 415 });
  }
  let size = 0; const parts = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 4096) throw Object.assign(new Error('request too large'), { status: 413 });
    parts.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(parts).toString('utf8'));
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) throw new Error('object required');
  return value;
}

async function upstreamJson(origin, path, options = {}) {
  const response = await fetch(new URL(path, origin), {
    ...options, redirect: 'manual', signal: AbortSignal.timeout(5000),
  });
  if (response.status >= 300 && response.status < 400) throw new Error('upstream redirect refused');
  if (!response.headers.get('content-type')?.startsWith('application/json')) throw new Error('JSON required');
  const chunks = []; let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length;
    if (bytes > 65536) throw new Error('upstream response too large');
    chunks.push(Buffer.from(chunk));
  }
  return { status: response.status, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) };
}

/** This adapter only exposes the existing loopback sandbox, never production PSP endpoints. */
export function createDemoBridge(configuration, { page = null, asset = null, gatewayAlive = () => true } = {}) {
  const createKeys = new Map();
  let active = 0;
  return async function demoHandler(request, response) {
    active += 1;
    try {
      const url = new URL(request.url, 'https://demo.invalid');
      if (url.search) return respond(response, 400, { code: 'query_not_allowed' });
      if (active > 8) return respond(response, 429, { code: 'demo_busy' });
      const path = url.pathname;
      if (request.method === 'GET' && /^\/health\/(startup|live|ready)$/.test(path)) {
        if (!gatewayAlive()) return respond(response, 503, { status: 'NOT_READY' });
        const probe = await upstreamJson(configuration.healthOrigin, '/health/ready');
        const ready = probe.status === 200 && probe.body.mode === 'local' && probe.body.status === 'ready';
        return respond(response, ready ? 200 : 503, { status: ready ? 'DEMO_READY' : 'NOT_READY',
          persistence: 'ephemeral', provider: 'local-sandbox' });
      }
      if (request.method === 'GET' && ['/', '/checkout', '/complete'].includes(path) && page) {
        return page(request, response);
      }
      if (request.method === 'GET' && asset && asset(path, response)) return;
      if (!gatewayAlive()) return respond(response, 503, { code: 'demo_backend_unavailable' });
      const member = sessionPattern.exec(path);
      const create = path === '/demo/orders';
      if (!create && !member) return respond(response, 404, { code: 'not_found' });
      const expected = create || member?.[2] ? 'POST' : 'GET';
      if (request.method !== expected) return respond(response, 405, { code: 'method_not_allowed' });
      if (expected === 'POST' && !configuration.origins.has(request.headers.origin)) {
        return respond(response, 403, { code: 'origin_rejected' });
      }
      const key = request.headers['idempotency-key'];
      if (expected === 'POST' && !keyPattern.test(key ?? '')) {
        return respond(response, 400, { code: 'invalid_idempotency_key' });
      }
      const headers = { accept: 'application/json', 'x-request-id': randomUUID(),
        'accept-language': 'zh-CN', 'content-type': 'application/json' };
      if (create) {
        const body = await jsonBody(request);
        if (Object.keys(body).join(',') !== 'scenario' || !scenarios.includes(body.scenario)) {
          return respond(response, 400, { code: 'invalid_demo_scenario' });
        }
        if (createKeys.has(key) && createKeys.get(key) !== body.scenario) {
          return respond(response, 409, { code: 'idempotency_conflict' });
        }
        if (!createKeys.has(key) && createKeys.size >= 200) {
          return respond(response, 429, { code: 'demo_capacity_reached' });
        }
        createKeys.set(key, body.scenario);
        const result = await upstreamJson(configuration.gatewayOrigin, '/v1/checkout-sessions', {
          method: 'POST', headers: { ...headers, authorization: `Bearer ${configuration.apiToken}`,
            'x-project-id': configuration.project, 'idempotency-key': key },
          body: JSON.stringify({ business_order_no: `demo-${createHash('sha256').update(key).digest('hex').slice(0, 24)}`,
            amount: 1000, currency: 'USD', return_route_id: 'demo-complete', payment_method: 'card' }),
        });
        if (result.status !== 201) return respond(response, result.status, { code: 'demo_create_rejected' });
        const target = new URL(result.body.checkout_url);
        const fragment = new URLSearchParams(target.hash.slice(1));
        if (target.origin !== configuration.publicOrigin || target.pathname !== '/checkout'
            || target.search || target.username || target.password
            || fragment.size !== 2 || fragment.getAll('session').length !== 1
            || fragment.getAll('token').length !== 1
            || fragment.get('session') !== result.body.checkout_session_id
            || !bearerPattern.test(`CheckoutSession ${fragment.get('token')}`)) {
          throw new Error('checkout origin mismatch');
        }
        return respond(response, 201, { checkout_session_id: result.body.checkout_session_id,
          checkout_url: target.href, scenario: body.scenario });
      }
      const authorization = request.headers.authorization;
      if (!bearerPattern.test(authorization ?? '')) return respond(response, 401, { code: 'invalid_checkout_token' });
      let body;
      if (expected === 'POST') {
        body = await jsonBody(request);
        if (Object.keys(body).some(name => !['method', 'payment_method_reference', 'provider_parameters'].includes(name))
            || body.method !== 'card' || body.payment_method_reference !== `psp://elmpay-demo/${member[1]}`
            || !body.provider_parameters || Object.getPrototypeOf(body.provider_parameters) !== Object.prototype
            || Object.keys(body.provider_parameters).join(',') !== 'simulation'
            || !scenarios.includes(body.provider_parameters.simulation)) {
          return respond(response, 400, { code: 'only_synthetic_demo_reference_allowed' });
        }
      }
      const result = await upstreamJson(configuration.gatewayOrigin, path, {
        method: expected, headers: { ...headers, authorization,
          ...(key ? { 'idempotency-key': key } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      return respond(response, result.status, result.body);
    } catch (error) {
      return respond(response, error.status ?? (error instanceof SyntaxError ? 400 : 503),
        { code: 'demo_request_unavailable' });
    } finally { active = Math.max(0, active - 1); }
  };
}
