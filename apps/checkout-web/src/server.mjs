import { createReadStream, statSync } from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BrowserSecurityRuntime } from './browser-security.mjs';
import { ProviderSdkPolicy } from './provider-sdk-policy.mjs';
import { createEdgeTransport, readMountedCredential } from './edge-transport.mjs';

const root = fileURLToPath(new URL('../public/', import.meta.url));
const scriptManifest = fileURLToPath(new URL('../security/script-allowlist.json', import.meta.url));
const providerSdkManifest = fileURLToPath(new URL('../security/provider-sdk-allowlist.json', import.meta.url));
const port = Number.parseInt(process.env.PORT ?? '8080', 10);
const browserSecurity = new BrowserSecurityRuntime({ publicRoot: root, manifestPath: scriptManifest });
const providerSdkSecurity = new ProviderSdkPolicy({
  manifestPath: providerSdkManifest,
  ticketKey: randomBytes(32),
});

const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.mjs', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
]);

const sessionPath = /^\/api\/checkout\/sessions\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?:\/confirm)?$/;
const providerConfigurationPath = /^\/api\/checkout\/sessions\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\/provider-sdk-config$/;

function securityHeaders(security, nonce) {
  return {
    'content-security-policy': security.csp(nonce),
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(self)',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'reporting-endpoints': 'elmpay-csp="/security/csp-report"',
    'report-to': JSON.stringify({ group: 'elmpay-csp', max_age: 86400,
      endpoints: [{ url: '/security/csp-report' }] }),
  };
}

function providerFrameHeaders(frame) {
  const connectSources = frame.connectOrigins.length === 0 ? "'none'" : frame.connectOrigins.join(' ');
  const frameSources = frame.frameOrigins.length === 0 ? "'none'" : frame.frameOrigins.join(' ');
  return {
    'content-security-policy': [
      "default-src 'none'", "base-uri 'none'", "frame-ancestors 'self'", "form-action 'none'",
      `script-src 'nonce-${frame.nonce}' ${frame.scriptUrl}`,
      `connect-src ${connectSources}`, `frame-src ${frameSources}`,
      "img-src data:", "style-src 'none'", "font-src 'none'", "object-src 'none'",
    ].join('; '),
    'cache-control': 'no-store',
    'content-type': 'text/html; charset=utf-8',
    'cross-origin-resource-policy': 'same-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  };
}

function staticHandler(request, response, security) {
  const rawPath = new URL(request.url, 'https://checkout.invalid').pathname;
  const relative = rawPath === '/' ? 'index.html' : rawPath.slice(1);
  const normalized = normalize(relative);
  const nonce = security.nonce();
  if (normalized.startsWith('..') || normalized.includes('\0')) {
    response.writeHead(400, {
      ...securityHeaders(security, nonce),
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
    }).end('invalid path');
    return;
  }
  const path = join(root, normalized);
  try {
    if (!statSync(path).isFile()) throw new Error('not a file');
  } catch {
    response.writeHead(404, { ...securityHeaders(security, nonce),
      'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }).end('not found');
    return;
  }
  try {
    let body = null;
    if (normalized === 'index.html') body = security.renderIndex(nonce);
    else if (extname(path) === '.mjs') body = security.verifyScript(`/${normalized}`);
    response.writeHead(200, {
      ...securityHeaders(security, nonce),
      'content-type': contentTypes.get(extname(path)) ?? 'application/octet-stream',
      'cache-control': extname(path) === '.html' ? 'no-store' : 'public, max-age=300',
    });
    if (body === null) createReadStream(path).pipe(response);
    else response.end(body);
  } catch {
    response.writeHead(503, { ...securityHeaders(security, nonce),
      'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
      .end('checkout integrity unavailable');
  }
}

export function createHandler({
  apiBaseUrl = null,
  transport = fetch,
  security = browserSecurity,
  providerSdkPolicy = providerSdkSecurity,
  securityReportSink = null,
} = {}) {
  const upstream = apiBaseUrl === null ? null : new URL(apiBaseUrl);
  const reportSink = securityReportSink ?? (upstream === null ? async () => {
    throw new Error('security report sink unavailable');
  } : upstreamReportSink(upstream, transport));
  return async function checkoutHandler(request, response) {
    const requestUrl = new URL(request.url, 'https://checkout.invalid');
    const path = requestUrl.pathname;
    if (path === '/health/startup' || path === '/health/live' || path === '/health/ready') {
      if (request.method !== 'GET') {
        problem(response, 405, 'method not allowed', security);
        return;
      }
      const ready = upstream !== null;
      const allowed = path !== '/health/ready' || ready;
      const body = Buffer.from(JSON.stringify({
        service: 'checkout-web',
        status: allowed ? 'UP' : 'NOT_READY',
        probe: path.slice('/health/'.length),
        checks: {
          process: 'UP', browserIntegrityPolicy: 'VERIFIED_AT_STARTUP',
          upstreamConfiguration: ready ? 'CONFIGURED' : 'MISSING',
          providerSdkAllowlist: providerSdkPolicy.enabledProviderCount > 0
            ? 'CONFIGURED' : 'NO_PROVIDER_ENABLED',
        },
      }), 'utf8');
      const nonce = security.nonce();
      response.writeHead(allowed ? 200 : 503, {
        ...securityHeaders(security, nonce),
        'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
      }).end(body);
      return;
    }
    if (path === '/security/provider-sdk-frame') {
      if (request.method !== 'GET' || requestUrl.searchParams.size !== 1
          || requestUrl.searchParams.getAll('ticket').length !== 1) {
        problem(response, 404, 'provider SDK frame not found', security);
        return;
      }
      try {
        const frame = providerSdkPolicy.renderFrame(requestUrl.searchParams.get('ticket'));
        response.writeHead(200, providerFrameHeaders(frame)).end(frame.bytes);
      } catch {
        problem(response, 404, 'provider SDK frame not found', security);
      }
      return;
    }
    if (path === '/security/script-policy') {
      if (request.method !== 'GET') {
        problem(response, 405, 'method not allowed', security);
        return;
      }
      const body = Buffer.from(JSON.stringify(security.publicPolicy()), 'utf8');
      const nonce = security.nonce();
      response.writeHead(200, { ...securityHeaders(security, nonce),
        'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }).end(body);
      return;
    }
    if (path === '/security/csp-report' || path === '/security/integrity-report') {
      if (request.method !== 'POST') {
        problem(response, 405, 'method not allowed', security);
        return;
      }
      try {
        const report = security.sanitizeReport(await boundedJson(request, 16_384));
        await reportSink(report);
        const nonce = security.nonce();
        response.writeHead(204, { ...securityHeaders(security, nonce), 'cache-control': 'no-store' }).end();
      } catch {
        problem(response, 503, 'security report could not be persisted', security);
      }
      return;
    }
    if (!path.startsWith('/api/checkout/sessions/')) {
      staticHandler(request, response, security);
      return;
    }
    if (upstream === null) {
      problem(response, 503, 'checkout proxy is not configured', security);
      return;
    }
    const providerConfigurationRequest = providerConfigurationPath.test(path);
    if ((!providerConfigurationRequest && !sessionPath.test(path))
        || (providerConfigurationRequest && request.method !== 'GET')
        || (!providerConfigurationRequest
          && (!(['GET', 'POST'].includes(request.method ?? 'GET'))
            || (path.endsWith('/confirm') !== ((request.method ?? 'GET') === 'POST'))))) {
      problem(response, 404, 'checkout resource not found', security);
      return;
    }
    const authorization = request.headers?.authorization;
    if (typeof authorization !== 'string'
        || !/^CheckoutSession [A-Za-z0-9_-]{48}\.[A-Za-z0-9_-]{43}$/.test(authorization)) {
      problem(response, 401, 'checkout authorization is invalid', security);
      return;
    }
    const idempotencyKey = request.headers?.['idempotency-key'];
    if (request.method === 'POST'
        && (typeof idempotencyKey !== 'string'
          || !/^[A-Za-z0-9._:-]{16,128}$/.test(idempotencyKey))) {
      problem(response, 400, 'a valid idempotency key is required', security);
      return;
    }
    if (providerConfigurationRequest) {
      const method = requestUrl.searchParams.get('method');
      const channel = requestUrl.searchParams.get('channel');
      if (requestUrl.searchParams.size !== 2
          || requestUrl.searchParams.getAll('method').length !== 1
          || requestUrl.searchParams.getAll('channel').length !== 1
          || !/^[a-z0-9._-]{1,64}$/.test(method ?? '')
          || !/^[A-Za-z0-9_-]{20,128}$/.test(channel ?? '')) {
        problem(response, 400, 'provider SDK configuration request is invalid', security);
        return;
      }
      try {
        const target = new URL(path, upstream);
        target.searchParams.set('method', method);
        target.searchParams.set('channel', channel);
        const upstreamResponse = await transport(target, {
          method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(5_000),
          headers: {
            accept: 'application/json', authorization, 'x-request-id': randomUUID(),
            traceparent: traceparent(),
          },
        });
        if (!upstreamResponse.ok || upstreamResponse.status >= 300
            || !upstreamResponse.headers.get('content-type')?.startsWith('application/json')) {
          throw new Error('upstream provider SDK configuration unavailable');
        }
        const upstreamConfiguration = await boundedResponseJson(upstreamResponse, 32_768);
        const configuration = providerSdkPolicy.authorizeConfiguration({
          checkoutSessionId: path.split('/')[4], method, channel, upstreamConfiguration,
        });
        const nonce = security.nonce();
        response.writeHead(200, {
          ...securityHeaders(security, nonce),
          'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
          'x-request-id': upstreamResponse.headers.get('x-request-id') ?? randomUUID(),
        }).end(JSON.stringify(configuration));
      } catch {
        problem(response, 503, 'provider SDK configuration is unavailable', security);
      }
      return;
    }
    try {
      const body = request.method === 'POST' ? await boundedBody(request, 32_768) : undefined;
      const target = new URL(path, upstream);
      const upstreamResponse = await transport(target, {
        method: request.method,
        redirect: 'manual',
        signal: AbortSignal.timeout(5_000),
        headers: {
          accept: 'application/json',
          'accept-language': preferredLanguage(request.headers?.['accept-language']),
          authorization,
          'x-request-id': randomUUID(),
          traceparent: traceparent(),
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          ...(idempotencyKey === undefined ? {} : { 'idempotency-key': idempotencyKey }),
        },
        body,
      });
      const bytes = new Uint8Array(await upstreamResponse.arrayBuffer());
      if (bytes.byteLength > 1_048_576) throw new Error('upstream response too large');
      const nonce = security.nonce();
      response.writeHead(upstreamResponse.status, {
        ...securityHeaders(security, nonce),
        'content-type': upstreamResponse.headers.get('content-type')?.startsWith('application/json')
          ? 'application/json; charset=utf-8' : 'application/problem+json; charset=utf-8',
        'cache-control': 'no-store',
        'x-request-id': upstreamResponse.headers.get('x-request-id') ?? randomUUID(),
      }).end(bytes);
    } catch {
      problem(response, 502, 'checkout status could not be verified', security);
    }
  };
}

export const handler = createHandler();

export function configFromEnvironment(environment) {
  const mode = environment.ELMPAY_CHECKOUT_WEB_MODE;
  if (mode === 'local') {
    if (environment.ELMPAY_ENABLE_LOCAL_SANDBOX !== 'true') {
      throw new Error('local checkout requires ELMPAY_ENABLE_LOCAL_SANDBOX=true');
    }
    const value = environment.ELMPAY_API_BASE_URL ?? 'http://127.0.0.1:8080/';
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(parsed.hostname)) {
      throw new Error('local API base must be loopback HTTP');
    }
    return { apiBaseUrl: parsed };
  }
  if (mode === 'production') {
    if (Object.hasOwn(environment, 'ELMPAY_PROVIDER_FRAME_TICKET_KEY')) {
      throw new Error('ELMPAY_PROVIDER_FRAME_TICKET_KEY is forbidden; use the read-only key mount');
    }
    const parsed = new URL(required(environment, 'ELMPAY_API_BASE_URL'));
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search
        || parsed.hash || parsed.pathname !== '/') {
      throw new Error('production API base must be one credential-free HTTPS origin');
    }
    const encodedKey = readMountedCredential(
      required(environment, 'ELMPAY_PROVIDER_FRAME_TICKET_KEY_FILE'),
      'provider frame ticket key',
    ).toString('utf8').replace(/\r?\n$/, '');
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(encodedKey)) {
      throw new Error('ELMPAY_PROVIDER_FRAME_TICKET_KEY_FILE must contain canonical base64url');
    }
    const providerFrameTicketKey = Buffer.from(encodedKey, 'base64url');
    if (providerFrameTicketKey.byteLength < 32
        || providerFrameTicketKey.toString('base64url') !== encodedKey) {
      throw new Error('ELMPAY_PROVIDER_FRAME_TICKET_KEY_FILE must contain at least 32 bytes');
    }
    const edgeTransport = createEdgeTransport({
      apiBaseUrl: parsed,
      certificateFile: required(environment, 'ELMPAY_EDGE_CLIENT_CERTIFICATE_FILE'),
      privateKeyFile: required(environment, 'ELMPAY_EDGE_CLIENT_PRIVATE_KEY_FILE'),
      trustBundleFile: required(environment, 'ELMPAY_EDGE_TRUST_BUNDLE_FILE'),
      serverName: required(environment, 'ELMPAY_EDGE_TLS_SERVER_NAME'),
    });
    return { apiBaseUrl: parsed, providerFrameTicketKey, transport: edgeTransport };
  }
  throw new Error('ELMPAY_CHECKOUT_WEB_MODE must be local or production');
}

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${name} is required`);
  return value;
}

async function boundedBody(request, maximumBytes) {
  const chunks = []; let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk); length += bytes.length;
    if (length > maximumBytes) throw new Error('request body too large');
    chunks.push(bytes);
  }
  const body = Buffer.concat(chunks);
  JSON.parse(body.toString('utf8'));
  return body;
}

async function boundedJson(request, maximumBytes) {
  const value = await boundedBody(request, maximumBytes);
  return JSON.parse(value.toString('utf8'));
}

async function boundedResponseJson(response, maximumBytes) {
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > maximumBytes) throw new Error('upstream response too large');
  return JSON.parse(Buffer.from(bytes).toString('utf8'));
}

function upstreamReportSink(upstream, transport) {
  return async report => {
    const target = new URL('/v1/security/browser-reports', upstream);
    const result = await transport(target, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(5_000),
      headers: { accept: 'application/json', 'content-type': 'application/json',
        'idempotency-key': report.reportId, 'x-request-id': randomUUID(), traceparent: traceparent() },
      body: JSON.stringify(report),
    });
    if (!result.ok) throw new Error('security report rejected');
  };
}

function traceparent() {
  return `00-${randomBytes(16).toString('hex')}-${randomBytes(8).toString('hex')}-01`;
}

function preferredLanguage(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256
      || !/^[A-Za-z0-9,;=._* -]+$/.test(value)) return 'en';
  return value;
}

function problem(response, status, message, security = browserSecurity) {
  const nonce = security.nonce();
  response.writeHead(status, {
    ...securityHeaders(security, nonce),
    'content-type': 'application/problem+json; charset=utf-8',
    'cache-control': 'no-store',
  }).end(JSON.stringify({ code: status === 401 ? 'invalid_checkout_token' : 'checkout_unavailable', message }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const configuration = configFromEnvironment(process.env);
  const runtimeProviderSdkPolicy = new ProviderSdkPolicy({
    manifestPath: providerSdkManifest,
    ticketKey: configuration.providerFrameTicketKey ?? randomBytes(32),
  });
  const runtimeHandler = createHandler({
    apiBaseUrl: configuration.apiBaseUrl,
    transport: configuration.transport ?? fetch,
    providerSdkPolicy: runtimeProviderSdkPolicy,
  });
  createServer((request, response) => { void runtimeHandler(request, response); })
    .listen(port, '0.0.0.0', () => process.stdout.write(`checkout listening on ${port}\n`));
}
