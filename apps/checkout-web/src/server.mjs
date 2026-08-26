import { createReadStream, statSync } from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../public/', import.meta.url));
const port = Number.parseInt(process.env.PORT ?? '8080', 10);
const csp = [
  "default-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "style-src 'self'",
  "script-src 'self'",
].join('; ');

const contentTypes = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.mjs', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
]);

const sessionPath = /^\/api\/checkout\/sessions\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?:\/confirm)?$/;

function staticHandler(request, response) {
  const rawPath = new URL(request.url, 'https://checkout.invalid').pathname;
  const relative = rawPath === '/' ? 'index.html' : rawPath.slice(1);
  const normalized = normalize(relative);
  if (normalized.startsWith('..') || normalized.includes('\0')) {
    response.writeHead(400, {
      'content-security-policy': csp,
      'content-type': 'text/plain; charset=utf-8',
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-store',
    }).end('invalid path');
    return;
  }
  const path = join(root, normalized);
  try {
    if (!statSync(path).isFile()) throw new Error('not a file');
    response.writeHead(200, {
      'content-type': contentTypes.get(extname(path)) ?? 'application/octet-stream',
      'content-security-policy': csp,
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
      'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(self)',
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
      'cache-control': extname(path) === '.html' ? 'no-store' : 'public, max-age=300',
    });
    createReadStream(path).pipe(response);
  } catch {
    response.writeHead(404, { 'content-security-policy': csp, 'content-type': 'text/plain' }).end('not found');
  }
}

export function createHandler({ apiBaseUrl = null, transport = fetch } = {}) {
  const upstream = apiBaseUrl === null ? null : new URL(apiBaseUrl);
  return async function checkoutHandler(request, response) {
    const path = new URL(request.url, 'https://checkout.invalid').pathname;
    if (!path.startsWith('/api/checkout/sessions/')) {
      staticHandler(request, response);
      return;
    }
    if (upstream === null) {
      problem(response, 503, 'checkout proxy is not configured');
      return;
    }
    if (!sessionPath.test(path)
        || !(['GET', 'POST'].includes(request.method ?? 'GET'))
        || (path.endsWith('/confirm') !== ((request.method ?? 'GET') === 'POST'))) {
      problem(response, 404, 'checkout resource not found');
      return;
    }
    const authorization = request.headers?.authorization;
    if (typeof authorization !== 'string'
        || !/^CheckoutSession [A-Za-z0-9_-]{48}\.[A-Za-z0-9_-]{43}$/.test(authorization)) {
      problem(response, 401, 'checkout authorization is invalid');
      return;
    }
    const idempotencyKey = request.headers?.['idempotency-key'];
    if (request.method === 'POST'
        && (typeof idempotencyKey !== 'string'
          || !/^[A-Za-z0-9._:-]{16,128}$/.test(idempotencyKey))) {
      problem(response, 400, 'a valid idempotency key is required');
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
      response.writeHead(upstreamResponse.status, {
        'content-type': upstreamResponse.headers.get('content-type')?.startsWith('application/json')
          ? 'application/json; charset=utf-8' : 'application/problem+json; charset=utf-8',
        'content-security-policy': csp,
        'cache-control': 'no-store',
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
        'x-request-id': upstreamResponse.headers.get('x-request-id') ?? randomUUID(),
      }).end(bytes);
    } catch {
      problem(response, 502, 'checkout status could not be verified');
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
    const parsed = new URL(required(environment, 'ELMPAY_API_BASE_URL'));
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
      throw new Error('production API base must be credential-free HTTPS');
    }
    return { apiBaseUrl: parsed };
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

function traceparent() {
  return `00-${randomBytes(16).toString('hex')}-${randomBytes(8).toString('hex')}-01`;
}

function problem(response, status, message) {
  response.writeHead(status, {
    'content-security-policy': csp,
    'content-type': 'application/problem+json; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  }).end(JSON.stringify({ code: status === 401 ? 'invalid_checkout_token' : 'checkout_unavailable', message }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const runtimeHandler = createHandler(configFromEnvironment(process.env));
  createServer((request, response) => { void runtimeHandler(request, response); })
    .listen(port, '0.0.0.0', () => process.stdout.write(`checkout listening on ${port}\n`));
}
