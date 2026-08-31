import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

export const MAX_RESPONSE_BYTES = 1_048_576;

export class ElmpayResponseError extends Error {
  constructor(message, { requestId = '', cause } = {}) {
    super(message, { cause }); this.name = new.target.name; this.requestId = requestId;
  }
}
export class ResponseTooLargeError extends ElmpayResponseError {}
export class InvalidResponseError extends ElmpayResponseError {}
export class ApiError extends ElmpayResponseError {
  constructor(problem, { requestId = '' } = {}) {
    super(`ElmPay API error ${problem.status}: ${problem.code}`, { requestId });
    this.problem = Object.freeze(problem); this.statusCode = problem.status;
  }
}

export class ElmpayClient {
  constructor({ baseUrl, bearerToken, projectId, timeoutMs = 5000, maximumAttempts = 3, transport = fetch }) {
    const url = new URL(baseUrl);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash)
      throw new TypeError('baseUrl must be an origin-form HTTPS URL');
    if (!bearerToken) throw new TypeError('bearerToken required');
    if (!/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(projectId ?? '')) throw new TypeError('projectId required');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300_000) throw new RangeError('timeoutMs must be positive and at most five minutes');
    if (maximumAttempts < 1 || maximumAttempts > 5) throw new RangeError('maximumAttempts must be 1..5');
    Object.assign(this, { baseUrl: url, bearerToken, projectId, timeoutMs, maximumAttempts, transport });
  }
  async createCheckoutSession(request, idempotencyKey = randomUUID()) {
    if (!Number.isSafeInteger(request.amount) || request.amount <= 0) throw new TypeError('amount must be a positive safe integer');
    const body = { business_order_no: request.businessOrderNo, amount: request.amount, currency: request.currency,
      ...(request.returnRouteId ? { return_route_id: request.returnRouteId } : {}) };
    return this.#send('POST', '/v1/checkout-sessions', body, idempotencyKey, 201);
  }
  async getCheckoutSession(id) { return this.#send('GET', `/v1/checkout-sessions/${encodeURIComponent(id)}`, undefined, undefined, 200); }
  async confirmCheckoutSession(id, request, idempotencyKey = randomUUID()) {
    return this.#send('POST', `/v1/checkout-sessions/${encodeURIComponent(id)}/confirm`, {
      payment_method_type: request.paymentMethodType,
      ...(request.paymentMethodReference ? { payment_method_reference: request.paymentMethodReference } : {}),
      ...(request.fingerprint ? { fingerprint: request.fingerprint } : {}),
    }, idempotencyKey, 200);
  }
  async #send(method, path, body, idempotencyKey, expectedStatus) {
    const retrySafe = method === 'GET' || Boolean(idempotencyKey);
    for (let attempt = 1; attempt <= this.maximumAttempts; attempt++) {
      let response;
      try {
        response = await this.transport(new URL(path, this.baseUrl), { method, redirect: 'manual', signal: AbortSignal.timeout(this.timeoutMs),
          headers: { accept: 'application/json', authorization: `Bearer ${this.bearerToken}`,
            'x-project-id': this.projectId,
            ...(body ? { 'content-type': 'application/json' } : {}), ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}) },
          body: body ? JSON.stringify(body) : undefined });
      } catch (error) {
        if (!retrySafe || attempt === this.maximumAttempts) throw error;
        await backoff(attempt);
        continue;
      }
      try {
        return await decodeResponse(response, expectedStatus);
      } catch (error) {
        if (!(error instanceof ApiError) || !retrySafe || attempt === this.maximumAttempts || !retryable(error.statusCode)) throw error;
      }
      await backoff(attempt);
    }
    throw new Error('unreachable');
  }
}

function retryable(status) { return status === 408 || status === 429 || status >= 500; }
function backoff(attempt) { return new Promise(resolve => setTimeout(resolve, Math.min(1000, 100 * 2 ** (attempt - 1)))); }

async function readBounded(response, requestId) {
  const rawLength = response.headers.get('content-length');
  if (rawLength !== null) {
    if (!/^\d+$/.test(rawLength)) throw new InvalidResponseError('invalid Content-Length', { requestId });
    const contentLength = Number(rawLength);
    if (!Number.isSafeInteger(contentLength)) throw new InvalidResponseError('invalid Content-Length', { requestId });
    if (contentLength > MAX_RESPONSE_BYTES) throw new ResponseTooLargeError('response exceeds 1 MiB limit', { requestId });
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw new InvalidResponseError('response body is not a readable byte stream', { requestId });
  }
  const reader = response.body.getReader(); const chunks = []; let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new InvalidResponseError('response stream returned non-bytes', { requestId });
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel('response exceeds limit');
        throw new ResponseTooLargeError('response exceeds 1 MiB limit', { requestId });
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

function requiredString(value, name, requestId) {
  const field = value[name];
  if (typeof field !== 'string' || field.trim() === '') throw new InvalidResponseError(`response field ${name} must be a non-empty string`, { requestId });
  return field;
}

function isRfc3339(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second, offsetHour, offsetMinute] =
    [match[1], match[2], match[3], match[4], match[5], match[6], match[8] ?? '0', match[9] ?? '0'].map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]
    && hour <= 23 && minute <= 59 && second <= 59 && offsetHour <= 23 && offsetMinute <= 59
    && !Number.isNaN(Date.parse(value));
}

function decodeCheckoutSession(value, requestId) {
  const checkoutSessionId = requiredString(value, 'checkout_session_id', requestId);
  const expiresAt = requiredString(value, 'expires_at', requestId);
  const checkoutUrl = requiredString(value, 'checkout_url', requestId);
  if (!isRfc3339(expiresAt)) {
    throw new InvalidResponseError('expires_at must be an RFC 3339 date-time', { requestId });
  }
  let parsedUrl; try { parsedUrl = new URL(checkoutUrl); } catch (cause) {
    throw new InvalidResponseError('checkout_url must be an absolute HTTPS URL', { requestId, cause });
  }
  if (parsedUrl.protocol !== 'https:') throw new InvalidResponseError('checkout_url must be an absolute HTTPS URL', { requestId });
  return Object.freeze({ checkoutSessionId, expiresAt, checkoutUrl });
}

function decodeProblem(value, status, requestId) {
  const type = requiredString(value, 'type', requestId);
  try { new URL(type); } catch (cause) { throw new InvalidResponseError('problem type must be an absolute URI', { requestId, cause }); }
  const title = requiredString(value, 'title', requestId);
  if (!Number.isInteger(value.status) || value.status !== status) throw new InvalidResponseError('problem status must match HTTP status', { requestId });
  const code = requiredString(value, 'code', requestId);
  const traceId = requiredString(value, 'trace_id', requestId);
  if (value.detail !== undefined && typeof value.detail !== 'string') throw new InvalidResponseError('problem detail must be a string', { requestId });
  return { type, title, status, code, traceId, ...(value.detail === undefined ? {} : { detail: value.detail }) };
}

async function decodeResponse(response, expectedStatus) {
  if (!response || !Number.isInteger(response.status) || !response.headers || typeof response.headers.get !== 'function') {
    throw new InvalidResponseError('transport returned an invalid response object');
  }
  const requestId = response.headers.get('x-request-id') ?? '';
  const mediaType = (response.headers.get('content-type') ?? '').split(';', 1)[0].trim().toLowerCase();
  if (mediaType !== 'application/json' && mediaType !== 'application/problem+json') {
    throw new InvalidResponseError('response Content-Type must be JSON', { requestId });
  }
  const bytes = await readBounded(response, requestId);
  let text; let value;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); value = JSON.parse(text); }
  catch (cause) { throw new InvalidResponseError('response is not strict UTF-8 JSON', { requestId, cause }); }
  if (value === null || Array.isArray(value) || typeof value !== 'object') throw new InvalidResponseError('response JSON must be an object', { requestId });
  if (response.status === expectedStatus) {
    if (mediaType !== 'application/json') throw new InvalidResponseError('success response must use application/json', { requestId });
    return Object.freeze({ statusCode: response.status, requestId, data: decodeCheckoutSession(value, requestId) });
  }
  if (response.status >= 400 && response.status <= 599) {
    if (mediaType !== 'application/problem+json') throw new InvalidResponseError('error response must use application/problem+json', { requestId });
    throw new ApiError(decodeProblem(value, response.status, requestId), { requestId });
  }
  throw new InvalidResponseError(`unexpected HTTP status ${response.status}`, { requestId });
}

export function verifyWebhook({ secret, rawBody, signatureHeader, now = Date.now(), toleranceMs = 300_000 }) {
  if (!Buffer.isBuffer(rawBody) || !Buffer.isBuffer(secret) || secret.length < 32
    || typeof signatureHeader !== 'string' || signatureHeader.length > 4096
    || !Number.isFinite(now) || !Number.isFinite(toleranceMs) || toleranceMs < 0
    || now < 0 || timestampOutOfSafeRange(now)) return false;
  const parts = new Map();
  for (const item of signatureHeader.split(',')) {
    const separator = item.indexOf('=');
    if (separator <= 0) return false;
    const key = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();
    if (!/^[A-Za-z0-9_]{1,16}$/.test(key) || !value || !['t', 'v1'].includes(key)
      || parts.has(key) || /\s/.test(value)) return false;
    parts.set(key, value);
  }
  if (parts.size !== 2 || !parts.has('t') || !parts.has('v1')
    || !/^\d{1,19}$/.test(parts.get('t')) || !/^[A-Za-z0-9_-]+={0,2}$/.test(parts.get('v1'))) return false;
  const timestamp = Number(parts.get('t'));
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || timestamp > Number.MAX_SAFE_INTEGER / 1000
    || Math.abs(now - timestamp * 1000) > toleranceMs) return false;
  let supplied; try { supplied = Buffer.from(parts.get('v1'), 'base64url'); } catch { return false; }
  if (supplied.length !== 32) return false;
  const expected = createHmac('sha256', secret).update(`${timestamp}.`).update(rawBody).digest();
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function timestampOutOfSafeRange(value) {
  return value > Number.MAX_SAFE_INTEGER;
}
