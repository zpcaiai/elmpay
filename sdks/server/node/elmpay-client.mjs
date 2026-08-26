import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

export class ElmpayClient {
  constructor({ baseUrl, bearerToken, projectId, timeoutMs = 5000, maximumAttempts = 3, transport = fetch }) {
    const url = new URL(baseUrl); if (url.protocol !== 'https:') throw new TypeError('baseUrl must use HTTPS');
    if (!bearerToken) throw new TypeError('bearerToken required');
    if (!/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(projectId ?? '')) throw new TypeError('projectId required');
    if (maximumAttempts < 1 || maximumAttempts > 5) throw new RangeError('maximumAttempts must be 1..5');
    Object.assign(this, { baseUrl: url, bearerToken, projectId, timeoutMs, maximumAttempts, transport });
  }
  async createCheckoutSession(request, idempotencyKey = randomUUID()) {
    if (!Number.isSafeInteger(request.amount) || request.amount <= 0) throw new TypeError('amount must be a positive safe integer');
    const body = { business_order_no: request.businessOrderNo, amount: request.amount, currency: request.currency,
      ...(request.returnRouteId ? { return_route_id: request.returnRouteId } : {}) };
    return this.#send('POST', '/v1/checkout-sessions', body, idempotencyKey);
  }
  async getCheckoutSession(id) { return this.#send('GET', `/v1/checkout-sessions/${encodeURIComponent(id)}`); }
  async confirmCheckoutSession(id, request, idempotencyKey = randomUUID()) {
    return this.#send('POST', `/v1/checkout-sessions/${encodeURIComponent(id)}/confirm`, {
      payment_method_type: request.paymentMethodType,
      ...(request.paymentMethodReference ? { payment_method_reference: request.paymentMethodReference } : {}),
      ...(request.fingerprint ? { fingerprint: request.fingerprint } : {}),
    }, idempotencyKey);
  }
  async #send(method, path, body, idempotencyKey) {
    const retrySafe = method === 'GET' || Boolean(idempotencyKey);
    for (let attempt = 1; attempt <= this.maximumAttempts; attempt++) {
      try {
        const response = await this.transport(new URL(path, this.baseUrl), { method, redirect: 'manual', signal: AbortSignal.timeout(this.timeoutMs),
          headers: { accept: 'application/json', authorization: `Bearer ${this.bearerToken}`,
            'x-project-id': this.projectId,
            ...(body ? { 'content-type': 'application/json' } : {}), ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}) },
          body: body ? JSON.stringify(body) : undefined });
        const result = { statusCode: response.status, requestId: response.headers.get('x-request-id') ?? '', body: await response.text() };
        if (!retrySafe || attempt === this.maximumAttempts || ![408, 429].includes(response.status) && response.status < 500) return result;
      } catch (error) { if (!retrySafe || attempt === this.maximumAttempts) throw error; }
      await new Promise(resolve => setTimeout(resolve, Math.min(1000, 100 * 2 ** (attempt - 1))));
    }
    throw new Error('unreachable');
  }
}

export function verifyWebhook({ secret, rawBody, signatureHeader, now = Date.now(), toleranceMs = 300_000 }) {
  if (!Buffer.isBuffer(rawBody) || !Buffer.isBuffer(secret) || secret.length < 32) return false;
  const parts = Object.fromEntries(signatureHeader.split(',').map(v => v.trim().split('=', 2)));
  const timestamp = Number(parts.t); if (!Number.isSafeInteger(timestamp) || Math.abs(now - timestamp * 1000) > toleranceMs) return false;
  let supplied; try { supplied = Buffer.from(parts.v1 ?? '', 'base64url'); } catch { return false; }
  const expected = createHmac('sha256', secret).update(`${timestamp}.`).update(rawBody).digest();
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}
