import assert from 'node:assert/strict';
import { test } from 'node:test';
import { OfficialProviderHandlers, stripeOfficialAdapter } from '../public/provider-handlers.mjs';

test('official Stripe hosted element returns only an opaque PSP reference', async () => {
  const card = Object.freeze({ hosted: true });
  const stripe = {
    async createPaymentMethod(input) {
      assert.equal(input.card, card);
      return { paymentMethod: { id: 'pm_provider_123', card: { fingerprint: 'fp_123' } } };
    },
    async handleNextAction() { return {}; },
  };
  const handlers = new OfficialProviderHandlers({
    adapters: { stripe_card: stripeOfficialAdapter(stripe, { getElement: () => card }) },
    allowedRedirectOrigins: ['https://payments.example/'],
  });
  assert.deepEqual(await handlers.tokenize({ method: 'stripe_card', checkoutSessionId: 's1' }), {
    paymentMethodReference: 'psp://stripe/pm_provider_123', fingerprint: 'fp_123',
  });
});

test('raw PAN, unregistered methods and unallowlisted redirects fail before API use', async () => {
  let actionCalled = false;
  const adapter = Object.freeze({ integrationType: 'official-provider-sdk',
    async tokenize() { return { paymentMethodReference: 'psp://unsafe/4111111111111111' }; },
    async handleAction() { actionCalled = true; } });
  const handlers = new OfficialProviderHandlers({ adapters: { card: adapter },
    allowedRedirectOrigins: ['https://payments.example/'] });
  await assert.rejects(handlers.tokenize({ method: 'card', checkoutSessionId: 's1' }), /opaque/);
  await assert.rejects(handlers.tokenize({ method: 'paypal', checkoutSessionId: 's1' }), /unavailable/);
  await assert.rejects(handlers.handle({ action: 'redirect', method: 'card',
    redirect_url: 'https://evil.example/collect' }, { checkoutSessionId: 's1' }), /allowlisted/);
  assert.equal(actionCalled, false);
});

test('global installation exposes immutable tokenizer and action boundaries', () => {
  const adapter = Object.freeze({ integrationType: 'official-provider-sdk',
    async tokenize() { return { paymentMethodReference: 'psp://provider/reference' }; },
    async handleAction() {} });
  const target = {};
  new OfficialProviderHandlers({ adapters: { card: adapter } }).install(target);
  assert.equal(typeof target.ElmPayPaymentMethodTokenizer.tokenize, 'function');
  assert.equal(Object.isFrozen(target.ElmPayPaymentMethodTokenizer), true);
  assert.throws(() => Object.defineProperty(target, 'ElmPayPaymentMethodTokenizer', { value: {} }));
});
