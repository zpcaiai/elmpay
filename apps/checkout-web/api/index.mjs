import { configFromEnvironment, createHandler } from '../src/server.mjs';
import { ProviderSdkPolicy } from '../src/provider-sdk-policy.mjs';
import { fileURLToPath } from 'node:url';

// This entrypoint never enables the local sandbox on a hosted deployment.
// Keep the existing production validator authoritative, including read-only
// mTLS mounts and the shared provider-frame signing key.
let checkout;
try {
  if (process.env.ELMPAY_CHECKOUT_WEB_MODE !== undefined
      && process.env.ELMPAY_CHECKOUT_WEB_MODE !== 'production') {
    throw new Error('hosted checkout requires production mode');
  }
  const configuration = configFromEnvironment({
    ...process.env, ELMPAY_CHECKOUT_WEB_MODE: 'production',
  });
  checkout = createHandler({
    apiBaseUrl: configuration.apiBaseUrl,
    transport: configuration.transport,
    providerSdkPolicy: new ProviderSdkPolicy({
      manifestPath: fileURLToPath(new URL('../security/provider-sdk-allowlist.json', import.meta.url)),
      ticketKey: configuration.providerFrameTicketKey,
    }),
  });
} catch {
  // Configuration errors must never disclose paths, credentials, or TLS details.
  checkout = null;
}

export default async function handler(request, response) {
  if (checkout !== null) return checkout(request, response);
  response.writeHead(503, {
    'content-type': 'application/problem+json; charset=utf-8',
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  }).end(JSON.stringify({
    service: 'checkout-web', status: 'NOT_READY',
    code: 'production_configuration_unavailable',
    message: 'ElmPay checkout is unavailable until its production backend and credentials are configured.',
    certification: 'NOT_CERTIFIED',
  }));
}
