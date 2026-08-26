# Stripe connector

`StripeAdapter` implements token-reference-only PaymentIntent/SetupIntent operations, stable idempotency headers, query/refund/dispute operations, subscription/meter/portal operations, raw-body webhook HMAC verification, overlap secret rotation, and stale-event detection. PAN/CVV-like inputs are rejected before transport.

API and webhook secrets are runtime inputs. Stripe-hosted UI, account configuration, CLI fixtures, SCA browser/device runs, Billing/Tax setup, and official test-mode certification remain `NOT_RUN`.
