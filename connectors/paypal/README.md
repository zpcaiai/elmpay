# PayPal connector

`PayPalAdapter` implements OAuth token caching, Orders v2 create/query/authorize/capture, refunds, subscriptions, dispute evidence, stable `PayPal-Request-Id`, and bounded execution with `UNKNOWN` outcomes. Webhooks are accepted only after PayPal's official `verify-webhook-signature` endpoint succeeds and merchant/object/amount/currency bindings match.

Client credentials and webhook IDs are runtime inputs. Sandbox buyer/business accounts, product permissions, real webhook delivery, and official certification remain `NOT_RUN`.
