# Alipay connector

`AlipayAdapter` implements certificate-mode request fields, public RSA2 canonical signing/verification, Web/WAP/App/QR/mini-program actions, query, close, refund, and bill URL operations. Return URLs use a registered-host allowlist; verified notifications are bound to app, seller, order, exact CNY minor amount, status, and certificate validity.

Private keys and certificate-derived public keys are runtime inputs. Official application onboarding, product activation, certificate-chain provisioning, callbacks, bills, and sandbox certification remain `NOT_RUN`.
