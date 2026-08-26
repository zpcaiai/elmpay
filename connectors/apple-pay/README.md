# Apple Pay connector

`ApplePayAdapter` validates eligibility and forwards an opaque wallet envelope directly to an approved Stripe or PayPal processor, then zeroizes its internal token copies. It neither decrypts nor stores wallet tokens and rejects raw card fields. `DataSourceApplePayLifecycle` durably tracks verified domains, KMS/HSM/Vault certificate references with overlap rotation, and hashed PSP merchant-token references.

Direct token decryption is intentionally unsupported. Apple Merchant ID/entitlements, domain approval, certificate issuance, PSP enablement, sandbox cards, and real-device certification remain `NOT_RUN`.
