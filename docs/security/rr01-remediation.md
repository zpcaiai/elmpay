# RR-01 local KMS envelope control remediation

`RR-01` originally tracked the gap between `kms://` / `vault://` secret references and KMS/HSM envelope-authenticated provider credential resolution.

## Implemented runtime controls

- Verified commit: `39c83e1c21f9b97d250af5daa51e7c5c59c6bff5`.
- `HttpsProviderCredentialResolver` (`services/payment-core/src/main/java/com/elmpay/payment/provider/HttpsProviderCredentialResolver.java`) integrates `EnvelopeEncryptionService` (`libs/security/src/main/java/com/elmpay/security/EnvelopeEncryptionService.java`) and `HttpsKmsClient` (`libs/security/src/main/java/com/elmpay/security/HttpsKmsClient.java`).
- When a `kms://` provider credential reference is resolved with KMS envelope encryption configured, plaintext `material.*` fields are rejected fail-closed (`kms:// provider credential lease requires KMS envelope material`).
- Every `envelope.<field>.*` record is bound to `keyReference == reference.uri()`, unwrapped via `HttpsKmsClient.unwrapDataKey` (`v1/data-keys/unwrap`) with short-lived data-key freshness (`1..30s`), and decrypted via `AES/GCM/NoPadding` (128-bit authentication tag) using canonical AAD bound to `tenantId`, `resourceId` (`providerAccountId`), `purpose` (`provider_credential:<field>`), `secretReference`, and `credentialVersion`.
- All intermediate wrapped keys, nonces, ciphertexts, AAD digests, and plaintext buffers are zeroized in `finally` blocks, and lease revocation on `SecretMaterialProviderCredential.close()` wipes the in-memory secret material.
- External production HSM hardware ceremony and live PSP production credential provisioning remain governed by `B20` / `B122` / `B127` external release gates.
