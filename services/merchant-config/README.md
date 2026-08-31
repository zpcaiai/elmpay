# Merchant Config service

The Java module provides tenant/project-bound provider accounts, external secret references,
capability filtering, deterministic routing and a PostgreSQL read model. Routing fails closed when
no active account satisfies the immutable payment constraints. Production activation still needs
provider callback and test-transaction evidence plus independent approval.

Tenant lifecycle transitions do not accept KYB, contract, settlement, retention or KEK-destruction
booleans. Authorities issue short-lived Ed25519 `AuthorityEvidenceReceipt` values bound to the
exact tenant, evidence type, authority, decision reference, payload digest, key, nonce and time
window. `TenantEvidenceVerifier` pins type-scoped authority keys and creates opaque
`VerifiedTenantEvidence`; its constructor is not exposed. PostgreSQL stores global key/nonce replay
state and per-transition authority/reference/payload/receipt digests under forced tenant RLS. The
forward-only `V101__tenant_authority_evidence.sql` migration leaves historical evidence flags in
place but the replacement lifecycle trigger never accepts them for a new transition.
