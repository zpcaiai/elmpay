package com.elmpay.risk.identity;

/** Durable identity command port. Implementations must apply each requestId idempotently. */
public interface IdentityMutationPort {
    /** Credential rotation and all prior-session revocation must commit atomically. */
    void changeCredentialAndRevokeSessions(IdentityMutationCommand command);

    void addPaymentMethod(IdentityMutationCommand command);

    void elevatePrivilege(IdentityMutationCommand command);
}
