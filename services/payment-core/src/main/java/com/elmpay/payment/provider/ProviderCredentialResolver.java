package com.elmpay.payment.provider;

import com.elmpay.security.SecretReference;
import java.util.UUID;

/** KMS/Vault boundary. Implementations must return the exact requested immutable version. */
public interface ProviderCredentialResolver {
    boolean configured();

    ProviderCredential resolve(UUID tenantId, UUID providerAccountId,
            SecretReference reference, String credentialVersion);
}
