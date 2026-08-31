package com.elmpay.gateway;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Durable append-only audit port for provider SDK configuration authorization. */
@FunctionalInterface
public interface CheckoutProviderSdkAudit {
    record Receipt(UUID auditId, UUID tenantId, UUID projectId, UUID merchantId,
            String checkoutSessionId, UUID paymentIntentId, UUID providerAccountId, String method,
            String provider, String actorType, String actorId, String requestId,
            String channelDigest, String businessOrderDigest, String checkoutSnapshotDigest,
            String configurationDigest, String capabilityVersion, String policyVersion,
            Instant sessionExpiresAt, Instant createdAt) {
        public Receipt {
            Objects.requireNonNull(auditId, "auditId");
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(merchantId, "merchantId");
            Objects.requireNonNull(paymentIntentId, "paymentIntentId");
            Objects.requireNonNull(providerAccountId, "providerAccountId");
            if (!UUID.fromString(checkoutSessionId).toString().equals(checkoutSessionId)
                    || !method.matches("[a-z0-9][a-z0-9._-]{0,63}")
                    || !provider.matches("[a-z0-9][a-z0-9._-]{0,63}")
                    || !actorType.matches("checkout_session|oauth_client")
                    || actorId.isBlank() || actorId.length() > 160
                    || !requestId.matches("[A-Za-z0-9._:-]{8,128}")) {
                throw new IllegalArgumentException("provider SDK audit identity is invalid");
            }
            for (String digest : java.util.List.of(channelDigest, businessOrderDigest,
                    checkoutSnapshotDigest, configurationDigest)) {
                if (digest == null || !digest.matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("provider SDK audit digest is invalid");
                }
            }
            if (capabilityVersion == null || capabilityVersion.isBlank()
                    || capabilityVersion.length() > 128 || policyVersion == null
                    || policyVersion.isBlank() || policyVersion.length() > 128
                    || sessionExpiresAt == null || createdAt == null
                    || !createdAt.isBefore(sessionExpiresAt)) {
                throw new IllegalArgumentException("provider SDK audit timing or version is invalid");
            }
        }
    }

    void append(Receipt receipt);
}
