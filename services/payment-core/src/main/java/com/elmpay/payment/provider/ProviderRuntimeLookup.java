package com.elmpay.payment.provider;

import com.elmpay.provider.RefundCommand;
import java.util.Objects;
import java.util.UUID;

/** Server-owned payment facts used to bind provider callbacks and follow-up operations. */
public interface ProviderRuntimeLookup {
    record PaymentFacts(String businessReference, String providerObjectId, long amountMinor,
            String currency) {
        public PaymentFacts {
            requireText(businessReference, "businessReference");
            providerObjectId = providerObjectId == null ? "" : providerObjectId;
            if (providerObjectId.length() > 256 || amountMinor <= 0
                    || currency == null || !currency.matches("[A-Z]{3}")) {
                throw new IllegalArgumentException("invalid provider payment facts");
            }
        }

        private static void requireText(String value, String field) {
            if (value == null || value.isBlank() || value.length() > 256) {
                throw new IllegalArgumentException(field + " is invalid");
            }
        }
    }

    PaymentFacts byBusinessReference(UUID tenantId, UUID providerAccountId, String provider,
            String businessReference);

    PaymentFacts byProviderObject(UUID tenantId, UUID providerAccountId, String provider,
            String providerObjectId);

    default long originalAmountMinor(RefundCommand command, String provider) {
        Objects.requireNonNull(command, "command");
        return byProviderObject(command.context().tenantId(),
                command.context().merchantAccountId(), provider,
                command.providerPaymentId()).amountMinor();
    }

    String refundBusinessReference(UUID tenantId, UUID providerAccountId, String provider,
            String providerRefundId, String refundReference);
}
