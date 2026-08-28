package com.elmpay.payment.checkout;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Tenant-scoped runtime boundary for checkout method eligibility. */
@FunctionalInterface
public interface CheckoutCapabilitySource {
    record Request(UUID tenantId, UUID projectId, UUID merchantId, Set<String> signedMethods,
            long amountMinor, String currency, String region, String deviceClass, Instant now) {
        public Request {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(merchantId, "merchantId");
            if (signedMethods == null || signedMethods.isEmpty()) {
                throw new IllegalArgumentException("signed checkout methods are required");
            }
            signedMethods = signedMethods.stream().map(value -> value.toLowerCase(Locale.ROOT))
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (amountMinor <= 0) {
                throw new IllegalArgumentException("checkout amount must be positive");
            }
            currency = required(currency, "currency").toUpperCase(Locale.ROOT);
            region = required(region, "region").toUpperCase(Locale.ROOT);
            deviceClass = required(deviceClass, "deviceClass").toUpperCase(Locale.ROOT);
            Objects.requireNonNull(now, "now");
        }

        private static String required(String value, String name) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(name + " is required");
            }
            return value;
        }
    }

    List<CapabilityResolver.Decision> resolve(Request request);
}
