package com.elmpay.payment.checkout;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Selects one tenant-bound provider account that may bootstrap a browser SDK. */
@FunctionalInterface
public interface CheckoutProviderSdkSource {
    record Request(UUID tenantId, UUID projectId, UUID merchantId, String method,
            Set<String> signedMethods, long amountMinor, String currency, String region,
            String deviceClass, Instant now) {
        public Request {
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            Objects.requireNonNull(merchantId, "merchantId");
            method = normalize(method, "method");
            signedMethods = Set.copyOf(Objects.requireNonNull(signedMethods, "signedMethods"));
            if (!signedMethods.contains(method) || amountMinor <= 0
                    || currency == null || !currency.matches("[A-Z]{3}")
                    || region == null || !region.matches("[A-Z]{2}")
                    || deviceClass == null || !deviceClass.matches("[A-Z]{2,16}")) {
                throw new IllegalArgumentException("invalid provider SDK selection request");
            }
            Objects.requireNonNull(now, "now");
        }
    }

    record Selection(UUID providerAccountId, String provider, String method,
            String capabilityVersion) {
        public Selection {
            Objects.requireNonNull(providerAccountId, "providerAccountId");
            provider = normalize(provider, "provider");
            method = normalize(method, "method");
            if (capabilityVersion == null
                    || !capabilityVersion.matches("[A-Za-z0-9._:-]{1,128}")) {
                throw new IllegalArgumentException("invalid capability version");
            }
        }
    }

    Optional<Selection> select(Request request);

    static CheckoutProviderSdkSource disabled() {
        return ignored -> Optional.empty();
    }

    private static String normalize(String value, String field) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")) {
            throw new IllegalArgumentException("invalid " + field);
        }
        return value.toLowerCase(Locale.ROOT);
    }
}
