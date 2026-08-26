package com.elmpay.payment;

import com.elmpay.money.Money;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record CreateIntentCommand(UUID tenantId, UUID projectId, UUID merchantId,
        String externalReference, Money amount, Set<String> allowedMethods,
        ConfirmationMode confirmationMode, String region, Duration timeToLive,
        String idempotencyKey) {
    public CreateIntentCommand {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(merchantId, "merchantId");
        Objects.requireNonNull(externalReference, "externalReference");
        Objects.requireNonNull(amount, "amount");
        Objects.requireNonNull(allowedMethods, "allowedMethods");
        Objects.requireNonNull(confirmationMode, "confirmationMode");
        Objects.requireNonNull(region, "region");
        Objects.requireNonNull(timeToLive, "timeToLive");
        Objects.requireNonNull(idempotencyKey, "idempotencyKey");
        allowedMethods = allowedMethods.stream().map(value -> value.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
        if (externalReference.isBlank() || amount.amountMinor() <= 0 || allowedMethods.isEmpty()
                || region.isBlank() || timeToLive.compareTo(Duration.ofMinutes(1)) < 0
                || timeToLive.compareTo(Duration.ofHours(24)) > 0) {
            throw new IllegalArgumentException("invalid payment intent command");
        }
    }
}
