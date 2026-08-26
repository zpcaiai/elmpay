package com.elmpay.payment;

import com.elmpay.money.Money;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Payment fact with an immutable amount, currency, order reference and method constraint snapshot. */
public record PaymentIntent(UUID id, UUID tenantId, UUID projectId, UUID merchantId,
        String externalReference, Money amount, long capturedAmountMinor, long refundedAmountMinor,
        IntentState state, Set<String> allowedMethods, ConfirmationMode confirmationMode,
        String region, String createIdempotencyKey, Instant expiresAt, Instant createdAt,
        Instant updatedAt, long version) {
    public PaymentIntent {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(merchantId, "merchantId");
        Objects.requireNonNull(externalReference, "externalReference");
        Objects.requireNonNull(amount, "amount");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(allowedMethods, "allowedMethods");
        Objects.requireNonNull(confirmationMode, "confirmationMode");
        Objects.requireNonNull(region, "region");
        Objects.requireNonNull(createIdempotencyKey, "createIdempotencyKey");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        allowedMethods = Set.copyOf(allowedMethods);
        if (externalReference.isBlank() || amount.amountMinor() <= 0 || allowedMethods.isEmpty()
                || capturedAmountMinor < 0 || refundedAmountMinor < 0
                || capturedAmountMinor > amount.amountMinor()
                || refundedAmountMinor > capturedAmountMinor || !expiresAt.isAfter(createdAt)
                || version < 0) {
            throw new IllegalArgumentException("invalid payment intent");
        }
    }

    public static PaymentIntent create(CreateIntentCommand command, Clock clock) {
        Instant now = clock.instant();
        return new PaymentIntent(UUID.randomUUID(), command.tenantId(), command.projectId(),
                command.merchantId(), command.externalReference(), command.amount(), 0, 0,
                IntentState.CREATED, command.allowedMethods(), command.confirmationMode(),
                command.region().toUpperCase(Locale.ROOT), command.idempotencyKey(),
                now.plus(command.timeToLive()), now, now, 0);
    }

    public boolean permitsMethod(String method) {
        return allowedMethods.contains(method.toLowerCase(Locale.ROOT));
    }

    public PaymentIntent withState(IntentState next, Instant at) {
        return new PaymentIntent(id, tenantId, projectId, merchantId, externalReference, amount,
                capturedAmountMinor, refundedAmountMinor, next, allowedMethods, confirmationMode,
                region, createIdempotencyKey, expiresAt, createdAt, at, version + 1);
    }

    public PaymentIntent withCapture(long newCapturedAmountMinor, boolean finalCapture, Instant at) {
        IntentState next = finalCapture ? IntentState.CAPTURED : IntentState.AUTHORIZED;
        return new PaymentIntent(id, tenantId, projectId, merchantId, externalReference, amount,
                newCapturedAmountMinor, refundedAmountMinor, next, allowedMethods, confirmationMode,
                region, createIdempotencyKey, expiresAt, createdAt, at, version + 1);
    }

    public PaymentIntent withRefund(long newRefundedAmountMinor, Instant at) {
        return new PaymentIntent(id, tenantId, projectId, merchantId, externalReference, amount,
                capturedAmountMinor, newRefundedAmountMinor, state, allowedMethods, confirmationMode,
                region, createIdempotencyKey, expiresAt, createdAt, at, version + 1);
    }
}
