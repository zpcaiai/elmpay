package com.elmpay.payment;

import java.time.Instant;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;

/** Explicit intent lifecycle. Client redirects and merchant requests cannot establish success. */
public final class PaymentStateMachine {
    private static final Map<IntentState, EnumSet<IntentState>> ALLOWED = allowedTransitions();

    public PaymentIntent transition(PaymentIntent intent, IntentState target,
            AuthoritySource authority, Instant at) {
        Objects.requireNonNull(intent, "intent");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(authority, "authority");
        Objects.requireNonNull(at, "at");
        if (target == IntentState.AUTHORIZED || target == IntentState.CAPTURED) {
            requireAuthority(authority);
        }
        if (!ALLOWED.getOrDefault(intent.state(), EnumSet.noneOf(IntentState.class)).contains(target)) {
            throw new PaymentCoreException("STATE_TRANSITION_NOT_ALLOWED",
                    "payment intent cannot transition from " + intent.state() + " to " + target);
        }
        return intent.withState(target, at);
    }

    public PaymentIntent recordCapture(PaymentIntent intent, long capturedAmountMinor,
            boolean finalCapture, AuthoritySource authority, Instant at) {
        requireAuthority(authority);
        boolean immediateFullCapture = (intent.state() == IntentState.CREATED
                || intent.state() == IntentState.REQUIRES_ACTION)
                && finalCapture && capturedAmountMinor == intent.amount().amountMinor();
        if ((!immediateFullCapture && intent.state() != IntentState.AUTHORIZED)
                || capturedAmountMinor <= intent.capturedAmountMinor()
                || capturedAmountMinor > intent.amount().amountMinor()) {
            throw new PaymentCoreException("CAPTURE_NOT_ALLOWED",
                    "capture must advance an authorized intent without exceeding its amount");
        }
        if (finalCapture != (capturedAmountMinor == intent.amount().amountMinor())) {
            throw new PaymentCoreException("CAPTURE_FINALITY_INVALID",
                    "final capture must equal the immutable intent amount");
        }
        return intent.withCapture(capturedAmountMinor, finalCapture, at);
    }

    public PaymentIntent expire(PaymentIntent intent, Instant at) {
        if (at.isBefore(intent.expiresAt())) {
            throw new PaymentCoreException("INTENT_NOT_EXPIRED", "intent TTL has not elapsed");
        }
        return transition(intent, IntentState.EXPIRED, AuthoritySource.SCHEDULER, at);
    }

    private static void requireAuthority(AuthoritySource authority) {
        if (!authority.authoritativeForSuccess()) {
            throw new PaymentCoreException("UNTRUSTED_SUCCESS_SOURCE",
                    "successful money state requires a verified provider or reconciliation source");
        }
    }

    private static Map<IntentState, EnumSet<IntentState>> allowedTransitions() {
        Map<IntentState, EnumSet<IntentState>> result = new EnumMap<>(IntentState.class);
        result.put(IntentState.CREATED, EnumSet.of(IntentState.REQUIRES_ACTION,
                IntentState.AUTHORIZED, IntentState.CAPTURED, IntentState.FAILED,
                IntentState.CANCELED, IntentState.EXPIRED));
        result.put(IntentState.REQUIRES_ACTION, EnumSet.of(IntentState.AUTHORIZED,
                IntentState.CAPTURED, IntentState.FAILED, IntentState.CANCELED,
                IntentState.EXPIRED));
        result.put(IntentState.AUTHORIZED,
                EnumSet.of(IntentState.CAPTURED, IntentState.FAILED,
                        IntentState.CANCELED, IntentState.EXPIRED));
        return Map.copyOf(result);
    }
}
