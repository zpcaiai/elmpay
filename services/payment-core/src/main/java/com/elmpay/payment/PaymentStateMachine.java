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

    /**
     * Record a cumulative capture.
     *
     * <p>The refusal codes are part of the B34 capture-lifecycle contract and are replayed from
     * {@code contracts/capture/vectors.json}: an implementation that refuses the right inputs for
     * the wrong reason is not interchangeable with the reference, and the reason is what an
     * operator reads at 3am.
     */
    public PaymentIntent recordCapture(PaymentIntent intent, long capturedAmountMinor,
            boolean finalCapture, AuthoritySource authority, Instant at) {
        requireAuthority(authority);
        boolean immediateFullCapture = (intent.state() == IntentState.CREATED
                || intent.state() == IntentState.REQUIRES_ACTION)
                && finalCapture && capturedAmountMinor == intent.amount().amountMinor();
        if (intent.state().terminal()) {
            throw new PaymentCoreException("AUTH_NOT_ACTIVE",
                    "authorization is " + intent.state()
                    + "; a terminal authorization takes no further capture");
        }
        if (capturedAmountMinor <= intent.capturedAmountMinor()) {
            throw new PaymentCoreException("CAPTURE_AMOUNT_NOT_POSITIVE",
                    "a capture must add a positive amount to the " + intent.capturedAmountMinor()
                    + " already captured");
        }
        if (capturedAmountMinor > intent.amount().amountMinor()) {
            throw new PaymentCoreException("CAPTURE_EXCEEDS_AUTHORIZED",
                    "cumulative capture " + capturedAmountMinor + " exceeds the authorized "
                    + intent.amount().amountMinor());
        }
        if (!immediateFullCapture && intent.state() != IntentState.AUTHORIZED) {
            throw new PaymentCoreException("AUTH_NOT_ACTIVE",
                    "a partial capture requires an authorization; " + intent.state()
                    + " has none to draw on");
        }
        if (finalCapture != (capturedAmountMinor == intent.amount().amountMinor())) {
            throw new PaymentCoreException("CAPTURE_FINALITY_INVALID",
                    "final capture must equal the immutable intent amount");
        }
        return intent.withCapture(capturedAmountMinor, finalCapture, at);
    }

    /**
     * Release the whole authorization. Legal only before anything was captured.
     *
     * <p>The guard lives here rather than in the service so that all three ways out of an active
     * authorization — captured in full, closed at a partial amount, voided at zero — are decided
     * in one place. Split across layers, the set stops being checkable.
     */
    public PaymentIntent voidAuthorization(PaymentIntent intent, AuthoritySource authority,
            Instant at) {
        requireAuthority(authority);
        if (intent.state() != IntentState.AUTHORIZED) {
            throw new PaymentCoreException("AUTH_NOT_ACTIVE",
                    "authorization is " + intent.state() + "; only an active one can be voided");
        }
        if (intent.capturedAmountMinor() > 0) {
            throw new PaymentCoreException("VOID_AFTER_CAPTURE",
                    "money has already been captured; release the remainder with close and "
                    + "return the captured part with a refund");
        }
        return transition(intent, IntentState.CANCELED, authority, at);
    }

    /**
     * Give up the uncaptured remainder of a partial capture.
     *
     * <p>Without this operation the remainder is released only when the authorization expires,
     * which leaves the payer's funds held for the provider's whole authorization window and
     * leaves the platform unable to state how much of its authorized exposure is still live.
     * A close therefore ends the capture phase at the amount actually taken: the intent reaches
     * {@code CAPTURED} with {@code capturedAmountMinor < amount}, and that combination is
     * reachable only through here — never by simply abandoning an authorization.
     */
    public PaymentIntent closeAfterPartialCapture(PaymentIntent intent, AuthoritySource authority,
            Instant at) {
        Objects.requireNonNull(intent, "intent");
        Objects.requireNonNull(at, "at");
        requireAuthority(authority);
        if (intent.state() != IntentState.AUTHORIZED) {
            throw new PaymentCoreException("AUTH_NOT_ACTIVE",
                    "authorization is " + intent.state() + "; only an active one can be closed");
        }
        if (intent.capturedAmountMinor() <= 0) {
            throw new PaymentCoreException("CLOSE_WITHOUT_CAPTURE",
                    "nothing has been captured; releasing the whole hold is a void, not a close");
        }
        return intent.withCapture(intent.capturedAmountMinor(), true, at);
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
