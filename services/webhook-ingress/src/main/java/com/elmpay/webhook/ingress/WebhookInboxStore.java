package com.elmpay.webhook.ingress;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/** Transactional store seam kept package-private so processor behavior is deterministic in tests. */
interface WebhookInboxStore {
    enum ApplyOutcome { PROCESSED, DUPLICATE_EFFECT }

    record Claim(WebhookEffectPort.Effect effect, String workerId, Instant leaseExpiresAt) {
        public Claim {
            Objects.requireNonNull(effect, "effect");
            if (workerId == null || !workerId.matches("[A-Za-z0-9_.:-]{1,128}")) {
                throw new IllegalArgumentException("workerId has an invalid format");
            }
            Objects.requireNonNull(leaseExpiresAt, "leaseExpiresAt");
        }
    }

    int terminalizeExhausted(String tenantId, Instant now, int maxAttempts);

    Optional<Claim> claim(String tenantId, String workerId, Instant now, Duration leaseTtl,
            int maxAttempts);

    ApplyOutcome apply(Claim claim, Instant now, WebhookEffectPort effectPort);

    boolean recordFailure(Claim claim, Instant failedAt, Instant nextAttemptAt,
            boolean terminal, String failureCode, String diagnosticSummary);

    class StoreException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        StoreException(String message) {
            super(message);
        }

        StoreException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    final class LeaseLostException extends StoreException {
        private static final long serialVersionUID = 1L;

        LeaseLostException(String message) {
            super(message);
        }
    }

    final class IdentityConflictException extends StoreException {
        private static final long serialVersionUID = 1L;

        IdentityConflictException(String message) {
            super(message);
        }
    }

    final class DispatchException extends StoreException {
        private static final long serialVersionUID = 1L;
        private final String failureCode;
        private final boolean permanent;

        DispatchException(String failureCode, boolean permanent, Throwable cause) {
            super("webhook effect dispatcher rejected the verified event", cause);
            this.failureCode = failureCode;
            this.permanent = permanent;
        }

        String failureCode() {
            return failureCode;
        }

        boolean permanent() {
            return permanent;
        }
    }
}
