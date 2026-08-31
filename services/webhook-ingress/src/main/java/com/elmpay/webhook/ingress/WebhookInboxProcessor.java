package com.elmpay.webhook.ingress;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;

/** Claims and applies one verified provider webhook with bounded retry and fencing. */
public final class WebhookInboxProcessor {
    public enum Outcome {
        IDLE,
        PROCESSED,
        DUPLICATE_EFFECT,
        RETRY_SCHEDULED,
        TERMINAL_FAILURE,
        LEASE_LOST
    }

    public record Policy(Duration leaseTtl, Duration baseBackoff, Duration maxBackoff,
            int maxAttempts) {
        public Policy {
            requirePositive(leaseTtl, "leaseTtl");
            requirePositive(baseBackoff, "baseBackoff");
            requirePositive(maxBackoff, "maxBackoff");
            if (maxBackoff.compareTo(baseBackoff) < 0) {
                throw new IllegalArgumentException("maxBackoff must not be below baseBackoff");
            }
            if (maxAttempts <= 0 || maxAttempts > 100) {
                throw new IllegalArgumentException("maxAttempts must be between 1 and 100");
            }
        }

        private static void requirePositive(Duration value, String field) {
            Objects.requireNonNull(value, field);
            if (value.isZero() || value.isNegative()) {
                throw new IllegalArgumentException(field + " must be positive");
            }
        }
    }

    private final WebhookInboxStore store;
    private final WebhookEffectPort effectPort;
    private final Clock clock;
    private final Policy policy;

    public WebhookInboxProcessor(DataSource dataSource, WebhookEffectPort effectPort, Clock clock,
            Policy policy) {
        this(new JdbcWebhookInboxStore(dataSource), effectPort, clock, policy);
    }

    WebhookInboxProcessor(WebhookInboxStore store, WebhookEffectPort effectPort, Clock clock,
            Policy policy) {
        this.store = Objects.requireNonNull(store, "store");
        this.effectPort = Objects.requireNonNull(effectPort, "effectPort");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    /**
     * Processes at most one row for the supplied tenant. Callers enumerate only tenants assigned
     * to this worker; the store also sets PostgreSQL tenant RLS in every transaction.
     */
    public Outcome runOnce(String tenantId, String workerId) {
        requireTenantId(tenantId);
        requireWorkerId(workerId);
        Instant now = clock.instant();
        if (store.terminalizeExhausted(tenantId, now, policy.maxAttempts()) > 0) {
            return Outcome.TERMINAL_FAILURE;
        }
        Optional<WebhookInboxStore.Claim> claimed = store.claim(tenantId, workerId, now,
                policy.leaseTtl(), policy.maxAttempts());
        if (claimed.isEmpty()) {
            return Outcome.IDLE;
        }
        WebhookInboxStore.Claim claim = claimed.orElseThrow();
        try {
            WebhookInboxStore.ApplyOutcome applied = store.apply(claim, now, effectPort);
            return applied == WebhookInboxStore.ApplyOutcome.PROCESSED
                    ? Outcome.PROCESSED : Outcome.DUPLICATE_EFFECT;
        } catch (WebhookInboxStore.LeaseLostException failure) {
            return Outcome.LEASE_LOST;
        } catch (RuntimeException failure) {
            boolean permanent = failure instanceof WebhookInboxStore.IdentityConflictException
                    || (failure instanceof WebhookInboxStore.DispatchException dispatch
                            && dispatch.permanent());
            int attempt = claim.effect().processingAttempt();
            boolean terminal = permanent || attempt >= policy.maxAttempts();
            Duration backoff = backoff(attempt);
            String code = failureCode(failure);
            String diagnostic = diagnostic(code, claim.effect().verificationDigest(), attempt);
            boolean recorded = store.recordFailure(claim, now, now.plus(backoff), terminal, code,
                    diagnostic);
            if (!recorded) {
                return Outcome.LEASE_LOST;
            }
            return terminal ? Outcome.TERMINAL_FAILURE : Outcome.RETRY_SCHEDULED;
        }
    }

    private Duration backoff(int attempt) {
        Duration result = policy.baseBackoff();
        for (int index = 1; index < attempt; index++) {
            try {
                result = result.multipliedBy(2);
            } catch (ArithmeticException overflow) {
                return policy.maxBackoff();
            }
            if (result.compareTo(policy.maxBackoff()) >= 0) {
                return policy.maxBackoff();
            }
        }
        return result;
    }

    private static String failureCode(RuntimeException failure) {
        if (failure instanceof WebhookInboxStore.DispatchException dispatch) {
            return dispatch.failureCode();
        }
        String type = failure.getClass().getSimpleName();
        return type.matches("[A-Za-z0-9_.-]{1,80}") ? type : "WebhookProcessingFailure";
    }

    private static String diagnostic(String code, String verificationDigest, int attempt) {
        return "failure=" + code + ";verification=" + verificationDigest.substring(0, 16)
                + ";attempt=" + attempt;
    }

    private static void requireTenantId(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{3,64}")) {
            throw new IllegalArgumentException("tenantId has an invalid format");
        }
    }

    private static void requireWorkerId(String value) {
        if (value == null || !value.matches("[A-Za-z0-9_.:-]{1,128}")) {
            throw new IllegalArgumentException("workerId has an invalid format");
        }
    }
}
