package com.elmpay.scheduler;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Atomic lease state machine with monotonically increasing fencing tokens.
 * A production adapter must persist the same compare-and-set semantics in a
 * strongly consistent store; stale tokens must also be checked by each sink.
 */
public final class FencedLeaseManager {
    public record JobKey(String tenantId, String jobName) {
        public JobKey {
            requireText(tenantId, "tenantId");
            requireText(jobName, "jobName");
        }
    }

    public record Lease(JobKey key, String holder, long fencingToken, Instant expiresAt) {
        public Lease {
            Objects.requireNonNull(key, "key");
            requireText(holder, "holder");
            if (fencingToken <= 0) {
                throw new IllegalArgumentException("fencingToken must be positive");
            }
            Objects.requireNonNull(expiresAt, "expiresAt");
        }
    }

    private final Clock clock;
    private final Map<JobKey, Lease> active = new HashMap<>();
    private final Map<JobKey, Long> sequences = new HashMap<>();

    public FencedLeaseManager(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public synchronized Optional<Lease> tryAcquire(JobKey key, String holder, Duration ttl) {
        Objects.requireNonNull(key, "key");
        requireText(holder, "holder");
        requirePositive(ttl);
        Instant now = clock.instant();
        Lease current = active.get(key);
        if (current != null && current.expiresAt().isAfter(now)) {
            return Optional.empty();
        }
        long nextToken = Math.addExact(sequences.getOrDefault(key, 0L), 1L);
        sequences.put(key, nextToken);
        Lease acquired = new Lease(key, holder, nextToken, now.plus(ttl));
        active.put(key, acquired);
        return Optional.of(acquired);
    }

    public synchronized Lease renew(Lease lease, Duration ttl) {
        Objects.requireNonNull(lease, "lease");
        requirePositive(ttl);
        assertCurrent(lease);
        Lease renewed = new Lease(lease.key(), lease.holder(), lease.fencingToken(), clock.instant().plus(ttl));
        active.put(lease.key(), renewed);
        return renewed;
    }

    public synchronized void assertCurrent(Lease lease) {
        Objects.requireNonNull(lease, "lease");
        Lease current = active.get(lease.key());
        if (current == null
                || current.fencingToken() != lease.fencingToken()
                || !current.holder().equals(lease.holder())
                || !current.expiresAt().isAfter(clock.instant())) {
            throw new StaleFencingTokenException("lease is missing, expired, or superseded");
        }
    }

    public synchronized void release(Lease lease) {
        assertCurrent(lease);
        active.remove(lease.key());
    }

    public synchronized long latestToken(JobKey key) {
        Objects.requireNonNull(key, "key");
        return sequences.getOrDefault(key, 0L);
    }

    public static final class StaleFencingTokenException extends IllegalStateException {
        @java.io.Serial
        private static final long serialVersionUID = 1L;

        public StaleFencingTokenException(String message) {
            super(message);
        }
    }

    private static void requirePositive(Duration ttl) {
        Objects.requireNonNull(ttl, "ttl");
        if (ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("lease ttl must be positive");
        }
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
