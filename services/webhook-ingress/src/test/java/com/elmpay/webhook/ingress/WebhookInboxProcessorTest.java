package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class WebhookInboxProcessorTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final Duration LEASE = Duration.ofSeconds(30);
    private static final WebhookInboxProcessor.Policy POLICY =
            new WebhookInboxProcessor.Policy(LEASE, Duration.ofSeconds(2),
                    Duration.ofMinutes(1), 3);

    @Test
    void concurrentWorkersClaimAndApplyOnlyOnce() throws Exception {
        FakeStore store = new FakeStore(effect(1, "tenant-001"));
        AtomicInteger dispatches = new AtomicInteger();
        WebhookInboxProcessor processor = processor(store, Clock.fixed(NOW, ZoneOffset.UTC),
                (connection, effect) -> dispatches.incrementAndGet());
        CountDownLatch start = new CountDownLatch(1);
        try (var workers = Executors.newFixedThreadPool(2)) {
            Future<WebhookInboxProcessor.Outcome> first = workers.submit(() -> {
                start.await();
                return processor.runOnce("tenant-001", "worker-a");
            });
            Future<WebhookInboxProcessor.Outcome> second = workers.submit(() -> {
                start.await();
                return processor.runOnce("tenant-001", "worker-b");
            });
            start.countDown();
            List<WebhookInboxProcessor.Outcome> outcomes = List.of(first.get(), second.get());
            assertEquals(1, outcomes.stream()
                    .filter(outcome -> outcome == WebhookInboxProcessor.Outcome.PROCESSED).count());
            assertEquals(1, outcomes.stream()
                    .filter(outcome -> outcome == WebhookInboxProcessor.Outcome.IDLE).count());
        }
        assertEquals(1, dispatches.get());
    }

    @Test
    void expiredLeaseIsRecoveredWithHigherFence() {
        FakeStore store = new FakeStore(effect(1, "tenant-001"));
        WebhookInboxStore.Claim abandoned = store.claim("tenant-001", "dead-worker", NOW,
                LEASE, 3).orElseThrow();
        MutableClock clock = new MutableClock(NOW.plus(LEASE).plusMillis(1));
        AtomicInteger dispatches = new AtomicInteger();
        WebhookInboxProcessor processor = processor(store, clock,
                (connection, effect) -> dispatches.incrementAndGet());

        assertEquals(WebhookInboxProcessor.Outcome.PROCESSED,
                processor.runOnce("tenant-001", "recovery-worker"));
        assertEquals(1, dispatches.get());
        assertTrue(store.row(1).fencingToken > abandoned.effect().fencingToken());
        assertEquals(2, store.row(1).attempts);
    }

    @Test
    void existingMatchingEffectCommitSkipsDispatcher() {
        FakeStore store = new FakeStore(effect(1, "tenant-001"));
        store.row(1).effectCommitted = true;
        store.row(1).committedDigest = store.row(1).template.verificationDigest();
        AtomicInteger dispatches = new AtomicInteger();

        assertEquals(WebhookInboxProcessor.Outcome.DUPLICATE_EFFECT,
                processor(store, Clock.fixed(NOW, ZoneOffset.UTC),
                        (connection, effect) -> dispatches.incrementAndGet())
                        .runOnce("tenant-001", "worker-a"));
        assertEquals(0, dispatches.get());
        assertEquals(Status.PROCESSED, store.row(1).status);
    }

    @Test
    void dispatcherFailureRollsBackAndRecoversAfterBackoff() {
        FakeStore store = new FakeStore(effect(1, "tenant-001"));
        MutableClock clock = new MutableClock(NOW);
        AtomicInteger calls = new AtomicInteger();
        WebhookInboxProcessor processor = processor(store, clock, (connection, effect) -> {
            if (calls.incrementAndGet() == 1) {
                throw new IllegalStateException("simulated internal dispatcher failure");
            }
        });

        assertEquals(WebhookInboxProcessor.Outcome.RETRY_SCHEDULED,
                processor.runOnce("tenant-001", "worker-a"));
        assertEquals(Status.FAILED, store.row(1).status);
        assertTrue(!store.row(1).effectCommitted);
        assertTrue(store.row(1).lastDiagnostic.matches(
                "failure=IllegalStateException;verification=[0-9a-f]{16};attempt=1"));
        assertEquals(WebhookInboxProcessor.Outcome.IDLE,
                processor.runOnce("tenant-001", "worker-b"));

        clock.advance(Duration.ofSeconds(2));
        assertEquals(WebhookInboxProcessor.Outcome.PROCESSED,
                processor.runOnce("tenant-001", "worker-b"));
        assertEquals(2, calls.get());
        assertTrue(store.row(1).effectCommitted);
        assertEquals(2, store.row(1).attempts);
    }

    @Test
    void maximumAttemptMovesFailureToTerminalState() {
        FakeStore store = new FakeStore(effect(1, "tenant-001"));
        WebhookInboxProcessor processor = new WebhookInboxProcessor(store,
                (connection, effect) -> {
                    throw new IllegalStateException("never persisted in diagnostics");
                }, Clock.fixed(NOW, ZoneOffset.UTC), new WebhookInboxProcessor.Policy(LEASE,
                        Duration.ofSeconds(2), Duration.ofMinutes(1), 1));

        assertEquals(WebhookInboxProcessor.Outcome.TERMINAL_FAILURE,
                processor.runOnce("tenant-001", "worker-a"));
        assertTrue(store.row(1).terminal);
        assertEquals(Status.FAILED, store.row(1).status);
        assertTrue(!store.row(1).lastDiagnostic.contains("never persisted"));
    }

    @Test
    void permanentDispatcherRejectionIsQuarantinedWithoutRetry() {
        FakeStore store = new FakeStore(effect(1, "tenant-001"));
        WebhookInboxProcessor processor = processor(store, Clock.fixed(NOW, ZoneOffset.UTC),
                (connection, effect) -> {
                    throw new WebhookEffectPort.EffectFailure(
                            "PROVIDER_EVENT_TYPE_QUARANTINED", true,
                            new IllegalArgumentException("unknown provider event"));
                });

        assertEquals(WebhookInboxProcessor.Outcome.TERMINAL_FAILURE,
                processor.runOnce("tenant-001", "worker-a"));
        assertTrue(store.row(1).terminal);
        assertEquals("PROVIDER_EVENT_TYPE_QUARANTINED", store.row(1).lastFailureCode);
        assertTrue(!store.row(1).lastDiagnostic.contains("unknown provider event"));
    }

    @Test
    void crashOnLastAttemptIsTerminalizedAfterLeaseExpires() {
        FakeStore store = new FakeStore(effect(1, "tenant-001"));
        store.row(1).attempts = POLICY.maxAttempts() - 1;
        store.claim("tenant-001", "dead-worker", NOW, LEASE, POLICY.maxAttempts())
                .orElseThrow();
        MutableClock clock = new MutableClock(NOW.plus(LEASE).plusMillis(1));

        assertEquals(WebhookInboxProcessor.Outcome.TERMINAL_FAILURE,
                processor(store, clock, (connection, effect) -> {
                    throw new AssertionError("exhausted event must not be dispatched again");
                }).runOnce("tenant-001", "reaper"));
        assertTrue(store.row(1).terminal);
        assertEquals(Status.FAILED, store.row(1).status);
    }

    @Test
    void tenantScopedRunCannotClaimAnotherTenant() {
        FakeStore store = new FakeStore(effect(1, "tenant-001"), effect(2, "tenant-002"));
        List<String> dispatchedTenants = new ArrayList<>();
        WebhookInboxProcessor processor = processor(store, Clock.fixed(NOW, ZoneOffset.UTC),
                (connection, effect) -> dispatchedTenants.add(effect.tenantId()));

        assertEquals(WebhookInboxProcessor.Outcome.PROCESSED,
                processor.runOnce("tenant-001", "worker-a"));
        assertEquals(List.of("tenant-001"), dispatchedTenants);
        assertEquals(Status.PROCESSED, store.row(1).status);
        assertEquals(Status.VERIFIED, store.row(2).status);
        assertEquals(0, store.row(2).attempts);
    }

    @Test
    void immutableDigestBindsEveryScopeAndCanonicalFactAtDatabasePrecision() {
        byte[] canonical = "{\"schema\":\"provider-webhook-effect.v1\"}"
                .getBytes(StandardCharsets.UTF_8);
        String canonicalDigest = WebhookVerificationDigests.sha256(canonical);
        String rawDigest = "a".repeat(64);
        WebhookIngressService.Context precise = new WebhookIngressService.Context("tenant-001",
                "project-001", "stripe", "merchant-001",
                Instant.parse("2026-08-30T00:00:00.123456789Z"));
        WebhookIngressService.VerifiedEvent event = new WebhookIngressService.VerifiedEvent(
                "evt-001", "payment.succeeded", "pi-001", "order-001",
                Instant.parse("2026-08-29T23:59:59.123456999Z"), "key-001", canonical);
        String digest = WebhookVerificationDigests.verificationDigest(precise, event, rawDigest,
                canonicalDigest);
        WebhookIngressService.Context persistedPrecision = new WebhookIngressService.Context(
                "tenant-001", "project-001", "stripe", "merchant-001",
                Instant.parse("2026-08-30T00:00:00.123456Z"));
        WebhookIngressService.VerifiedEvent persistedEvent = new WebhookIngressService.VerifiedEvent(
                "evt-001", "payment.succeeded", "pi-001", "order-001",
                Instant.parse("2026-08-29T23:59:59.123456Z"), "key-001", canonical);

        assertEquals(digest, WebhookVerificationDigests.verificationDigest(persistedPrecision,
                persistedEvent, rawDigest, canonicalDigest));
        assertNotEquals(digest, WebhookVerificationDigests.verificationDigest(
                new WebhookIngressService.Context("tenant-002", "project-001", "stripe",
                        "merchant-001", persistedPrecision.receivedAt()),
                persistedEvent, rawDigest, canonicalDigest));
        assertNotEquals(digest, WebhookVerificationDigests.verificationDigest(persistedPrecision,
                persistedEvent, "b".repeat(64), canonicalDigest));
    }

    private static WebhookInboxProcessor processor(FakeStore store, Clock clock,
            WebhookEffectPort port) {
        return new WebhookInboxProcessor(store, port, clock, POLICY);
    }

    private static WebhookEffectPort.Effect effect(long id, String tenantId) {
        byte[] canonical = ("{\"schema\":\"provider-webhook-effect.v1\",\"id\":" + id + "}")
                .getBytes(StandardCharsets.UTF_8);
        return new WebhookEffectPort.Effect(id, tenantId, "project-001", "stripe",
                "merchant-001", "evt-" + id, "payment.succeeded", "pi-" + id,
                "order-" + id, NOW.minusSeconds(1), NOW, "key-001", 1250L, "USD",
                WebhookIngressService.CANONICAL_SCHEMA_V1, "a".repeat(64),
                WebhookVerificationDigests.sha256(canonical), "b".repeat(64), canonical, 1, 1);
    }

    private enum Status { VERIFIED, PROCESSING, PROCESSED, FAILED }

    private static final class Row {
        private final WebhookEffectPort.Effect template;
        private Status status = Status.VERIFIED;
        private int attempts;
        private long fencingToken;
        private String workerId;
        private Instant leaseExpiresAt;
        private Instant nextAttemptAt = Instant.MIN;
        private boolean terminal;
        private boolean effectCommitted;
        private String committedDigest;
        private String lastFailureCode;
        private String lastDiagnostic;

        private Row(WebhookEffectPort.Effect template) {
            this.template = template;
        }

        private WebhookEffectPort.Effect claimedEffect() {
            return new WebhookEffectPort.Effect(template.inboxId(), template.tenantId(),
                    template.projectId(), template.provider(), template.merchantAccountId(),
                    template.providerEventId(), template.eventType(),
                    template.providerPaymentId(), template.businessOrderNo(),
                    template.occurredAt(), template.receivedAt(), template.signatureKeyId(),
                    template.amountMinor(), template.currency(), template.canonicalSchema(),
                    template.rawBodySha256(), template.canonicalPayloadSha256(),
                    template.verificationDigest(), template.canonicalPayload(), attempts,
                    fencingToken);
        }
    }

    private static final class FakeStore implements WebhookInboxStore {
        private final List<Row> rows = new ArrayList<>();

        private FakeStore(WebhookEffectPort.Effect... effects) {
            for (WebhookEffectPort.Effect effect : effects) {
                rows.add(new Row(effect));
            }
        }

        private synchronized Row row(long inboxId) {
            return rows.stream().filter(row -> row.template.inboxId() == inboxId)
                    .findFirst().orElseThrow();
        }

        @Override
        public synchronized int terminalizeExhausted(String tenantId, Instant now,
                int maxAttempts) {
            int changed = 0;
            for (Row row : rows) {
                boolean inactive = row.status == Status.VERIFIED || row.status == Status.FAILED;
                boolean stale = row.status == Status.PROCESSING && row.leaseExpiresAt != null
                        && !row.leaseExpiresAt.isAfter(now);
                if (row.template.tenantId().equals(tenantId) && !row.terminal
                        && row.attempts >= maxAttempts && (inactive || stale)) {
                    row.status = Status.FAILED;
                    row.terminal = true;
                    row.lastFailureCode = "MAX_ATTEMPTS_EXHAUSTED";
                    row.lastDiagnostic = "failure=MAX_ATTEMPTS_EXHAUSTED;verification="
                            + row.template.verificationDigest().substring(0, 16)
                            + ";attempt=" + row.attempts;
                    clearLease(row);
                    changed++;
                }
            }
            return changed;
        }

        @Override
        public synchronized Optional<Claim> claim(String tenantId, String workerId, Instant now,
                Duration leaseTtl, int maxAttempts) {
            Optional<Row> candidate = rows.stream()
                    .filter(row -> row.template.tenantId().equals(tenantId))
                    .filter(row -> !row.terminal && row.attempts < maxAttempts)
                    .filter(row -> (row.status == Status.VERIFIED || row.status == Status.FAILED)
                            ? !row.nextAttemptAt.isAfter(now)
                            : row.status == Status.PROCESSING && row.leaseExpiresAt != null
                                    && !row.leaseExpiresAt.isAfter(now))
                    .min(Comparator.comparingLong(row -> row.template.inboxId()));
            if (candidate.isEmpty()) {
                return Optional.empty();
            }
            Row row = candidate.orElseThrow();
            row.status = Status.PROCESSING;
            row.attempts++;
            row.fencingToken++;
            row.workerId = workerId;
            row.leaseExpiresAt = now.plus(leaseTtl);
            return Optional.of(new Claim(row.claimedEffect(), workerId, row.leaseExpiresAt));
        }

        @Override
        public synchronized ApplyOutcome apply(Claim claim, Instant now, WebhookEffectPort port) {
            Row row = row(claim.effect().inboxId());
            requireFence(row, claim, now);
            if (row.effectCommitted) {
                if (!claim.effect().verificationDigest().equals(row.committedDigest)) {
                    throw new IdentityConflictException("digest conflict");
                }
                row.status = Status.PROCESSED;
                clearLease(row);
                return ApplyOutcome.DUPLICATE_EFFECT;
            }
            try {
                port.apply((Connection) null, claim.effect());
            } catch (Exception failure) {
                if (failure instanceof WebhookEffectPort.EffectFailure classified) {
                    throw new DispatchException(classified.failureCode(),
                            classified.permanent(), classified);
                }
                throw new DispatchException(failure.getClass().getSimpleName(), false, failure);
            }
            row.effectCommitted = true;
            row.committedDigest = claim.effect().verificationDigest();
            row.status = Status.PROCESSED;
            clearLease(row);
            return ApplyOutcome.PROCESSED;
        }

        @Override
        public synchronized boolean recordFailure(Claim claim, Instant failedAt,
                Instant nextAttemptAt, boolean terminal, String failureCode,
                String diagnosticSummary) {
            Row row = row(claim.effect().inboxId());
            if (!hasFence(row, claim, failedAt)) {
                return false;
            }
            row.status = Status.FAILED;
            row.nextAttemptAt = nextAttemptAt;
            row.terminal = terminal;
            row.lastFailureCode = failureCode;
            row.lastDiagnostic = diagnosticSummary;
            clearLease(row);
            return true;
        }

        private static void requireFence(Row row, Claim claim, Instant now) {
            if (!hasFence(row, claim, now)) {
                throw new LeaseLostException("stale fake lease");
            }
        }

        private static boolean hasFence(Row row, Claim claim, Instant now) {
            return row.status == Status.PROCESSING
                    && claim.workerId().equals(row.workerId)
                    && claim.effect().fencingToken() == row.fencingToken
                    && row.leaseExpiresAt != null && row.leaseExpiresAt.isAfter(now);
        }

        private static void clearLease(Row row) {
            row.workerId = null;
            row.leaseExpiresAt = null;
        }
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("test clock is UTC only");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
