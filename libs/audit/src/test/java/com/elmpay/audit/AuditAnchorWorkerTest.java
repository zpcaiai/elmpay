package com.elmpay.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class AuditAnchorWorkerTest {
    private static final Instant NOW = Instant.parse("2026-08-28T00:00:00Z");
    private static final UUID TENANT = UUID.fromString("00000000-0000-0000-0000-000000000023");
    private static final AuditAnchorWorker.Candidate CANDIDATE = new AuditAnchorWorker.Candidate(
            UUID.fromString("10000000-0000-0000-0000-000000000023"), TENANT, 42,
            "a".repeat(64), 7, "anchor-worker-1");

    @Test
    void signedExternalTimestampIsVerifiedBeforeImmutableReceiptPersistence() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        RecordingStore store = new RecordingStore();
        AuditAnchorWorker worker = worker(store, keyPair,
                candidate -> signedReceipt(candidate, keyPair));

        assertEquals(AuditAnchorWorker.Outcome.ANCHORED, worker.runOnce(TENANT));
        assertTrue(store.persisted);
        assertFalse(store.failed);
        assertEquals(CANDIDATE.fencingToken(), store.persistedCandidate.fencingToken());
    }

    @Test
    void mismatchedOrInvalidReceiptIsFailClosedAndCrashRetryRemainsLeaseBound() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        RecordingStore store = new RecordingStore();
        AuditAnchorWorker worker = worker(store, keyPair, candidate ->
                new AuditAnchorWorker.Receipt("authority-1", "receipt-1", candidate.tenantId(),
                        candidate.throughSequence(), candidate.chainHash(), NOW,
                        new byte[64]));

        assertEquals(AuditAnchorWorker.Outcome.RETRY_SCHEDULED, worker.runOnce(TENANT));
        assertFalse(store.persisted);
        assertTrue(store.failed);
        assertEquals(CANDIDATE.fencingToken(), store.failedCandidate.fencingToken());
        assertTrue(store.retryAt.isAfter(NOW));
    }

    @Test
    void businessMutationAndAuditFactShareOneCommitAndTenantMismatchRollsBack() {
        RecordingDatabase database = new RecordingDatabase();
        JdbcAuditedMutation audited = new JdbcAuditedMutation(database);
        AuditEvent event = event(TENANT);

        assertEquals("updated", audited.execute(TENANT, connection -> {
            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE refund SET status='APPROVED' WHERE tenant_id=?::uuid")) {
                statement.setString(1, TENANT.toString());
                statement.executeUpdate();
            }
            return "updated";
        }, ignored -> event));
        assertEquals(1, database.commits);
        assertEquals(0, database.rollbacks);
        assertTrue(database.sql.stream().anyMatch(value -> value.contains("UPDATE refund")));
        assertTrue(database.sql.stream().anyMatch(value -> value.contains("INSERT INTO audit_event")));

        UUID wrongTenant = UUID.fromString("00000000-0000-0000-0000-000000000024");
        assertThrows(SecurityException.class, () -> audited.execute(TENANT,
                connection -> "wrong", ignored -> event(wrongTenant)));
        assertEquals(1, database.commits);
        assertEquals(1, database.rollbacks);
    }

    @Test
    void timestampAuthorityTransportRejectsRedirectFollowingClients() {
        HttpClient redirecting = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.ALWAYS).build();
        assertThrows(IllegalArgumentException.class, () -> new HttpsAuditTimestampAuthority(
                redirecting, URI.create("https://timestamp.example.test/v1/anchor"),
                Duration.ofSeconds(5), "t".repeat(32)));
    }

    private static AuditAnchorWorker worker(RecordingStore store, KeyPair keyPair,
            AuditAnchorWorker.TimestampAuthority authority) {
        return new AuditAnchorWorker(store, authority, keyPair.getPublic(), "anchor-worker-1",
                Duration.ofSeconds(30), Duration.ofMinutes(1), Duration.ofMinutes(5),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static AuditAnchorWorker.Receipt signedReceipt(AuditAnchorWorker.Candidate candidate,
            KeyPair keyPair) {
        try {
            AuditAnchorWorker.Receipt unsigned = new AuditAnchorWorker.Receipt("authority-1",
                    "receipt-1", candidate.tenantId(), candidate.throughSequence(),
                    candidate.chainHash(), NOW, new byte[64]);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyPair.getPrivate());
            signer.update(AuditAnchorWorker.canonicalReceipt(unsigned));
            return new AuditAnchorWorker.Receipt(unsigned.authorityId(), unsigned.receiptId(),
                    unsigned.tenantId(), unsigned.throughSequence(), unsigned.chainHash(),
                    unsigned.anchoredAt(), signer.sign());
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static AuditEvent event(UUID tenantId) {
        return new AuditEvent(UUID.fromString("20000000-0000-0000-0000-000000000023"),
                tenantId, "operator-a", "refund.approve", "refund", "refund-1",
                "verified customer request", "ticket-23", Map.of("status", "PENDING"),
                Map.of("status", "APPROVED"), "correlation-23", NOW);
    }

    private static final class RecordingStore implements AuditAnchorWorker.Store {
        private boolean persisted;
        private boolean failed;
        private AuditAnchorWorker.Candidate persistedCandidate;
        private AuditAnchorWorker.Candidate failedCandidate;
        private Instant retryAt;

        @Override
        public Optional<AuditAnchorWorker.Candidate> claim(UUID tenantId, String workerId,
                Instant now, Instant leaseUntil) {
            return Optional.of(CANDIDATE);
        }

        @Override
        public void recordVerifiedReceipt(AuditAnchorWorker.Candidate candidate,
                AuditAnchorWorker.Receipt receipt, Instant receivedAt) {
            persisted = true;
            persistedCandidate = candidate;
        }

        @Override
        public void recordFailure(AuditAnchorWorker.Candidate candidate, String errorCode,
                Instant retry) {
            failed = true;
            failedCandidate = candidate;
            retryAt = retry;
        }
    }

    private static final class RecordingDatabase implements DataSource {
        private final List<String> sql = new ArrayList<>();
        private int commits;
        private int rollbacks;

        @Override
        public Connection getConnection() {
            AtomicBoolean closed = new AtomicBoolean();
            return (Connection) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {Connection.class}, (proxy, method, arguments) ->
                            switch (method.getName()) {
                                case "getAutoCommit" -> false;
                                case "setAutoCommit" -> null;
                                case "prepareStatement" -> prepared((String) arguments[0]);
                                case "commit" -> { commits++; yield null; }
                                case "rollback" -> { rollbacks++; yield null; }
                                case "close" -> { closed.set(true); yield null; }
                                case "isClosed" -> closed.get();
                                case "unwrap" -> null;
                                case "isWrapperFor" -> false;
                                default -> defaultValue(method.getReturnType());
                            });
        }

        private PreparedStatement prepared(String query) {
            sql.add(query);
            return (PreparedStatement) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) ->
                            switch (method.getName()) {
                                case "setString", "setObject", "setBytes", "setLong", "close" -> null;
                                case "execute" -> true;
                                case "executeUpdate" -> 1;
                                case "executeQuery" -> emptyRows();
                                default -> defaultValue(method.getReturnType());
                            });
        }

        private ResultSet emptyRows() {
            return (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[] {ResultSet.class}, (proxy, method, arguments) ->
                            switch (method.getName()) {
                                case "next" -> false;
                                case "close" -> null;
                                default -> defaultValue(method.getReturnType());
                            });
        }

        @Override public Connection getConnection(String username, String password) { return getConnection(); }
        @Override public <T> T unwrap(Class<T> iface) { return null; }
        @Override public boolean isWrapperFor(Class<?> iface) { return false; }
        @Override public java.io.PrintWriter getLogWriter() { return null; }
        @Override public void setLogWriter(java.io.PrintWriter out) {}
        @Override public void setLoginTimeout(int seconds) {}
        @Override public int getLoginTimeout() { return 0; }
        @Override public java.util.logging.Logger getParentLogger() {
            return java.util.logging.Logger.getGlobal();
        }
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        if (type == char.class) return '\0';
        return null;
    }
}
