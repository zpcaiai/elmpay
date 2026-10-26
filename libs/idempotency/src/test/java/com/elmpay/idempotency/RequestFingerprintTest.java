package com.elmpay.idempotency;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

final class RequestFingerprintTest {
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse(
                    "postgres@sha256:9e2cf6287f25c3151f4c9421ccce2b17f3e60061c111a29165e0d2cdd9ff0a97"))
            .withDatabaseName("elmpay")
            .withUsername("postgres")
            .withPassword("postgres");
    private static PGSimpleDataSource appDataSource;

    @BeforeAll
    static void startPostgresAndApplyProductionIdempotencySchema() throws Exception {
        POSTGRES.start();
        PGSimpleDataSource admin = dataSource("postgres", "postgres");
        try (Connection connection = admin.getConnection(); Statement statement = connection.createStatement()) {
            statement.execute("CREATE ROLE elmpay_idempotency_app LOGIN PASSWORD 'test-only-password'");
            for (String sql : productionIdempotencyStatements()) {
                statement.execute(sql);
            }
            statement.execute("GRANT SELECT, INSERT, UPDATE ON idempotency_record TO elmpay_idempotency_app");
        }
        appDataSource = dataSource("elmpay_idempotency_app", "test-only-password");
    }

    @AfterAll
    static void stopPostgres() {
        POSTGRES.stop();
    }

    @Test
    void fingerprintIsStableAndKeyValidationIsStrict() {
        assertEquals(RequestFingerprint.sha256("canonical"), RequestFingerprint.sha256("canonical"));
        RequestFingerprint.validateKey("request-1234567890");
        RequestFingerprint.validateKey("0123456789abcdef");
        RequestFingerprint.validateKey("a".repeat(128));
        assertThrows(IdempotencyException.class, () -> RequestFingerprint.validateKey("short"));
        assertThrows(IdempotencyException.class,
                () -> RequestFingerprint.validateKey("a".repeat(15)));
        assertThrows(IdempotencyException.class,
                () -> RequestFingerprint.validateKey("a".repeat(129)));
        assertThrows(IdempotencyException.class,
                () -> RequestFingerprint.validateKey("request key has spaces"));
        assertThrows(IdempotencyException.class,
                () -> RequestFingerprint.validateKey("unicode-支付-key-123"));
        assertThrows(IdempotencyException.class, () -> RequestFingerprint.validateKey(null));
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                RequestFingerprint.sha256(""));
    }

    @Test
    void storedResultDefensivelyCopiesBodyAtConstructionAndAccess() {
        byte[] original = {1, 2, 3};
        StoredResult result = new StoredResult(200, "application/json", original);
        original[0] = 9;

        byte[] firstRead = result.body();
        assertArrayEquals(new byte[] {1, 2, 3}, firstRead);
        assertNotSame(firstRead, result.body());
        firstRead[1] = 8;
        assertArrayEquals(new byte[] {1, 2, 3}, result.body());
    }

    @Test
    void storedResultEnforcesHttpStatusAndBodySizeBounds() {
        assertEquals(100, new StoredResult(100, "text/plain", new byte[0]).statusCode());
        assertEquals(599, new StoredResult(599, "text/plain", new byte[0]).statusCode());
        assertEquals(1_048_576,
                new StoredResult(200, "application/octet-stream", new byte[1_048_576]).body().length);
        assertThrows(IllegalArgumentException.class,
                () -> new StoredResult(99, "text/plain", new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> new StoredResult(600, "text/plain", new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> new StoredResult(200, "application/octet-stream", new byte[1_048_577]));
        assertThrows(NullPointerException.class, () -> new StoredResult(200, null, new byte[0]));
        assertThrows(NullPointerException.class, () -> new StoredResult(200, "text/plain", null));
    }

    @Test
    void idempotencyClaimEnforcesOwnedAndReplayStateRequirements() {
        StoredResult replay = new StoredResult(201, "application/json", new byte[] {4});
        assertEquals("owner", new IdempotencyClaim(IdempotencyClaim.Status.OWNED,
                "owner", null).ownerToken());
        assertEquals(replay, new IdempotencyClaim(IdempotencyClaim.Status.REPLAY,
                null, replay).replay());
        assertEquals(IdempotencyClaim.Status.BUSY,
                new IdempotencyClaim(IdempotencyClaim.Status.BUSY, null, null).status());
        assertEquals(IdempotencyClaim.Status.UNKNOWN_OUTCOME,
                new IdempotencyClaim(IdempotencyClaim.Status.UNKNOWN_OUTCOME, null, null).status());
        assertThrows(NullPointerException.class, () -> new IdempotencyClaim(null, null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new IdempotencyClaim(IdempotencyClaim.Status.OWNED, null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new IdempotencyClaim(IdempotencyClaim.Status.OWNED, "  ", null));
        assertThrows(IllegalArgumentException.class,
                () -> new IdempotencyClaim(IdempotencyClaim.Status.REPLAY, null, null));
    }

    @Test
    void idempotencyExceptionPreservesCodeMessageAndCause() {
        IdempotencyException plain = new IdempotencyException("KEY_CONFLICT", "different request");
        assertEquals("KEY_CONFLICT", plain.code());
        assertEquals("different request", plain.getMessage());
        assertNull(plain.getCause());

        SQLException cause = new SQLException("connection refused");
        IdempotencyException caused = new IdempotencyException(
                "STORE_UNAVAILABLE", "cannot claim", cause);
        assertEquals("STORE_UNAVAILABLE", caused.code());
        assertEquals("cannot claim", caused.getMessage());
        assertNotNull(caused.getCause());
        assertEquals(cause, caused.getCause());
    }

    @Test
    void rlsIdentityIsTransactionLocalAndRejectsAutocommit() throws Exception {
        UUID tenant = UUID.fromString("00000000-0000-0000-0000-000000000022");
        List<String> calls = new ArrayList<>();

        JdbcIdempotencyRegistry.setTenantContext(connection(false, calls), tenant);

        assertTrue(calls.getFirst().contains("set_config('app.tenant_id', ?, true)"));
        assertEquals(tenant.toString(), calls.get(1));
        assertThrows(SQLException.class, () -> JdbcIdempotencyRegistry.setTenantContext(
                connection(true, new ArrayList<>()), tenant));
    }

    @Test
    void jdbcRegistryClaimsConflictsCompletesAndReplaysUsingPostgres() {
        UUID tenant = UUID.randomUUID();
        String key = newKey();
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        JdbcIdempotencyRegistry registry = new JdbcIdempotencyRegistry(appDataSource, clock);

        IdempotencyClaim owned = registry.claim(tenant, "payment.create", key, hash('a'),
                Duration.ofSeconds(30), Duration.ofMinutes(5));
        assertEquals(IdempotencyClaim.Status.OWNED, owned.status());
        assertNotNull(owned.ownerToken());
        assertEquals(IdempotencyClaim.Status.BUSY,
                registry.claim(tenant, "payment.create", key, hash('a'),
                        Duration.ofSeconds(30), Duration.ofMinutes(5)).status());

        IdempotencyException conflict = assertThrows(IdempotencyException.class,
                () -> registry.claim(tenant, "payment.create", key, hash('b'),
                        Duration.ofSeconds(30), Duration.ofMinutes(5)));
        assertEquals("IDEMPOTENCY_PAYLOAD_CONFLICT", conflict.code());

        StoredResult expected = new StoredResult(201, "application/json", new byte[] {1, 2, 3});
        registry.complete(tenant, "payment.create", key, owned.ownerToken(), expected);
        IdempotencyClaim replay = registry.claim(tenant, "payment.create", key, hash('a'),
                Duration.ofSeconds(30), Duration.ofMinutes(5));
        assertEquals(IdempotencyClaim.Status.REPLAY, replay.status());
        assertEquals(expected.statusCode(), replay.replay().statusCode());
        assertEquals(expected.contentType(), replay.replay().contentType());
        assertArrayEquals(expected.body(), replay.replay().body());
    }

    @Test
    void jdbcRegistryReclaimsExpiredLeaseAndPersistsUnknownOutcome() {
        UUID tenant = UUID.randomUUID();
        String key = newKey();
        Instant started = Instant.parse("2026-01-01T00:00:00Z");
        Duration lease = Duration.ofSeconds(1);
        Duration retention = Duration.ofMinutes(5);
        IdempotencyClaim first = new JdbcIdempotencyRegistry(appDataSource,
                Clock.fixed(started, ZoneOffset.UTC)).claim(tenant, "payment.create", key,
                        hash('c'), lease, retention);
        IdempotencyClaim recovered = new JdbcIdempotencyRegistry(appDataSource,
                Clock.fixed(started.plusSeconds(2), ZoneOffset.UTC)).claim(tenant,
                        "payment.create", key, hash('c'), lease, retention);

        assertEquals(IdempotencyClaim.Status.OWNED, first.status());
        assertEquals(IdempotencyClaim.Status.OWNED, recovered.status());
        assertTrue(!first.ownerToken().equals(recovered.ownerToken()));

        JdbcIdempotencyRegistry registry = new JdbcIdempotencyRegistry(appDataSource,
                Clock.fixed(started.plusSeconds(2), ZoneOffset.UTC));
        registry.markUnknown(tenant, "payment.create", key, recovered.ownerToken(), "PROVIDER_TIMEOUT");
        assertEquals(IdempotencyClaim.Status.UNKNOWN_OUTCOME,
                registry.claim(tenant, "payment.create", key, hash('c'), lease, retention).status());
        assertEquals("IDEMPOTENCY_OWNERSHIP_LOST", assertThrows(IdempotencyException.class,
                () -> registry.complete(tenant, "payment.create", key, recovered.ownerToken(),
                        new StoredResult(200, "text/plain", new byte[0]))).code());
    }

    @Test
    void productionRlsPolicyHidesAnotherTenantsRecord() throws Exception {
        UUID ownerTenant = UUID.randomUUID();
        UUID otherTenant = UUID.randomUUID();
        String key = newKey();
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        JdbcIdempotencyRegistry registry = new JdbcIdempotencyRegistry(appDataSource, clock);
        registry.claim(ownerTenant, "payment.create", key, hash('d'), Duration.ofSeconds(30),
                Duration.ofMinutes(5));

        assertEquals(IdempotencyClaim.Status.OWNED,
                registry.claim(otherTenant, "payment.create", key, hash('d'),
                        Duration.ofSeconds(30), Duration.ofMinutes(5)).status());
        try (Connection connection = appDataSource.getConnection()) {
            connection.setAutoCommit(false);
            JdbcIdempotencyRegistry.setTenantContext(connection, otherTenant);
            try (PreparedStatement query = connection.prepareStatement(
                    "SELECT count(*) FROM idempotency_record WHERE tenant_id = ? AND idempotency_key = ?")) {
                query.setObject(1, ownerTenant);
                query.setString(2, key);
                try (var rows = query.executeQuery()) {
                    assertTrue(rows.next());
                    assertEquals(0L, rows.getLong(1));
                }
            }
            connection.rollback();
        }
    }

    @Test
    void sixtyFourConcurrentWritersProduceOneOwnerAndSixtyThreeBusyClaims() throws Exception {
        UUID tenant = UUID.randomUUID();
        String key = newKey();
        String requestHash = hash('e');
        Clock clock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        CountDownLatch ready = new CountDownLatch(64);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<IdempotencyClaim.Status>> results = new ArrayList<>();

        try (ExecutorService workers = Executors.newFixedThreadPool(64)) {
            for (int index = 0; index < 64; index++) {
                results.add(workers.submit(() -> {
                    ready.countDown();
                    if (!start.await(20, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("concurrent claim start timed out");
                    }
                    return new JdbcIdempotencyRegistry(appDataSource, clock).claim(tenant,
                            "payment.create", key, requestHash, Duration.ofSeconds(30),
                            Duration.ofMinutes(5)).status();
                }));
            }
            assertTrue(ready.await(20, TimeUnit.SECONDS));
            start.countDown();
            long owners = 0;
            long busy = 0;
            for (Future<IdempotencyClaim.Status> result : results) {
                IdempotencyClaim.Status status = result.get(30, TimeUnit.SECONDS);
                if (status == IdempotencyClaim.Status.OWNED) owners++;
                if (status == IdempotencyClaim.Status.BUSY) busy++;
            }
            assertEquals(1L, owners);
            assertEquals(63L, busy);
        }
    }

    private static List<String> productionIdempotencyStatements() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        while (directory != null
                && !Files.isRegularFile(directory.resolve("governance/module-registry.json"))) {
            directory = directory.getParent();
        }
        if (directory == null) {
            throw new IOException("repository root not found for production migration test");
        }
        String migration = Files.readString(directory.resolve(
                "apps/edge-gateway/src/main/resources/db/migration/V032__payment_runtime.sql"));
        List<String> statements = Arrays.stream(migration.split(";"))
                .map(String::strip)
                .filter(sql -> {
                    String normalized = sql.toLowerCase(Locale.ROOT);
                    return normalized.startsWith("create table if not exists idempotency_record")
                            || normalized.startsWith("alter table idempotency_record")
                            || normalized.startsWith("drop policy if exists idempotency_record_tenant_policy")
                            || normalized.startsWith("create policy idempotency_record_tenant_policy");
                }).toList();
        if (statements.size() != 5) {
            throw new IOException("expected the table and four RLS statements from V032, found "
                    + statements.size());
        }
        return statements;
    }

    private static PGSimpleDataSource dataSource(String username, String password) {
        PGSimpleDataSource dataSource = new PGSimpleDataSource();
        dataSource.setUrl(POSTGRES.getJdbcUrl());
        dataSource.setUser(username);
        dataSource.setPassword(password);
        return dataSource;
    }

    private static String newKey() {
        return "integration-key-" + UUID.randomUUID();
    }

    private static String hash(char digit) {
        return String.valueOf(digit).repeat(64);
    }

    private static Connection connection(boolean autoCommit, List<String> calls) {
        return (Connection) Proxy.newProxyInstance(RequestFingerprintTest.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getAutoCommit" -> autoCommit;
                    case "prepareStatement" -> {
                        calls.add((String) args[0]);
                        yield statement(calls);
                    }
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                });
    }

    private static PreparedStatement statement(List<String> calls) {
        return (PreparedStatement) Proxy.newProxyInstance(RequestFingerprintTest.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "setString" -> {
                        calls.add((String) args[1]);
                        yield null;
                    }
                    case "execute" -> true;
                    case "close" -> null;
                    default -> defaultValue(method.getReturnType());
                });
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
