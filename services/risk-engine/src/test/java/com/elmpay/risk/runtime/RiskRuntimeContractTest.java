package com.elmpay.risk.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.RiskOperation;
import com.elmpay.risk.RiskOperations;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class RiskRuntimeContractTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final String TENANT = "10000000-0000-0000-0000-000000000001";
    private static final String PROJECT = "20000000-0000-0000-0000-000000000001";
    @TempDir Path directory;

    @Test
    void nonceReplayIdempotencyAndOutboxAreDurable() throws Exception {
        String migration = migration();
        assertTrue(migration.contains("nonce_digest char(64) NOT NULL UNIQUE"));
        assertTrue(migration.contains("consumed_at timestamptz"));
        assertTrue(migration.contains("PRIMARY KEY (tenant_id, project_id, request_id)"));
        String implementation = source("JdbcRiskDecisionService.java");
        int consume = implementation.indexOf("consumeNonce(connection");
        int decision = implementation.indexOf("insertDecision(connection");
        int outbox = implementation.indexOf("appendOutbox(connection");
        assertTrue(consume >= 0 && decision > consume && outbox > decision);

        RiskEvaluationRequest first = request(100);
        RiskEvaluationRequest conflicting = request(101);
        assertNotEquals(first.requestDigest(), conflicting.requestDigest());
        assertEquals(first.requestDigest(), request(100).requestDigest());
    }

    @Test
    void migrationForcesTenantRlsAndImmutableEvidence() throws Exception {
        String migration = migration();
        assertTrue(migration.contains("FORCE ROW LEVEL SECURITY"));
        assertTrue(migration.contains("risk_runtime_forbid_change"));
        assertTrue(migration.contains("risk_runtime_decision_immutable"));
        assertTrue(migration.contains("risk_runtime_signal_immutable"));
        assertTrue(migration.contains("risk_runtime_model_immutable"));
        assertTrue(migration.contains("risk_runtime_validate_list_effect"));
        assertTrue(migration.contains("risk_runtime_validate_case_effect"));
        assertTrue(migration.contains("operation.project_id = NEW.project_id"));
        assertTrue(migration.contains("current_setting(''app.tenant_id'', true)::uuid"));
        String hardening = adminHardeningMigration();
        assertTrue(hardening.contains("REVOKE ALL ON FUNCTION"));
        assertTrue(hardening.contains("risk_runtime_forbid_change()"));
        assertTrue(hardening.contains("risk_runtime_validate_case_effect()"));
        assertTrue(hardening.contains("elmpay.admin-command-db-api.v1"));
    }

    @Test
    void fourEyesExpiryAndOptimisticConcurrencyAreEnforced() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        RiskOperations operations = new RiskOperations(clock);
        var proposal = operations.propose(TENANT, RiskOperations.Kind.LIST_ADD, "digest",
                "review", "operator-a", NOW.plusSeconds(30));
        assertThrows(SecurityException.class,
                () -> operations.approve(TENANT, proposal.id(), "operator-a", 1));
        assertThrows(IllegalStateException.class,
                () -> operations.approve(TENANT, proposal.id(), "operator-b", 2));
        clock.value = NOW.plusSeconds(31);
        assertThrows(IllegalStateException.class,
                () -> operations.approve(TENANT, proposal.id(), "operator-b", 1));
        String migration = migration();
        assertTrue(migration.contains("approved_by_digest <> proposed_by_digest"));
        assertTrue(migration.contains("approval_expires_at >"));
        assertTrue(migration.contains("NEW.record_version <> OLD.record_version + 1"));
        assertThrows(IllegalStateException.class, () ->
                JdbcRiskControlPlane.requireGovernedMutation(NOW, NOW));
        assertThrows(IllegalStateException.class, () ->
                JdbcRiskControlPlane.requireGovernedMutation(NOW.minusNanos(1), NOW));
    }

    @Test
    void projectedMountRotationIsAllowedButEscapeAndWritableFilesAreRejected() throws Exception {
        Path mount = Files.createDirectory(directory.resolve("mount"));
        Path revision = Files.createDirectory(mount.resolve("..2026_08_30"));
        Path value = revision.resolve("value");
        Files.writeString(value, "mounted-value", StandardCharsets.UTF_8);
        readonly(value);
        Files.createSymbolicLink(mount.resolve("..data"), Path.of("..2026_08_30"));
        Path projected = mount.resolve("value");
        Files.createSymbolicLink(projected, Path.of("..data/value"));
        var binding = RiskMountedFiles.forTest(projected, mount, "value", 1024);
        assertEquals("mounted-value", new String(RiskMountedFiles.read(binding, 1024),
                StandardCharsets.UTF_8));
        RiskPostgresDataSource.requireMounted(binding, "projected", 1024);

        Path outside = directory.resolve("outside");
        Files.writeString(outside, "outside");
        readonly(outside);
        Path escaped = mount.resolve("escaped");
        Files.createSymbolicLink(escaped, outside);
        assertThrows(IllegalStateException.class,
                () -> RiskMountedFiles.read(RiskMountedFiles.forTest(escaped, mount,
                        "escaped", 1024), 1024));
        assertThrows(java.sql.SQLException.class,
                () -> RiskPostgresDataSource.requireMounted(RiskMountedFiles.forTest(
                        escaped, mount, "escaped", 1024), "escaped", 1024));

        Path writable = mount.resolve("writable");
        Files.writeString(writable, "writable");
        Files.setPosixFilePermissions(writable, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
        assertThrows(IllegalStateException.class, () -> RiskMountedFiles.read(
                RiskMountedFiles.forTest(writable, mount, "writable", 1024), 1024));

        assertThrows(IllegalStateException.class, () -> RiskTlsContexts.readMounted(Map.of(
                "ELMPAY_RISK_TLS_SERVER_PRIVATE_KEY_FILE", writable.toString()),
                "ELMPAY_RISK_TLS_SERVER_PRIVATE_KEY_FILE", 1024));
        assertThrows(IllegalStateException.class, () -> RiskRuntimeConfig.readOnly(Map.of(
                "ELMPAY_RISK_GOVERNANCE_POLICY_FILE", writable.toString()),
                "ELMPAY_RISK_GOVERNANCE_POLICY_FILE", 1024));
    }

    @Test
    void databaseAndDependencyUrisRejectAllOverrideChannels() throws Exception {
        Path placeholder = directory.resolve("placeholder").toAbsolutePath();
        assertEquals("elmpay_risk_engine",
                RiskPostgresDataSource.requireRuntimeUsername("elmpay_risk_engine"));
        assertThrows(IllegalStateException.class,
                () -> RiskPostgresDataSource.requireRuntimeUsername("risk-user"));
        assertThrows(IllegalArgumentException.class, () -> new RiskPostgresDataSource(
                "jdbc:postgresql://db/elmpay?sslmode=disable", "risk-user", placeholder,
                placeholder, placeholder, placeholder));
        assertThrows(IllegalArgumentException.class, () -> new RiskPostgresDataSource(
                "jdbc:postgresql://user:password@db/elmpay", "risk-user", placeholder,
                placeholder, placeholder, placeholder));
        assertThrows(IllegalStateException.class, () -> RiskPostgresDataSource.fromEnvironment(
                Map.of("ELMPAY_RISK_DATABASE_URL", "jdbc:postgresql://db/elmpay",
                        "ELMPAY_RISK_DATABASE_USERNAME", "risk-user",
                        "ELMPAY_RISK_DATABASE_PASSWORD_FILE", placeholder.toString(),
                        "ELMPAY_RISK_DATABASE_CA_FILE", placeholder.toString(),
                        "ELMPAY_RISK_DATABASE_CLIENT_CERTIFICATE_FILE", placeholder.toString(),
                        "ELMPAY_RISK_DATABASE_CLIENT_PRIVATE_KEY_FILE",
                        placeholder.toString())));
        assertThrows(IllegalArgumentException.class, () -> StrictHttpsTransport.exactHttps(
                URI.create("https://signal.example/v1/risk/signals?redirect=true")));
        assertThrows(IllegalArgumentException.class, () -> StrictHttpsTransport.exactHttps(
                URI.create("http://signal.example/v1/risk/signals")));
        assertThrows(IllegalArgumentException.class, () -> new StrictHttpsTransport(
                javax.net.ssl.SSLContext.getDefault(), java.time.Duration.ofMillis(100), 1024)
                .post(URI.create("https://signal.example/v1/risk/signals"), new byte[] {'{', '}'},
                        Map.of("Content-Type", "text/plain")));
        assertEquals("application/json", StrictHttpsTransport.exactContentType(
                java.net.http.HttpHeaders.of(Map.of("Content-Type",
                        List.of("application/json")), (name, value) -> true)));
        assertEquals("", StrictHttpsTransport.exactContentType(
                java.net.http.HttpHeaders.of(Map.of("Content-Type",
                        List.of("application/json", "application/problem+json")),
                        (name, value) -> true)));
        assertEquals("", StrictHttpsTransport.exactContentType(
                java.net.http.HttpHeaders.of(Map.of("Content-Type",
                        List.of("application/json; charset=utf-8")),
                        (name, value) -> true)));
    }

    @Test
    void dependencyBudgetIsTheFixedGovernedOneHundredMilliseconds() {
        assertEquals(Duration.ofMillis(100), RiskRuntimeConfig.dependencyTimeout(Map.of()));
        assertEquals(Duration.ofMillis(100), RiskRuntimeConfig.dependencyTimeout(Map.of(
                "ELMPAY_RISK_DEPENDENCY_TIMEOUT_MILLISECONDS", "100")));
        assertThrows(IllegalStateException.class, () -> RiskRuntimeConfig.dependencyTimeout(Map.of(
                "ELMPAY_RISK_DEPENDENCY_TIMEOUT_MILLISECONDS", "99")));
        assertThrows(IllegalStateException.class, () -> RiskRuntimeConfig.dependencyTimeout(Map.of(
                "ELMPAY_RISK_DEPENDENCY_TIMEOUT_MILLISECONDS", "101")));
    }

    @Test
    void databaseTlsFilesArePinnedPerConnectionWhileProjectedSecretsRotate() throws Exception {
        Path mount = Files.createDirectory(directory.resolve("database-mount"));
        Path first = Files.createDirectory(mount.resolve("..2026_08_30_01"));
        Path second = Files.createDirectory(mount.resolve("..2026_08_30_02"));
        for (Path revision : List.of(first, second)) {
            for (String name : List.of("password", "ca.crt", "tls.crt", "tls.key")) {
                Path value = revision.resolve(name);
                Files.writeString(value, name.equals("password") ? "database-password" : name,
                        StandardCharsets.UTF_8);
                readonly(value);
            }
        }
        Path data = mount.resolve("..data");
        Files.createSymbolicLink(data, first.getFileName());
        for (String name : List.of("password", "ca.crt", "tls.crt", "tls.key")) {
            Files.createSymbolicLink(mount.resolve(name), Path.of("..data", name));
        }
        List<java.util.Properties> calls = new java.util.ArrayList<>();
        RiskPostgresDataSource dataSource = new RiskPostgresDataSource(
                "jdbc:postgresql://database.example/elmpay", "elmpay_risk_engine",
                mount.resolve("password"), mount.resolve("ca.crt"), mount.resolve("tls.crt"),
                mount.resolve("tls.key"), (url, properties) -> {
                    var snapshot = new java.util.Properties();
                    snapshot.putAll(properties);
                    calls.add(snapshot);
                    return null;
                });
        dataSource.getConnection();
        assertEquals("-c search_path=pg_catalog,public,pg_temp",
                calls.getFirst().getProperty("options"));
        assertTrue(Path.of(calls.getFirst().getProperty("sslrootcert")).startsWith(
                first.toRealPath()));
        assertNotEquals(mount.resolve("ca.crt").toString(),
                calls.getFirst().getProperty("sslrootcert"));

        Files.delete(data);
        Files.createSymbolicLink(data, second.getFileName());
        dataSource.getConnection();
        assertTrue(Path.of(calls.get(1).getProperty("sslrootcert")).startsWith(
                second.toRealPath()));
        assertTrue(Path.of(calls.get(1).getProperty("sslcert")).startsWith(second.toRealPath()));
        assertTrue(Path.of(calls.get(1).getProperty("sslkey")).startsWith(second.toRealPath()));
    }

    @Test
    void privateKeyParsingAvoidsImmutableSecretStringsAndWipesTemporaryBuffers()
            throws Exception {
        String implementation = source("RiskTlsContexts.java");
        assertTrue(!implementation.contains("new String(raw"));
        assertTrue(implementation.contains("Arrays.fill(normalized, (byte) 0)"));
        assertTrue(implementation.contains("Arrays.fill(der, (byte) 0)"));
        assertTrue(implementation.contains("Arrays.fill(encodedPrivateKey, (byte) 0)"));
    }

    @Test
    void requestTargetsAndAttributeCardinalityAreBounded() throws Exception {
        String boundary = source("RiskHttpApi.java");
        assertTrue(boundary.contains("requestUri.getRawQuery() != null"));
        assertTrue(boundary.contains("requestUri.getRawFragment() != null"));
        assertTrue(boundary.contains("values.size() > 32"));
        assertTrue(boundary.contains("textValue.length() > 256"));
        assertTrue(boundary.contains("one exact application/json content type required"));
        assertTrue(boundary.contains("one canonical content length required"));
        assertTrue(boundary.contains("forwarded or ambiguous identity header"));
        assertTrue(boundary.contains("purposes.contains(\"1.3.6.1.5.5.7.3.2\")"));
        assertTrue(boundary.contains("client SPIFFE URI is not canonical"));

        Map<String, String> tooMany = new LinkedHashMap<>();
        for (int index = 0; index < 33; index++) tooMany.put("key" + index, "value");
        assertThrows(IllegalArgumentException.class, () -> new RiskEvaluationRequest(TENANT,
                PROJECT, "PAYMENT_CREATE:key-2", RiskOperation.PAYMENT_CREATE, "merchant-1",
                100, "USD", NOW, tooMany));
        assertThrows(IllegalArgumentException.class, () -> new RiskEvaluationRequest(TENANT,
                PROJECT, "PAYMENT_CREATE:key-3", RiskOperation.PAYMENT_CREATE, "merchant-1",
                100, "USD", NOW, Map.of("key", "x".repeat(257))));

        var ticker = new java.util.concurrent.atomic.AtomicLong(1_000);
        assertTrue(!RiskHttpApi.requestBudgetExceeded(ticker::get, 1_000));
        ticker.addAndGet(Duration.ofSeconds(5).toNanos());
        assertTrue(RiskHttpApi.requestBudgetExceeded(ticker::get, 1_000));
    }

    @Test
    void adminRiskEffectAndReceiptShareOneFencedTransaction() throws Exception {
        String consumer = source("AdminRiskActionCommandConsumer.java");
        int effect = consumer.indexOf("applyApprovedAdminCommand(connection, claim, now)");
        int receipt = consumer.indexOf("queue.complete(connection, claim, effectDigest, now)");
        int commit = consumer.indexOf("connection.commit();", receipt);
        assertTrue(effect >= 0 && receipt > effect && commit > receipt);
        assertTrue(consumer.contains("COMMIT_OUTCOME_UNKNOWN"));
        assertTrue(consumer.contains("queue.findReceipt"));
        assertTrue(consumer.contains("claim.fencingToken()"));

        String control = source("JdbcRiskControlPlane.java");
        assertTrue(control.contains("risk.admin_operation.applied.v1"));
        assertTrue(control.contains("command.proposerDigest().equals(command.approverDigest())"));
        assertTrue(control.contains("command.approvalExpiresAt().isAfter(appliedAt)"));
        assertTrue(control.contains("command.policyDigest().equals(adminActionPolicyDigest)"));
        assertTrue(control.contains("adminActionPolicyValidUntil.isAfter(appliedAt)"));
    }

    @Test
    void runtimeStartupVerifiesExactRoleRlsOwnershipAndCrossDomainPrivileges() throws Exception {
        String verifier = source("RiskRuntimeSchemaVerifier.java");
        assertTrue(verifier.contains("RUNTIME_DATABASE_ROLE.equals(result.getString(1))"));
        assertTrue(verifier.contains("rolsuper, rolbypassrls, rolcreaterole"));
        assertTrue(verifier.contains("rolcanlogin, rolinherit"));
        assertTrue(verifier.contains("current_setting('search_path')"));
        assertTrue(verifier.contains("REQUIRED_SEARCH_PATH_RENDERINGS"));
        assertTrue(verifier.contains("runtime_role.rolconfig"));
        assertTrue(verifier.contains("current_setting('row_security') = 'on'"));
        assertTrue(verifier.contains("p.prosecdef"));
        assertTrue(verifier.contains("has_function_privilege"));
        assertTrue(verifier.contains("count(*) = 5"));
        assertTrue(verifier.contains("owner.rolname = 'elmpay_migrator'"));
        assertTrue(verifier.contains("search_path=pg_catalog, public"));
        assertTrue(verifier.contains("row_security=on"));
        assertTrue(verifier.contains("elmpay.admin-command-db-api.v1"));
        assertTrue(verifier.contains("aclexplode"));
        assertTrue(verifier.contains("c.relowner = r.oid"));
        assertTrue(verifier.contains("c.relrowsecurity, c.relforcerowsecurity"));
        assertTrue(verifier.contains("has_any_column_privilege"));
        assertTrue(verifier.contains("MAINTAIN"));
        assertTrue(verifier.contains("has_database_privilege(current_user, current_database(), 'TEMP')"));
        assertTrue(verifier.contains("FROM pg_policy"));
        assertTrue(verifier.contains("p.polroles = ARRAY[0]::oid[]"));
        assertTrue(verifier.contains("EXACT_TENANT_POLICY_EXPRESSIONS"));
        assertTrue(verifier.contains("requireNoCrossDomainRelationPrivilege(connection)"));
        assertTrue(verifier.contains("c.relkind IN ('r', 'p', 'f', 'v', 'm')"));
        assertTrue(verifier.contains("has_sequence_privilege"));
        assertTrue(verifier.contains("requireNoCrossDomainSequencePrivilege(connection)"));

        String application = source("RiskEngineApplication.java");
        assertTrue(application.contains("schema.verify();"));
        assertTrue(application.contains("schema.ready() && decisions.ready()"));
    }

    @Test
    void tenantPolicyExpressionAllowsOnlyTheExactTenantGucPredicate() {
        assertTrue(RiskRuntimeSchemaVerifier.exactTenantExpression(
                "(tenant_id = (current_setting('app.tenant_id'::text, true))::uuid)"));
        assertTrue(RiskRuntimeSchemaVerifier.exactTenantExpression(
                "(tenant_id = (NULLIF(current_setting('app.tenant_id'::text, true), "
                        + "''::text))::uuid)"));
        assertFalse(RiskRuntimeSchemaVerifier.exactTenantExpression(
                "(tenant_id = (current_setting('app. tenant_id'::text, true))::uuid)"));
        assertFalse(RiskRuntimeSchemaVerifier.exactTenantExpression(
                "((tenant_id = (current_setting('app.tenant_id'::text, true))::uuid) "
                        + "OR true)"));
    }

    private static RiskEvaluationRequest request(long amount) {
        return new RiskEvaluationRequest(TENANT, PROJECT, "PAYMENT_CREATE:key-1",
                RiskOperation.PAYMENT_CREATE, "merchant-1", amount, "USD", NOW,
                Map.of("channel", "api"));
    }

    private static String migration() throws Exception {
        try (var input = RiskRuntimeContractTest.class.getResourceAsStream(
                "/db/migration/V102__risk_engine_runtime.sql")) {
            if (input == null) throw new IllegalStateException("migration resource missing");
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String adminHardeningMigration() throws Exception {
        Path path = Path.of("apps/edge-gateway/src/main/resources/db/migration/"
                + "V103__admin_queue_runtime_role_hardening.sql");
        if (!Files.exists(path)) {
            path = Path.of("../../apps/edge-gateway/src/main/resources/db/migration/"
                    + "V103__admin_queue_runtime_role_hardening.sql");
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private static String source(String name) throws Exception {
        Path path = Path.of("src/main/java/com/elmpay/risk/runtime", name);
        if (!Files.exists(path)) {
            path = Path.of("services/risk-engine/src/main/java/com/elmpay/risk/runtime", name);
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private static void readonly(Path path) throws Exception {
        Files.setPosixFilePermissions(path, Set.of(PosixFilePermission.OWNER_READ));
    }

    private static final class MutableClock extends Clock {
        private Instant value;
        private MutableClock(Instant value) { this.value = value; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return value; }
    }
}
