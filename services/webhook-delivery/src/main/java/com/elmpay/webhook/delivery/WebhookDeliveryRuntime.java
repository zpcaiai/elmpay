package com.elmpay.webhook.delivery;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.sql.DataSource;

/** Production composition that leases project-bound signing material for one delivery attempt. */
public final class WebhookDeliveryRuntime {
    public record KeyDescriptor(String projectId, String keyId, String secretReference,
            Instant validFrom, Instant validUntil) {
        public KeyDescriptor {
            requireId(projectId, "projectId");
            requireId(keyId, "keyId");
            if (secretReference == null
                    || !secretReference.matches("(kms|hsm|vault)://[^\\s]{3,300}")) {
                throw new IllegalArgumentException("secretReference has an invalid format");
            }
            Objects.requireNonNull(validFrom, "validFrom");
            Objects.requireNonNull(validUntil, "validUntil");
            if (!validUntil.isAfter(validFrom)) {
                throw new IllegalArgumentException("signing key validity is invalid");
            }
        }
    }

    public record Configuration(Set<String> approvedHosts, List<KeyDescriptor> keys) {
        public Configuration {
            approvedHosts = Set.copyOf(approvedHosts);
            keys = List.copyOf(keys);
            if (approvedHosts.isEmpty() != keys.isEmpty()) {
                throw new IllegalArgumentException(
                        "delivery runtime endpoints and signing keys must be configured together");
            }
        }
    }

    public static final class SecretLease implements AutoCloseable {
        private final String tenantId;
        private final String projectId;
        private final String keyId;
        private final String secretReference;
        private final String leaseId;
        private final Instant expiresAt;
        private final byte[] secret;
        private boolean closed;

        public SecretLease(String tenantId, String projectId, String keyId,
                String secretReference, String leaseId, Instant expiresAt, byte[] secret) {
            requireId(tenantId, "tenantId");
            requireId(projectId, "projectId");
            requireId(keyId, "keyId");
            requireId(leaseId, "leaseId");
            this.tenantId = tenantId;
            this.projectId = projectId;
            this.keyId = keyId;
            this.secretReference = Objects.requireNonNull(secretReference, "secretReference");
            this.leaseId = leaseId;
            this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
            byte[] supplied = Objects.requireNonNull(secret, "secret");
            if (supplied.length < 32 || supplied.length > 128) {
                throw new IllegalArgumentException("leased signing secret has an invalid size");
            }
            this.secret = supplied.clone();
        }

        public synchronized byte[] require(KeyDescriptor descriptor, String expectedTenant, Instant now,
                Duration maximumLifetime) {
            if (closed) {
                throw new IllegalStateException("signing secret lease is closed");
            }
            if (!tenantId.equals(expectedTenant) || !projectId.equals(descriptor.projectId())
                    || !keyId.equals(descriptor.keyId())
                    || !secretReference.equals(descriptor.secretReference())) {
                throw new SecurityException("signing secret lease binding mismatch");
            }
            if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plus(maximumLifetime))) {
                throw new SecurityException("signing secret lease lifetime is outside policy");
            }
            return secret.clone();
        }

        @Override
        public synchronized void close() {
            if (!closed) {
                Arrays.fill(secret, (byte) 0);
                closed = true;
            }
        }

        @Override
        public String toString() {
            return "SecretLease[leaseId=" + leaseId + ", secret=REDACTED]";
        }
    }

    @FunctionalInterface
    public interface SigningSecretResolver {
        SecretLease lease(String tenantId, KeyDescriptor descriptor, Duration maximumLifetime);
    }

    @FunctionalInterface
    public interface ConfigurationSource {
        Configuration load(String tenantId, Instant now);
    }

    public record Settings(Duration connectTimeout, Duration requestTimeout,
            Duration outboxLease, Duration baseBackoff, Duration maximumBackoff,
            Duration maximumSecretLease) {
        public Settings {
            connectTimeout = positive(connectTimeout, "connectTimeout");
            requestTimeout = positive(requestTimeout, "requestTimeout");
            outboxLease = positive(outboxLease, "outboxLease");
            baseBackoff = positive(baseBackoff, "baseBackoff");
            maximumBackoff = positive(maximumBackoff, "maximumBackoff");
            maximumSecretLease = positive(maximumSecretLease, "maximumSecretLease");
            if (baseBackoff.compareTo(maximumBackoff) > 0
                    || maximumSecretLease.compareTo(Duration.ofMinutes(5)) > 0) {
                throw new IllegalArgumentException("delivery runtime settings exceed safe bounds");
            }
        }

        public static Settings productionDefaults() {
            return new Settings(Duration.ofSeconds(2), Duration.ofSeconds(5),
                    Duration.ofSeconds(30), Duration.ofSeconds(5), Duration.ofMinutes(10),
                    Duration.ofMinutes(2));
        }
    }

    /** Tenant-scoped JDBC config; raw signing secrets are never stored in PostgreSQL. */
    public static final class JdbcConfigurationSource implements ConfigurationSource {
        private final DataSource dataSource;

        public JdbcConfigurationSource(DataSource dataSource) {
            this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        }

        @Override
        public Configuration load(String tenantId, Instant now) {
            requireId(tenantId, "tenantId");
            Objects.requireNonNull(now, "now");
            try (Connection connection = dataSource.getConnection()) {
                connection.setReadOnly(true);
                connection.setAutoCommit(false);
                setTenant(connection, tenantId);
                Set<String> hosts = activeHosts(connection, tenantId);
                List<KeyDescriptor> keys = activeKeys(connection, tenantId, now);
                connection.commit();
                return new Configuration(hosts, keys);
            } catch (SQLException exception) {
                throw new IllegalStateException("cannot load webhook delivery runtime", exception);
            }
        }

        private static Set<String> activeHosts(Connection connection, String tenantId)
                throws SQLException {
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT DISTINCT approved_host FROM webhook_endpoint
                     WHERE tenant_id=? AND status='ACTIVE'
                    """)) {
                statement.setString(1, tenantId);
                try (ResultSet result = statement.executeQuery()) {
                    java.util.LinkedHashSet<String> values = new java.util.LinkedHashSet<>();
                    while (result.next()) values.add(result.getString(1));
                    return Set.copyOf(values);
                }
            }
        }

        private static List<KeyDescriptor> activeKeys(Connection connection, String tenantId,
                Instant now) throws SQLException {
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT project_id, key_id, secret_ref, valid_from, valid_until
                      FROM webhook_signing_key
                     WHERE tenant_id=? AND status IN ('ACTIVE','OVERLAP')
                       AND valid_from<=? AND valid_until>?
                     ORDER BY project_id, valid_from, key_id
                    """)) {
                statement.setString(1, tenantId);
                statement.setObject(2, now);
                statement.setObject(3, now);
                try (ResultSet result = statement.executeQuery()) {
                    List<KeyDescriptor> values = new ArrayList<>();
                    while (result.next()) {
                        values.add(new KeyDescriptor(result.getString(1), result.getString(2),
                                result.getString(3), result.getTimestamp(4).toInstant(),
                                result.getTimestamp(5).toInstant()));
                    }
                    return List.copyOf(values);
                }
            }
        }

        private static void setTenant(Connection connection, String tenantId) throws SQLException {
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT set_config('app.tenant_id', ?, true)")) {
                statement.setString(1, tenantId);
                statement.execute();
            }
        }
    }

    private final DataSource dataSource;
    private final ConfigurationSource configurationSource;
    private final SigningSecretResolver secretResolver;
    private final Settings settings;
    private final Clock clock;

    public WebhookDeliveryRuntime(DataSource dataSource, ConfigurationSource configurationSource,
            SigningSecretResolver secretResolver, Settings settings, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.configurationSource = Objects.requireNonNull(configurationSource,
                "configurationSource");
        this.secretResolver = Objects.requireNonNull(secretResolver, "secretResolver");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Fully mounted production composition. The signing-secret mTLS identity, trust bundle and
     * rotating token are validated synchronously before this method returns.
     */
    public static WebhookDeliveryRuntime fromEnvironment(DataSource dataSource,
            Map<String, String> environment, Clock clock) {
        Objects.requireNonNull(dataSource, "dataSource");
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(clock, "clock");
        Settings settings = new Settings(
                duration(environment, "ELMPAY_WEBHOOK_DELIVERY_CONNECT_TIMEOUT_MILLISECONDS",
                        2_000, 10_000),
                duration(environment, "ELMPAY_WEBHOOK_DELIVERY_REQUEST_TIMEOUT_MILLISECONDS",
                        5_000, 10_000),
                duration(environment, "ELMPAY_WEBHOOK_DELIVERY_OUTBOX_LEASE_MILLISECONDS",
                        30_000, 300_000),
                duration(environment, "ELMPAY_WEBHOOK_DELIVERY_BASE_BACKOFF_MILLISECONDS",
                        5_000, 3_600_000),
                duration(environment, "ELMPAY_WEBHOOK_DELIVERY_MAXIMUM_BACKOFF_MILLISECONDS",
                        600_000, 86_400_000),
                duration(environment, "ELMPAY_WEBHOOK_DELIVERY_MAXIMUM_SECRET_LEASE_MILLISECONDS",
                        120_000, 300_000));
        HttpsWebhookSigningSecretResolver resolver =
                HttpsWebhookSigningSecretResolver.fromEnvironment(environment, clock);
        return new WebhookDeliveryRuntime(dataSource, new JdbcConfigurationSource(dataSource),
                resolver, settings, clock);
    }

    public WebhookDeliveryService.Outcome runOnce(String tenantId) {
        requireId(tenantId, "tenantId");
        Instant now = clock.instant();
        Configuration configuration = configurationSource.load(tenantId, now);
        if (configuration.approvedHosts().isEmpty()) {
            return WebhookDeliveryService.Outcome.IDLE;
        }
        List<SecretLease> leases = new ArrayList<>();
        List<WebhookDeliveryService.SigningKey> keys = new ArrayList<>();
        try {
            for (KeyDescriptor descriptor : configuration.keys()) {
                SecretLease lease = secretResolver.lease(tenantId, descriptor,
                        settings.maximumSecretLease());
                leases.add(lease);
                byte[] secret = lease.require(descriptor, tenantId, now,
                        settings.maximumSecretLease());
                try {
                    keys.add(new WebhookDeliveryService.SigningKey(descriptor.projectId(),
                            descriptor.keyId(), secret, descriptor.validFrom(),
                            descriptor.validUntil()));
                } finally {
                    Arrays.fill(secret, (byte) 0);
                }
            }
            try (WebhookDeliveryService.RotatingKeyRing ring =
                    new WebhookDeliveryService.RotatingKeyRing(keys)) {
                WebhookDeliveryService service = new WebhookDeliveryService(tenantId,
                        new DataSourceWebhookOutbox(dataSource),
                        new WebhookDeliveryService.JdkTransport(settings.connectTimeout()),
                        new WebhookDeliveryService.EndpointPolicy(configuration.approvedHosts(),
                                InetAddress::getAllByName), ring, settings.requestTimeout(),
                        settings.outboxLease(), settings.baseBackoff(),
                        settings.maximumBackoff(), clock);
                return service.deliverNext();
            }
        } finally {
            keys.forEach(WebhookDeliveryService.SigningKey::close);
            leases.forEach(SecretLease::close);
        }
    }

    private static Duration positive(Duration value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(field + " must be positive");
        }
        return value;
    }

    private static Duration duration(Map<String, String> environment, String key,
            long fallback, long maximum) {
        String configured = environment.get(key);
        long value = fallback;
        if (configured != null) {
            if (!configured.matches("(?:0|[1-9][0-9]{0,8})")) {
                throw new IllegalStateException(key + " is invalid");
            }
            value = Long.parseLong(configured);
        }
        if (value < 1 || value > maximum) {
            throw new IllegalStateException(key + " exceeds its production bound");
        }
        return Duration.ofMillis(value);
    }

    private static void requireId(String value, String field) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{3,64}")) {
            throw new IllegalArgumentException(field + " has an invalid format");
        }
    }
}
