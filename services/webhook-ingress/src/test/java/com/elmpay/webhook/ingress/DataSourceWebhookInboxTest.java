package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

final class DataSourceWebhookInboxTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final String RAW_DIGEST = "a".repeat(64);

    @Test
    void matchingConcurrentDuplicateIsAcknowledgedWithoutSecondInsert() {
        WebhookIngressService.VerifiedEvent event = event();
        String canonicalDigest = WebhookVerificationDigests.sha256(event.canonicalPayload());
        AtomicBoolean committed = new AtomicBoolean();
        DataSourceWebhookInbox inbox = new DataSourceWebhookInbox(dataSource(RAW_DIGEST,
                canonicalDigest, committed));

        assertFalse(inbox.store(context(), event, RAW_DIGEST));
        assertTrue(committed.get());
        assertTrue(DataSourceWebhookInbox.SELECT_DUPLICATE.contains("FOR UPDATE"));
    }

    @Test
    void reusedProviderEventIdWithDifferentRawDigestFailsClosed() {
        WebhookIngressService.VerifiedEvent event = event();
        String canonicalDigest = WebhookVerificationDigests.sha256(event.canonicalPayload());
        AtomicBoolean committed = new AtomicBoolean();
        DataSourceWebhookInbox inbox = new DataSourceWebhookInbox(dataSource("b".repeat(64),
                canonicalDigest, committed));

        assertThrows(DataSourceWebhookInbox.ProviderEventIdentityConflictException.class,
                () -> inbox.store(context(), event, RAW_DIGEST));
        assertFalse(committed.get());
    }

    private static WebhookIngressService.Context context() {
        return new WebhookIngressService.Context("tenant-001", "project-001", "stripe",
                "merchant-001", NOW);
    }

    private static WebhookIngressService.VerifiedEvent event() {
        return new WebhookIngressService.VerifiedEvent("evt-001", "payment.succeeded", "pi-001",
                "order-001", NOW.minusSeconds(1), "key-001", 1250L, "USD",
                WebhookIngressService.CANONICAL_SCHEMA_V1,
                "{\"schema\":\"provider-webhook-effect.v1\"}"
                        .getBytes(StandardCharsets.UTF_8));
    }

    private static DataSource dataSource(String storedRawDigest, String storedCanonicalDigest,
            AtomicBoolean committed) {
        return (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(),
                new Class<?>[] {DataSource.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("getConnection")) {
                        return connection(storedRawDigest, storedCanonicalDigest, committed);
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static Connection connection(String storedRawDigest, String storedCanonicalDigest,
            AtomicBoolean committed) {
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                new Class<?>[] {Connection.class}, (proxy, method, arguments) -> {
                    return switch (method.getName()) {
                        case "prepareStatement" -> statement((String) arguments[0],
                                storedRawDigest, storedCanonicalDigest);
                        case "commit" -> {
                            committed.set(true);
                            yield null;
                        }
                        default -> defaultValue(method.getReturnType());
                    };
                });
    }

    private static PreparedStatement statement(String sql, String storedRawDigest,
            String storedCanonicalDigest) {
        return (PreparedStatement) Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("executeUpdate")) {
                        return sql.startsWith("INSERT INTO provider_webhook_inbox") ? 0 : 1;
                    }
                    if (method.getName().equals("executeQuery")) {
                        return resultSet(storedRawDigest, storedCanonicalDigest);
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static ResultSet resultSet(String storedRawDigest, String storedCanonicalDigest) {
        AtomicBoolean first = new AtomicBoolean(true);
        return (ResultSet) Proxy.newProxyInstance(ResultSet.class.getClassLoader(),
                new Class<?>[] {ResultSet.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("next")) {
                        return first.getAndSet(false);
                    }
                    if (method.getName().equals("getString")) {
                        return switch ((String) arguments[0]) {
                            case "raw_body_sha256" -> storedRawDigest;
                            case "canonical_payload_sha256" -> storedCanonicalDigest;
                            case "currency" -> "USD";
                            case "canonical_schema" ->
                                    WebhookIngressService.CANONICAL_SCHEMA_V1;
                            default -> null;
                        };
                    }
                    if (method.getName().equals("getLong")) {
                        return 1250L;
                    }
                    if (method.getName().equals("wasNull")) {
                        return false;
                    }
                    return defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == float.class) {
            return 0F;
        }
        if (type == double.class) {
            return 0D;
        }
        if (type == char.class) {
            return '\0';
        }
        return null;
    }
}
