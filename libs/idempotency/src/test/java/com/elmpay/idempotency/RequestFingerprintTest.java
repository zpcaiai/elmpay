package com.elmpay.idempotency;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class RequestFingerprintTest {
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
