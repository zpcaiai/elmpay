package com.elmpay.gateway;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class AdminActionRuntimeFactoryTest {
    @Test
    void runtimeIsOptInAndProductionOnly() {
        assertTrue(AdminActionRuntimeFactory.create("postgres", Map.of(),
                Clock.systemUTC()).isEmpty());
        assertThrows(IllegalStateException.class, () -> AdminActionRuntimeFactory.create(
                "local", Map.of("ELMPAY_ADMIN_ACTIONS_ENABLED", "true"),
                Clock.systemUTC()));
    }

    @Test
    void enabledRuntimeRequiresExplicitDatabaseTlsAndSpiffeIdentity() {
        Map<String, String> environment = new HashMap<>();
        environment.put("ELMPAY_ADMIN_ACTIONS_ENABLED", "true");
        environment.put("ELMPAY_DATABASE_URL", "jdbc:postgresql://postgres.elmpay/db");
        environment.put("ELMPAY_DATABASE_USERNAME", "admin_action_runtime");
        environment.put("ELMPAY_DATABASE_PASSWORD_FILE", "/secrets/database/password");
        environment.put("ELMPAY_DATABASE_CA_FILE", "/secrets/database/ca.crt");
        environment.put("ELMPAY_DATABASE_CLIENT_CERTIFICATE_FILE",
                "/secrets/database/tls.crt");
        environment.put("ELMPAY_DATABASE_CLIENT_PRIVATE_KEY_FILE",
                "/secrets/database/tls.key");
        assertThrows(IllegalStateException.class, () -> AdminActionRuntimeFactory.create(
                "postgres", environment, Clock.systemUTC()));
        environment.put("ELMPAY_ADMIN_ACTION_EXPECTED_SPIFFE_ID",
                "spiffe://elmpay.example/admin-web");
        assertTrue(AdminActionRuntimeFactory.create("postgres", environment,
                Clock.systemUTC()).isPresent());
    }
}
