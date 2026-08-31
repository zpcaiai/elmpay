package com.elmpay.gateway;

import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Fail-closed construction of the co-deployed internal Admin Action API. */
public final class AdminActionRuntimeFactory {
    private AdminActionRuntimeFactory() {
    }

    public record Runtime(JdbcAdminActionService service,
            AdminActionPeerVerifier peerVerifier) {
        public Runtime {
            Objects.requireNonNull(service, "service");
            Objects.requireNonNull(peerVerifier, "peerVerifier");
        }
    }

    public static Optional<Runtime> create(String mode, Map<String, String> environment,
            Clock clock) {
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(clock, "clock");
        String enabled = environment.getOrDefault("ELMPAY_ADMIN_ACTIONS_ENABLED", "false");
        if (!SetValues.BOOLEAN.contains(enabled)) {
            throw new IllegalStateException("ELMPAY_ADMIN_ACTIONS_ENABLED must be true or false");
        }
        if (!Boolean.parseBoolean(enabled)) {
            return Optional.empty();
        }
        if (!"postgres".equals(mode)) {
            throw new IllegalStateException(
                    "admin actions can only run against the durable PostgreSQL runtime");
        }
        DriverManagerDataSource dataSource = DriverManagerDataSource.fromEnvironment(environment,
                "elmpay-admin-action-api");
        return Optional.of(new Runtime(new JdbcAdminActionService(dataSource),
                AdminActionPeerVerifier.fromEnvironment(environment, clock)));
    }

    private static final class SetValues {
        private static final java.util.Set<String> BOOLEAN = java.util.Set.of("true", "false");

        private SetValues() {
        }
    }
}
