package com.elmpay.payment.provider;

import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderPayment;
import com.elmpay.provider.ProviderRefund;
import com.elmpay.provider.VerifiedProviderEvent;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.LongSupplier;
import javax.sql.DataSource;

/** PostgreSQL circuit breaker whose outcome is derived exclusively from an executed call. */
public final class JdbcProviderCallCircuitBreaker implements ProviderCallCircuitBreaker {
    public record Policy(int failureRateBasisPoints, int minimumCalls, Duration openDuration,
            int halfOpenCalls, Duration observationWindow) {
        public Policy {
            if (failureRateBasisPoints < 1 || failureRateBasisPoints > 10_000
                    || minimumCalls < 1 || minimumCalls > 10_000
                    || halfOpenCalls < 1 || halfOpenCalls > 32
                    || openDuration == null || openDuration.isNegative() || openDuration.isZero()
                    || openDuration.compareTo(Duration.ofMinutes(30)) > 0
                    || observationWindow == null
                    || observationWindow.compareTo(openDuration) < 0
                    || observationWindow.compareTo(Duration.ofHours(24)) > 0) {
                throw new IllegalArgumentException("provider circuit policy is outside safe bounds");
            }
        }

        public static Policy fromEnvironment(Map<String, String> environment) {
            int threshold = integer(environment, "ELMPAY_PROVIDER_BREAKER_FAILURE_BASIS_POINTS",
                    2_000, 1, 10_000);
            int minimum = integer(environment, "ELMPAY_PROVIDER_BREAKER_MINIMUM_CALLS",
                    20, 1, 10_000);
            int openSeconds = integer(environment, "ELMPAY_PROVIDER_BREAKER_OPEN_SECONDS",
                    30, 1, 1_800);
            int probes = integer(environment, "ELMPAY_PROVIDER_BREAKER_HALF_OPEN_CALLS",
                    3, 1, 32);
            int windowSeconds = integer(environment, "ELMPAY_PROVIDER_BREAKER_WINDOW_SECONDS",
                    Math.max(60, openSeconds * 2), openSeconds, 86_400);
            return new Policy(threshold, minimum, Duration.ofSeconds(openSeconds), probes,
                    Duration.ofSeconds(windowSeconds));
        }

        private static int integer(Map<String, String> environment, String key, int fallback,
                int minimum, int maximum) {
            String configured = environment.get(key);
            int value = fallback;
            if (configured != null && !configured.isBlank()) {
                try {
                    value = Integer.parseInt(configured);
                } catch (NumberFormatException exception) {
                    throw new IllegalStateException(key + " is invalid", exception);
                }
            }
            if (value < minimum || value > maximum) {
                throw new IllegalStateException(key + " is outside its safe bound");
            }
            return value;
        }
    }

    private record Permit(boolean allowed) { }
    record Observation(boolean succeeded, String errorClass) { }
    enum Admission { ALLOW, DENY, BEGIN_HALF_OPEN }

    private final DataSource dataSource;
    private final Policy policy;
    private final Clock clock;
    private final LongSupplier monotonicNanos;

    public JdbcProviderCallCircuitBreaker(DataSource dataSource, Policy policy, Clock clock) {
        this(dataSource, policy, clock, System::nanoTime);
    }

    JdbcProviderCallCircuitBreaker(DataSource dataSource, Policy policy, Clock clock,
            LongSupplier monotonicNanos) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.monotonicNanos = Objects.requireNonNull(monotonicNanos, "monotonicNanos");
    }

    @Override
    public <T> T execute(UUID tenantId, UUID providerAccountId, String provider,
            Operation operation, ProviderCall<T> call) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(providerAccountId, "providerAccountId");
        String normalizedProvider = provider(provider);
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(call, "call");
        Instant startedAt = clock.instant();
        if (!acquire(tenantId, providerAccountId, normalizedProvider, startedAt).allowed()) {
            throw new ProviderException("PROVIDER_CIRCUIT_OPEN",
                    "provider account circuit is not available", false, false);
        }
        long startedNanos = monotonicNanos.getAsLong();
        T result;
        Observation observation;
        try {
            result = call.invoke();
            observation = resultObservation(result);
        } catch (RuntimeException exception) {
            observation = exceptionObservation(exception);
            try {
                record(tenantId, providerAccountId, normalizedProvider, operation,
                        observation, elapsedMillis(startedNanos), clock.instant());
            } catch (RuntimeException accountingFailure) {
                exception.addSuppressed(accountingFailure);
            }
            throw exception;
        }
        recordOrFail(tenantId, providerAccountId, normalizedProvider, operation,
                observation, elapsedMillis(startedNanos), clock.instant(), true);
        return result;
    }

    static Observation resultObservation(Object result) {
        if (result instanceof ProviderPayment payment) {
            return payment.outcome() == ProviderOutcome.UNKNOWN
                    ? new Observation(false, "UNKNOWN_OUTCOME")
                    : new Observation(true, null);
        }
        if (result instanceof ProviderRefund refund) {
            return refund.outcome() == ProviderOutcome.UNKNOWN
                    ? new Observation(false, "UNKNOWN_OUTCOME")
                    : new Observation(true, null);
        }
        if (result instanceof VerifiedProviderEvent) {
            return new Observation(true, null);
        }
        throw new ProviderException("PROVIDER_RESULT_INVALID",
                "provider runtime returned an unsupported result", false, true);
    }

    static Observation exceptionObservation(RuntimeException exception) {
        if (exception instanceof ProviderException providerFailure) {
            if (!providerFailure.retryable() && !providerFailure.outcomeUnknown()) {
                return new Observation(true, "CALL_REJECTED");
            }
            return new Observation(false, providerFailure.outcomeUnknown()
                    ? "UNKNOWN_OUTCOME" : "RETRYABLE_PROVIDER_FAILURE");
        }
        if (exception instanceof SecurityException || exception instanceof IllegalArgumentException) {
            return new Observation(true, "CALL_REJECTED");
        }
        return new Observation(false, "RUNTIME_FAILURE");
    }

    private Permit acquire(UUID tenantId, UUID providerAccountId, String provider, Instant now) {
        String insert = """
                INSERT INTO provider_call_circuit
                  (tenant_id,provider_account_id,provider,state,open_until,
                   half_open_successes,half_open_in_flight,version,updated_at)
                VALUES (?::uuid,?::uuid,?,'HEALTHY',NULL,0,false,1,?::timestamptz)
                ON CONFLICT (tenant_id,provider_account_id,provider) DO NOTHING
                """;
        String select = """
                SELECT state,open_until,half_open_successes,half_open_in_flight
                  FROM provider_call_circuit
                 WHERE tenant_id=?::uuid AND provider_account_id=?::uuid AND provider=?
                 FOR UPDATE
                """;
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                try (PreparedStatement statement = connection.prepareStatement(insert)) {
                    bindKey(statement, tenantId, providerAccountId, provider);
                    statement.setString(4, now.toString());
                    statement.executeUpdate();
                }
                boolean allowed;
                try (PreparedStatement statement = connection.prepareStatement(select)) {
                    bindKey(statement, tenantId, providerAccountId, provider);
                    try (ResultSet row = statement.executeQuery()) {
                        if (!row.next()) {
                            throw new IllegalStateException("provider circuit state is missing");
                        }
                        String state = row.getString(1);
                        Timestamp openUntil = row.getTimestamp(2);
                        int successes = row.getInt(3);
                        boolean inFlight = row.getBoolean(4);
                        Admission decision = admission(state,
                                openUntil == null ? null : openUntil.toInstant(), successes,
                                inFlight, now, policy.halfOpenCalls());
                        allowed = switch (decision) {
                            case ALLOW -> true;
                            case DENY -> false;
                            case BEGIN_HALF_OPEN -> beginHalfOpen(connection, tenantId,
                                    providerAccountId, provider, now,
                                    "OPEN".equals(state) ? 0 : successes);
                        };
                    }
                }
                connection.commit();
                return new Permit(allowed);
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException | RuntimeException exception) {
            if (exception instanceof ProviderException providerException) {
                throw providerException;
            }
            throw stateUnavailable(exception, false);
        }
    }

    static Admission admission(String state, Instant openUntil, int halfOpenSuccesses,
            boolean halfOpenInFlight, Instant now, int maximumHalfOpenCalls) {
        if (state == null || now == null || maximumHalfOpenCalls < 1
                || halfOpenSuccesses < 0) {
            return Admission.DENY;
        }
        return switch (state) {
            case "HEALTHY", "DEGRADED" -> Admission.ALLOW;
            case "OPEN" -> openUntil != null && !now.isBefore(openUntil)
                    ? Admission.BEGIN_HALF_OPEN : Admission.DENY;
            case "HALF_OPEN" -> !halfOpenInFlight
                    && halfOpenSuccesses < maximumHalfOpenCalls
                    ? Admission.BEGIN_HALF_OPEN : Admission.DENY;
            case "UNKNOWN" -> Admission.DENY;
            default -> Admission.DENY;
        };
    }

    private boolean beginHalfOpen(Connection connection, UUID tenantId, UUID accountId,
            String provider, Instant now, int successes) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE provider_call_circuit
                   SET state='HALF_OPEN',open_until=NULL,half_open_successes=?,
                       half_open_in_flight=true,version=version+1,updated_at=?::timestamptz
                 WHERE tenant_id=?::uuid AND provider_account_id=?::uuid AND provider=?
                """)) {
            statement.setInt(1, successes);
            statement.setString(2, now.toString());
            statement.setString(3, tenantId.toString());
            statement.setString(4, accountId.toString());
            statement.setString(5, provider);
            return statement.executeUpdate() == 1;
        }
    }

    private void recordOrFail(UUID tenantId, UUID accountId, String provider,
            Operation operation, Observation observation, int latencyMillis, Instant observedAt,
            boolean providerReturned) {
        try {
            record(tenantId, accountId, provider, operation, observation, latencyMillis,
                    observedAt);
        } catch (RuntimeException exception) {
            ProviderException failure = stateUnavailable(exception, providerReturned);
            throw failure;
        }
    }

    private void record(UUID tenantId, UUID accountId, String provider, Operation operation,
            Observation observation, int latencyMillis, Instant observedAt) {
        Instant windowStart = observedAt.minus(policy.observationWindow());
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                CircuitState prior = lockState(connection, tenantId, accountId, provider);
                if (prior == null || "UNKNOWN".equals(prior.state())) {
                    throw new IllegalStateException("provider circuit state is unknown");
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO provider_call_outcome
                          (outcome_id,tenant_id,provider_account_id,provider,operation,
                           observed_at,succeeded,latency_ms,error_class)
                        VALUES (?::uuid,?::uuid,?::uuid,?,?,?::timestamptz,?,?,?)
                        """)) {
                    statement.setString(1, UUID.randomUUID().toString());
                    statement.setString(2, tenantId.toString());
                    statement.setString(3, accountId.toString());
                    statement.setString(4, provider);
                    statement.setString(5, operation.name());
                    statement.setString(6, observedAt.toString());
                    statement.setBoolean(7, observation.succeeded());
                    statement.setInt(8, latencyMillis);
                    statement.setString(9, observation.errorClass());
                    statement.executeUpdate();
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        DELETE FROM provider_call_outcome
                         WHERE tenant_id=?::uuid AND provider_account_id=?::uuid AND provider=?
                           AND observed_at < ?::timestamptz
                        """)) {
                    bindKey(statement, tenantId, accountId, provider);
                    statement.setString(4, windowStart.toString());
                    statement.executeUpdate();
                }
                Counts counts = counts(connection, tenantId, accountId, provider, windowStart);
                Transition transition = transition(prior, observation, counts,
                        observedAt);
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE provider_call_circuit
                           SET state=?,open_until=?::timestamptz,half_open_successes=?,
                               half_open_in_flight=false,version=version+1,
                               updated_at=?::timestamptz
                         WHERE tenant_id=?::uuid AND provider_account_id=?::uuid AND provider=?
                        """)) {
                    statement.setString(1, transition.state());
                    statement.setString(2, transition.openUntil() == null
                            ? null : transition.openUntil().toString());
                    statement.setInt(3, transition.halfOpenSuccesses());
                    statement.setString(4, observedAt.toString());
                    statement.setString(5, tenantId.toString());
                    statement.setString(6, accountId.toString());
                    statement.setString(7, provider);
                    if (statement.executeUpdate() != 1) {
                        throw new IllegalStateException("provider circuit state update was lost");
                    }
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("provider circuit outcome could not be recorded",
                    exception);
        }
    }

    private record CircuitState(String state, int halfOpenSuccesses) { }
    private record Counts(int calls, int failures) { }
    private record Transition(String state, Instant openUntil, int halfOpenSuccesses) { }

    private CircuitState lockState(Connection connection, UUID tenantId, UUID accountId,
            String provider) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT state,half_open_successes FROM provider_call_circuit
                 WHERE tenant_id=?::uuid AND provider_account_id=?::uuid AND provider=?
                 FOR UPDATE
                """)) {
            bindKey(statement, tenantId, accountId, provider);
            try (ResultSet row = statement.executeQuery()) {
                return row.next() ? new CircuitState(row.getString(1), row.getInt(2)) : null;
            }
        }
    }

    private Counts counts(Connection connection, UUID tenantId, UUID accountId, String provider,
            Instant windowStart) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT count(*),count(*) FILTER (WHERE NOT succeeded)
                  FROM provider_call_outcome
                 WHERE tenant_id=?::uuid AND provider_account_id=?::uuid AND provider=?
                   AND observed_at >= ?::timestamptz
                   AND error_class IS DISTINCT FROM 'CALL_REJECTED'
                """)) {
            bindKey(statement, tenantId, accountId, provider);
            statement.setString(4, windowStart.toString());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) {
                    throw new IllegalStateException("provider circuit outcome window is unavailable");
                }
                return new Counts(row.getInt(1), row.getInt(2));
            }
        }
    }

    private Transition transition(CircuitState prior, Observation observation, Counts counts,
            Instant observedAt) {
        if ("CALL_REJECTED".equals(observation.errorClass())) {
            return new Transition(prior.state(), null, prior.halfOpenSuccesses());
        }
        if ("HALF_OPEN".equals(prior.state())) {
            if (!observation.succeeded()) {
                return new Transition("OPEN", observedAt.plus(policy.openDuration()), 0);
            }
            int completed = prior.halfOpenSuccesses() + 1;
            return completed >= policy.halfOpenCalls()
                    ? new Transition("HEALTHY", null, 0)
                    : new Transition("HALF_OPEN", null, completed);
        }
        boolean thresholdReached = counts.calls() >= policy.minimumCalls()
                && (long) counts.failures() * 10_000L
                >= (long) counts.calls() * policy.failureRateBasisPoints();
        if (thresholdReached) {
            return new Transition("OPEN", observedAt.plus(policy.openDuration()), 0);
        }
        return new Transition(observation.succeeded() ? "HEALTHY" : "DEGRADED", null, 0);
    }

    private int elapsedMillis(long startedNanos) {
        long elapsed = Math.max(0, monotonicNanos.getAsLong() - startedNanos);
        return (int) Math.min(Integer.MAX_VALUE, elapsed / 1_000_000L);
    }

    private static void bindKey(PreparedStatement statement, UUID tenantId, UUID accountId,
            String provider) throws SQLException {
        statement.setString(1, tenantId.toString());
        statement.setString(2, accountId.toString());
        statement.setString(3, provider);
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private static String provider(String value) {
        String normalized = Objects.requireNonNull(value, "provider").toLowerCase(Locale.ROOT);
        if (!normalized.matches("[a-z][a-z0-9_]{1,31}")) {
            throw new IllegalArgumentException("provider is invalid");
        }
        return normalized;
    }

    private static ProviderException stateUnavailable(Exception cause,
            boolean outcomeUnknown) {
        ProviderException failure = new ProviderException("PROVIDER_CIRCUIT_STATE_UNAVAILABLE",
                "provider circuit state is unavailable", false, outcomeUnknown);
        failure.addSuppressed(cause);
        return failure;
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }
}
