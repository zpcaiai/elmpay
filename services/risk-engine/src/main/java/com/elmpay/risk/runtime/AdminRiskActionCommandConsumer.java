package com.elmpay.risk.runtime;

import com.elmpay.admin.AdminDomainCommand;
import com.elmpay.admin.AdminDomainCommandQueue;
import com.elmpay.admin.JdbcAdminDomainCommandQueue;
import com.elmpay.risk.CanonicalDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;

/** Leased, fenced consumer for risk-owned admin commands. */
public final class AdminRiskActionCommandConsumer implements Runnable, AutoCloseable {
    private static final Duration READY_STALENESS = Duration.ofSeconds(10);
    private final DataSource dataSource;
    private final AdminDomainCommandQueue queue;
    private final JdbcRiskControlPlane controls;
    private final Clock clock;
    private final String workerId;
    private final Duration lease;
    private final Duration pollInterval;
    private final Instant capabilityValidUntil;
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicReference<Instant> lastSuccessfulCycle = new AtomicReference<>(Instant.MIN);
    private volatile Thread thread;

    public AdminRiskActionCommandConsumer(DataSource dataSource, JdbcRiskControlPlane controls,
            Clock clock, String workerId, Duration lease, Duration pollInterval,
            Instant capabilityValidUntil) {
        this(dataSource, new JdbcAdminDomainCommandQueue(), controls, clock, workerId, lease,
                pollInterval, capabilityValidUntil);
    }

    AdminRiskActionCommandConsumer(DataSource dataSource, AdminDomainCommandQueue queue,
            JdbcRiskControlPlane controls, Clock clock, String workerId, Duration lease,
            Duration pollInterval, Instant capabilityValidUntil) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.queue = Objects.requireNonNull(queue, "queue");
        this.controls = Objects.requireNonNull(controls, "controls");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (workerId == null || !workerId.matches("[A-Za-z0-9._:-]{8,128}")) {
            throw new IllegalArgumentException("risk admin worker identity is invalid");
        }
        this.workerId = workerId;
        this.lease = bounded(lease, Duration.ofSeconds(5), Duration.ofSeconds(60), "lease");
        this.pollInterval = bounded(pollInterval, Duration.ofMillis(25), Duration.ofSeconds(5),
                "poll interval");
        this.capabilityValidUntil = Objects.requireNonNull(capabilityValidUntil,
                "capabilityValidUntil");
    }

    public synchronized void start() {
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("risk admin consumer is already running");
        }
        thread = Thread.ofPlatform().name("risk-admin-command-consumer").start(this);
    }

    @Override
    public void run() {
        long delay = pollInterval.toMillis();
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            try {
                boolean processed = runOnce();
                delay = pollInterval.toMillis();
                if (!processed) sleep(delay);
            } catch (SQLException | RuntimeException failure) {
                // Never render command, exception, tenant, target, or credential data to logs.
                sleep(delay);
                delay = Math.min(5_000, Math.max(pollInterval.toMillis(), delay * 2));
            }
        }
        running.set(false);
    }

    boolean runOnce() throws SQLException {
        Optional<AdminDomainCommandQueue.Claim> selected = claim();
        if (selected.isEmpty()) {
            lastSuccessfulCycle.set(clock.instant());
            return false;
        }
        AdminDomainCommandQueue.Claim claim = selected.orElseThrow();
        try {
            execute(claim);
            lastSuccessfulCycle.set(clock.instant());
            return true;
        } catch (JdbcRiskControlPlane.AdminCommandRejectedException rejected) {
            block(claim, "INVALID_BINDING");
            lastSuccessfulCycle.set(clock.instant());
            return true;
        } catch (UnknownCommitException uncertain) {
            if (retryOrReconcile(claim, "COMMIT_OUTCOME_UNKNOWN", true)) {
                lastSuccessfulCycle.set(clock.instant());
                return true;
            }
            throw uncertain.sqlException();
        } catch (SQLException failure) {
            if (retryOrReconcile(claim, "DATABASE_OPERATION_FAILED", false)) {
                lastSuccessfulCycle.set(clock.instant());
                return true;
            }
            throw failure;
        }
    }

    public boolean ready() {
        Instant success = lastSuccessfulCycle.get();
        return running.get() && !success.equals(Instant.MIN)
                && success.plus(READY_STALENESS).isAfter(clock.instant())
                && capabilityValidUntil.isAfter(clock.instant());
    }

    private Optional<AdminDomainCommandQueue.Claim> claim() throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            begin(connection);
            try {
                Optional<AdminDomainCommandQueue.Claim> claim = queue.claim(connection,
                        AdminDomainCommand.ConsumerGroup.RISK, workerId, lease);
                connection.commit();
                return claim;
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        }
    }

    private void execute(AdminDomainCommandQueue.Claim claim) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            begin(connection);
            try {
                Instant now = databaseNow(connection);
                String effectDigest = controls.applyApprovedAdminCommand(connection, claim, now);
                queue.complete(connection, claim, effectDigest, now);
                try {
                    connection.commit();
                } catch (SQLException uncertain) {
                    throw new UnknownCommitException(uncertain);
                }
            } catch (UnknownCommitException uncertain) {
                try { connection.rollback(); } catch (SQLException ignored) {
                    uncertain.sqlException().addSuppressed(ignored);
                }
                throw uncertain;
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        }
    }

    private void block(AdminDomainCommandQueue.Claim claim, String failureCode)
            throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            begin(connection);
            try {
                Instant now = databaseNow(connection);
                boolean changed = queue.block(connection, claim, failureCode,
                        diagnostic(claim, failureCode), now);
                if (!changed) throw new SQLException("admin risk command block lost its fence");
                connection.commit();
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        }
    }

    /** Return true only when an uncertain commit is reconciled to an existing receipt. */
    private boolean retryOrReconcile(AdminDomainCommandQueue.Claim claim, String failureCode,
            boolean outcomeUnknown) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            begin(connection);
            try {
                Instant now = databaseNow(connection);
                Instant retryAt = now.plus(retryDelay(claim.attempt()));
                boolean changed = queue.retry(connection, claim, failureCode,
                        diagnostic(claim, failureCode), retryAt, outcomeUnknown, now);
                boolean receipt = false;
                if (!changed) {
                    receipt = queue.findReceipt(connection, claim.command().tenantId(),
                            claim.command().idempotencyKey()).isPresent();
                    if (!receipt) {
                        throw new SQLException("admin risk retry lost its fence without receipt");
                    }
                }
                connection.commit();
                return receipt;
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        }
    }

    private static Instant databaseNow(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT clock_timestamp()" );
                ResultSet result = statement.executeQuery()) {
            if (!result.next()) throw new SQLException("database clock returned no row");
            return result.getTimestamp(1).toInstant();
        }
    }

    private static void begin(Connection connection) throws SQLException {
        connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
        connection.setAutoCommit(false);
    }

    private static void rollback(Connection connection, Throwable failure) {
        try {
            connection.rollback();
        } catch (SQLException rollback) {
            failure.addSuppressed(rollback);
        }
    }

    private static Duration retryDelay(int attempt) {
        long multiplier = 1L << Math.min(6, Math.max(0, attempt - 1));
        return Duration.ofMillis(Math.min(30_000, 250 * multiplier));
    }

    private static String diagnostic(AdminDomainCommandQueue.Claim claim, String code) {
        return CanonicalDigest.sha256(List.of("risk-admin-consumer-diagnostic-v1", code,
                claim.command().commandDigest(), Integer.toString(claim.attempt()),
                Long.toString(claim.fencingToken())));
    }

    private static Duration bounded(Duration value, Duration minimum, Duration maximum,
            String name) {
        Objects.requireNonNull(value, name);
        if (value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException("risk admin " + name + " is out of bounds");
        }
        return value;
    }

    private static void sleep(long milliseconds) {
        try {
            Thread.sleep(Math.max(1, milliseconds));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public synchronized void close() {
        running.set(false);
        Thread active = thread;
        if (active != null) {
            active.interrupt();
            try {
                active.join(2_000);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static final class UnknownCommitException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final SQLException sqlException;

        private UnknownCommitException(SQLException sqlException) {
            super("admin risk command commit outcome is unknown", sqlException);
            this.sqlException = Objects.requireNonNull(sqlException, "sqlException");
        }

        private SQLException sqlException() { return sqlException; }
    }
}
