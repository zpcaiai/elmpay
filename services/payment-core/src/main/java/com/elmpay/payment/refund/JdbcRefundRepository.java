package com.elmpay.payment.refund;

import com.elmpay.money.Money;
import com.elmpay.payment.PaymentCoreException;
import com.elmpay.security.CanonicalPayload;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL refund repository with RLS, row locks, action receipts and transactional outbox. */
public final class JdbcRefundRepository implements RefundRepository {
    private static final String COLUMNS = """
            id, tenant_id, project_id, payment_intent_id, provider_account_id, provider,
            provider_payment_id, amount_minor, currency, reason, state, risk_decision,
            risk_context_digest, idempotency_key, request_digest, requester_id, approved_by,
            approval_reason, approval_ticket_id, provider_refund_id, provider_outcome_digest,
            failure_code, correlation_id, created_at, updated_at, version
            """;
    private final DataSource dataSource;

    public JdbcRefundRepository(DataSource dataSource) {
        this.dataSource = java.util.Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public Optional<RefundRecord> find(UUID tenantId, UUID refundId) {
        return queryOne(tenantId, "SELECT " + COLUMNS
                + " FROM refund WHERE tenant_id = ?::uuid AND id = ?::uuid",
                statement -> {
                    statement.setString(1, tenantId.toString());
                    statement.setString(2, refundId.toString());
                });
    }

    @Override
    public Optional<RefundRecord> findByRequestKey(UUID tenantId, String idempotencyKey) {
        return queryOne(tenantId, "SELECT " + COLUMNS
                + " FROM refund WHERE tenant_id = ?::uuid AND idempotency_key = ?",
                statement -> {
                    statement.setString(1, tenantId.toString());
                    statement.setString(2, idempotencyKey);
                });
    }

    @Override
    public Optional<RefundActionReceipt> findActionReceipt(UUID tenantId, UUID refundId,
            String idempotencyKey) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                RefundActionReceipt receipt = findReceipt(connection, tenantId, idempotencyKey);
                connection.commit();
                return receipt != null && receipt.refundId().equals(refundId)
                        ? Optional.of(receipt) : Optional.empty();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot read refund action receipt", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot read refund action receipt", exception);
        }
    }

    @Override
    public WriteResult createAndReserve(RefundRecord proposed, long capturedAmountMinor,
            long alreadyRefundedAmountMinor, String eventType) {
        validatePaymentAmounts(capturedAmountMinor, alreadyRefundedAmountMinor);
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, proposed.tenantId());
                advisoryLock(connection, "refund:idempotency:" + proposed.tenantId() + ":"
                        + proposed.requestIdempotencyKey());
                RefundRecord replay = findByRequestKey(connection, proposed.tenantId(),
                        proposed.requestIdempotencyKey(), false);
                if (replay != null) {
                    requireSameRequest(replay, proposed.requestDigest());
                    connection.commit();
                    return new WriteResult(replay, true);
                }
                if (findReceipt(connection, proposed.tenantId(),
                        proposed.requestIdempotencyKey()) != null) {
                    throw conflict("refund request key already belongs to an action");
                }
                PaymentAmounts payment = lockPayment(connection, proposed);
                if (proposed.status().holdsReservation()) {
                    long pending = pendingReservations(connection, proposed.tenantId(),
                            proposed.paymentIntentId());
                    long used = Math.addExact(payment.refundedAmountMinor(), pending);
                    if (proposed.amount().amountMinor() > payment.capturedAmountMinor() - used) {
                        throw new PaymentCoreException("REFUND_AMOUNT_EXCEEDS_REFUNDABLE",
                                "refund exceeds the atomically reserved refundable amount");
                    }
                }
                insertRefund(connection, proposed);
                appendOutbox(connection, proposed, eventType, null);
                connection.commit();
                return new WriteResult(proposed, false);
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot reserve refund amount", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot reserve refund amount", exception);
        }
    }

    @Override
    public WriteResult transitionWithReceipt(RefundRecord expected, RefundRecord proposed,
            RefundActionReceipt receipt, String eventType) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, expected.tenantId());
                advisoryLock(connection, "refund:idempotency:" + receipt.tenantId() + ":"
                        + receipt.idempotencyKey());
                RefundActionReceipt replay = findReceipt(connection, receipt.tenantId(),
                        receipt.idempotencyKey());
                if (replay != null) {
                    requireSameReceipt(replay, receipt);
                    RefundRecord current = currentRefund(connection, replay.tenantId(),
                            replay.refundId(), false);
                    connection.commit();
                    return new WriteResult(current, true);
                }
                requireActionKeyUnusedByRequest(connection, receipt);
                RefundRecord current = currentRefund(connection, expected.tenantId(),
                        expected.id(), true);
                requireExpected(current, expected);
                requireTransition(current, proposed);
                requireReceipt(receipt, proposed);
                updateRefund(connection, proposed, current.version());
                insertReceipt(connection, receipt);
                appendOutbox(connection, proposed, eventType, receipt);
                connection.commit();
                return new WriteResult(proposed, false);
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot apply refund action", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot apply refund action", exception);
        }
    }

    @Override
    public WriteResult claimAction(RefundRecord expected, RefundActionReceipt receipt,
            String eventType) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, expected.tenantId());
                advisoryLock(connection, "refund:idempotency:" + receipt.tenantId() + ":"
                        + receipt.idempotencyKey());
                RefundActionReceipt replay = findReceipt(connection, receipt.tenantId(),
                        receipt.idempotencyKey());
                if (replay != null) {
                    requireSameReceipt(replay, receipt);
                    RefundRecord current = currentRefund(connection, replay.tenantId(),
                            replay.refundId(), false);
                    connection.commit();
                    return new WriteResult(current, true);
                }
                requireActionKeyUnusedByRequest(connection, receipt);
                RefundRecord current = currentRefund(connection, expected.tenantId(),
                        expected.id(), true);
                requireExpected(current, expected);
                if (receipt.resultVersion() != current.version()
                        || !receipt.refundId().equals(current.id())) {
                    throw new PaymentCoreException("REFUND_ACTION_RECEIPT_INVALID",
                            "refund action receipt does not match the current aggregate");
                }
                insertReceipt(connection, receipt);
                appendOutbox(connection, current, eventType, receipt);
                connection.commit();
                return new WriteResult(current, false);
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot claim refund action", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot claim refund action", exception);
        }
    }

    @Override
    public RefundRecord recordProviderOutcome(RefundRecord expected, RefundRecord proposed,
            String eventType) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, expected.tenantId());
                RefundRecord current = currentRefund(connection, expected.tenantId(),
                        expected.id(), true);
                requireExpected(current, expected);
                requireTransition(current, proposed);
                if (proposed.status() == RefundStatus.SUCCEEDED) {
                    applySuccessfulRefund(connection, proposed);
                }
                updateRefund(connection, proposed, current.version());
                appendOutbox(connection, proposed, eventType, null);
                connection.commit();
                return proposed;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot record provider refund outcome", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot record provider refund outcome", exception);
        }
    }

    @Override
    public long remainingRefundable(UUID tenantId, UUID paymentIntentId,
            long capturedAmountMinor, long alreadyRefundedAmountMinor) {
        validatePaymentAmounts(capturedAmountMinor, alreadyRefundedAmountMinor);
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                PaymentAmounts payment = paymentAmounts(connection, tenantId, paymentIntentId,
                        false);
                long pending = pendingReservations(connection, tenantId, paymentIntentId);
                connection.commit();
                return Math.max(0, payment.capturedAmountMinor()
                        - Math.addExact(payment.refundedAmountMinor(), pending));
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot read refundable amount", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot read refundable amount", exception);
        }
    }

    private Optional<RefundRecord> queryOne(UUID tenantId, String sql, SqlBinder binder) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    binder.bind(statement);
                    try (ResultSet result = statement.executeQuery()) {
                        RefundRecord refund = result.next() ? refund(result) : null;
                        connection.commit();
                        return Optional.ofNullable(refund);
                    }
                }
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot read refund", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot read refund", exception);
        }
    }

    private static RefundRecord findByRequestKey(Connection connection, UUID tenantId,
            String key, boolean forUpdate) throws SQLException {
        String sql = "SELECT " + COLUMNS + " FROM refund WHERE tenant_id = ?::uuid"
                + " AND idempotency_key = ?" + (forUpdate ? " FOR UPDATE" : "");
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, key);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? refund(result) : null;
            }
        }
    }

    private static RefundRecord currentRefund(Connection connection, UUID tenantId, UUID refundId,
            boolean forUpdate) throws SQLException {
        String sql = "SELECT " + COLUMNS + " FROM refund WHERE tenant_id = ?::uuid"
                + " AND id = ?::uuid" + (forUpdate ? " FOR UPDATE" : "");
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, refundId.toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new PaymentCoreException("RESOURCE_NOT_FOUND",
                            "refund does not exist in this tenant");
                }
                return refund(result);
            }
        }
    }

    private static PaymentAmounts lockPayment(Connection connection, RefundRecord proposed)
            throws SQLException {
        PaymentAmounts payment = paymentAmounts(connection, proposed.tenantId(),
                proposed.paymentIntentId(), true);
        if (!payment.projectId().equals(proposed.projectId())
                || !payment.currency().equals(proposed.amount().currency().code())) {
            throw new PaymentCoreException("REFUND_PAYMENT_SCOPE_MISMATCH",
                    "refund payment tenant, project or currency does not match");
        }
        return payment;
    }

    private static PaymentAmounts paymentAmounts(Connection connection, UUID tenantId,
            UUID paymentIntentId, boolean forUpdate) throws SQLException {
        String sql = """
                SELECT project_id, captured_amount_minor, refunded_amount_minor, currency
                  FROM payment_intent
                 WHERE tenant_id = ?::uuid AND id = ?::uuid
                """ + (forUpdate ? " FOR UPDATE" : "");
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, paymentIntentId.toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new PaymentCoreException("RESOURCE_NOT_FOUND",
                            "payment intent does not exist in this tenant");
                }
                return new PaymentAmounts(result.getObject("project_id", UUID.class),
                        result.getLong("captured_amount_minor"),
                        result.getLong("refunded_amount_minor"), result.getString("currency"));
            }
        }
    }

    private static long pendingReservations(Connection connection, UUID tenantId,
            UUID paymentIntentId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT COALESCE(SUM(amount_minor), 0)
                  FROM refund
                 WHERE tenant_id = ?::uuid AND payment_intent_id = ?::uuid
                   AND state IN ('approval_pending', 'processing', 'unknown',
                                 'partially_succeeded')
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, paymentIntentId.toString());
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getLong(1);
            }
        }
    }

    private static void applySuccessfulRefund(Connection connection, RefundRecord refund)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE payment_intent
                   SET refunded_amount_minor = refunded_amount_minor + ?,
                       updated_at = ?, version = version + 1
                 WHERE tenant_id = ?::uuid AND id = ?::uuid
                   AND refunded_amount_minor + ? <= captured_amount_minor
                """)) {
            statement.setLong(1, refund.amount().amountMinor());
            statement.setTimestamp(2, Timestamp.from(refund.updatedAt()));
            statement.setString(3, refund.tenantId().toString());
            statement.setString(4, refund.paymentIntentId().toString());
            statement.setLong(5, refund.amount().amountMinor());
            if (statement.executeUpdate() != 1) {
                throw new PaymentCoreException("REFUND_AMOUNT_EXCEEDS_REFUNDABLE",
                        "successful refund would exceed captured amount");
            }
        }
    }

    private static void insertRefund(Connection connection, RefundRecord refund)
            throws SQLException {
        String sql = "INSERT INTO refund (" + COLUMNS + ") VALUES ("
                + "?::uuid, ?::uuid, ?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                + " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            bindRefund(statement, refund);
            statement.executeUpdate();
        }
    }

    private static void updateRefund(Connection connection, RefundRecord refund,
            long expectedVersion) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE refund
                   SET state = ?, approved_by = ?, approval_reason = ?, approval_ticket_id = ?,
                       provider_refund_id = ?, provider_outcome_digest = ?, failure_code = ?,
                       correlation_id = ?, updated_at = ?, version = ?
                 WHERE tenant_id = ?::uuid AND id = ?::uuid AND version = ?
                """)) {
            statement.setString(1, db(refund.status()));
            statement.setString(2, refund.approverId());
            statement.setString(3, refund.approvalReason());
            statement.setString(4, refund.approvalTicketId());
            statement.setString(5, refund.providerRefundId());
            statement.setString(6, refund.providerOutcomeDigest());
            statement.setString(7, refund.failureCode());
            statement.setString(8, refund.correlationId());
            statement.setTimestamp(9, Timestamp.from(refund.updatedAt()));
            statement.setLong(10, refund.version());
            statement.setString(11, refund.tenantId().toString());
            statement.setString(12, refund.id().toString());
            statement.setLong(13, expectedVersion);
            if (statement.executeUpdate() != 1) {
                throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                        "refund changed during provider resolution");
            }
        }
    }

    private static void bindRefund(PreparedStatement statement, RefundRecord refund)
            throws SQLException {
        statement.setString(1, refund.id().toString());
        statement.setString(2, refund.tenantId().toString());
        statement.setString(3, refund.projectId().toString());
        statement.setString(4, refund.paymentIntentId().toString());
        statement.setString(5, refund.providerAccountId().toString());
        statement.setString(6, refund.provider());
        statement.setString(7, refund.providerPaymentId());
        statement.setLong(8, refund.amount().amountMinor());
        statement.setString(9, refund.amount().currency().code());
        statement.setString(10, refund.reason().wireValue());
        statement.setString(11, db(refund.status()));
        statement.setString(12, db(refund.riskDecision()));
        statement.setString(13, refund.riskContextDigest());
        statement.setString(14, refund.requestIdempotencyKey());
        statement.setString(15, refund.requestDigest());
        statement.setString(16, refund.requesterId());
        statement.setString(17, refund.approverId());
        statement.setString(18, refund.approvalReason());
        statement.setString(19, refund.approvalTicketId());
        statement.setString(20, refund.providerRefundId());
        statement.setString(21, refund.providerOutcomeDigest());
        statement.setString(22, refund.failureCode());
        statement.setString(23, refund.correlationId());
        statement.setTimestamp(24, Timestamp.from(refund.createdAt()));
        statement.setTimestamp(25, Timestamp.from(refund.updatedAt()));
        statement.setLong(26, refund.version());
    }

    private static RefundRecord refund(ResultSet result) throws SQLException {
        if (result.getString("request_digest") == null) {
            throw new PaymentCoreException("REFUND_LEGACY_RECORD_UNSUPPORTED",
                    "legacy refund lacks the durable runtime request snapshot");
        }
        return new RefundRecord(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                result.getObject("payment_intent_id", UUID.class),
                result.getObject("provider_account_id", UUID.class), result.getString("provider"),
                result.getString("provider_payment_id"),
                Money.of(result.getLong("amount_minor"), result.getString("currency")),
                enumValue(RefundReason.class, result.getString("reason")),
                enumValue(RefundStatus.class, result.getString("state")),
                enumValue(RefundRiskDecision.class, result.getString("risk_decision")),
                result.getString("risk_context_digest"), result.getString("idempotency_key"),
                result.getString("request_digest"), result.getString("requester_id"),
                result.getString("approved_by"), result.getString("approval_reason"),
                result.getString("approval_ticket_id"), result.getString("provider_refund_id"),
                result.getString("provider_outcome_digest"), result.getString("failure_code"),
                result.getString("correlation_id"),
                result.getTimestamp("created_at").toInstant(),
                result.getTimestamp("updated_at").toInstant(), result.getLong("version"));
    }

    private static RefundActionReceipt findReceipt(Connection connection, UUID tenantId,
            String idempotencyKey) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT tenant_id, refund_id, operation, idempotency_key, request_digest,
                       actor_id, reason, ticket_id, result_version, completed_at
                  FROM refund_action_receipt
                 WHERE tenant_id = ?::uuid AND idempotency_key = ?
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, idempotencyKey);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? new RefundActionReceipt(
                        result.getObject("tenant_id", UUID.class),
                        result.getObject("refund_id", UUID.class), result.getString("operation"),
                        result.getString("idempotency_key"), result.getString("request_digest"),
                        result.getString("actor_id"), result.getString("reason"),
                        result.getString("ticket_id"), result.getLong("result_version"),
                        result.getTimestamp("completed_at").toInstant()) : null;
            }
        }
    }

    private static void insertReceipt(Connection connection, RefundActionReceipt receipt)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO refund_action_receipt
                  (tenant_id, refund_id, operation, idempotency_key, request_digest,
                   actor_id, reason, ticket_id, result_version, completed_at)
                VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setString(1, receipt.tenantId().toString());
            statement.setString(2, receipt.refundId().toString());
            statement.setString(3, receipt.operation());
            statement.setString(4, receipt.idempotencyKey());
            statement.setString(5, receipt.requestDigest());
            statement.setString(6, receipt.actorId());
            statement.setString(7, receipt.reason());
            statement.setString(8, receipt.ticketId());
            statement.setLong(9, receipt.resultVersion());
            statement.setTimestamp(10, Timestamp.from(receipt.completedAt()));
            statement.executeUpdate();
        }
    }

    private static void appendOutbox(Connection connection, RefundRecord refund,
            String eventType, RefundActionReceipt receipt) throws SQLException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("refund_id", refund.id().toString());
        payload.put("payment_intent_id", refund.paymentIntentId().toString());
        payload.put("amount_minor", refund.amount().amountMinor());
        payload.put("currency", refund.amount().currency().code());
        payload.put("state", db(refund.status()));
        payload.put("reason", refund.reason().wireValue());
        payload.put("requester_id", refund.requesterId());
        payload.put("risk_decision", refund.riskDecision().name());
        if (receipt != null) {
            payload.put("actor_id", receipt.actorId());
            payload.put("action_reason", receipt.reason());
            payload.put("ticket_id", receipt.ticketId());
        }
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO outbox_event
                  (id, tenant_id, project_id, aggregate_type, aggregate_id, event_type,
                   event_version, payload, correlation_id, created_at)
                VALUES (?::uuid, ?::uuid, ?::uuid, 'refund', ?::uuid, ?, 1,
                        ?::jsonb, ?, ?)
                """)) {
            statement.setString(1, UUID.randomUUID().toString());
            statement.setString(2, refund.tenantId().toString());
            statement.setString(3, refund.projectId().toString());
            statement.setString(4, refund.id().toString());
            statement.setString(5, eventType);
            statement.setString(6, new String(CanonicalPayload.encode(payload),
                    StandardCharsets.UTF_8));
            statement.setString(7, refund.correlationId());
            statement.setTimestamp(8, Timestamp.from(refund.updatedAt()));
            statement.executeUpdate();
        }
    }

    private static void requireActionKeyUnusedByRequest(Connection connection,
            RefundActionReceipt receipt) throws SQLException {
        if (findByRequestKey(connection, receipt.tenantId(), receipt.idempotencyKey(), false)
                != null) {
            throw conflict("refund action key already belongs to a create request");
        }
    }

    private static void requireExpected(RefundRecord current, RefundRecord expected) {
        if (current.version() != expected.version() || current.status() != expected.status()
                || !current.requestDigest().equals(expected.requestDigest())) {
            throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                    "refund changed during the operation");
        }
    }

    private static void requireTransition(RefundRecord current, RefundRecord proposed) {
        if (!current.id().equals(proposed.id())
                || !current.tenantId().equals(proposed.tenantId())
                || !current.requestDigest().equals(proposed.requestDigest())
                || proposed.version() != current.version() + 1) {
            throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                    "invalid or stale refund transition");
        }
    }

    private static void requireReceipt(RefundActionReceipt receipt, RefundRecord proposed) {
        if (!receipt.tenantId().equals(proposed.tenantId())
                || !receipt.refundId().equals(proposed.id())
                || receipt.resultVersion() != proposed.version()) {
            throw new PaymentCoreException("REFUND_ACTION_RECEIPT_INVALID",
                    "refund action receipt does not match the resulting aggregate");
        }
    }

    private static void requireSameRequest(RefundRecord existing, String digest) {
        if (!existing.sameRequestDigest(digest)) {
            throw conflict("refund request key was reused with a different canonical payload");
        }
    }

    private static void requireSameReceipt(RefundActionReceipt existing,
            RefundActionReceipt proposed) {
        if (!existing.refundId().equals(proposed.refundId())
                || !existing.matches(proposed.operation(), proposed.requestDigest())) {
            throw conflict("refund action key was reused with a different operation or payload");
        }
    }

    private static void advisoryLock(Connection connection, String scope) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")) {
            statement.setString(1, scope);
            statement.execute();
        }
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        if (connection.getAutoCommit()) {
            throw new SQLException("tenant RLS context requires an explicit transaction");
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static RuntimeException translate(String message, Exception exception) {
        if (exception instanceof PaymentCoreException payment) {
            return payment;
        }
        if (exception instanceof SQLException sql && "23505".equals(sql.getSQLState())) {
            return conflict("refund idempotency or provider reference already exists");
        }
        return exception instanceof RuntimeException runtime
                ? runtime : new IllegalStateException(message, exception);
    }

    private static void validatePaymentAmounts(long captured, long refunded) {
        if (captured < 0 || refunded < 0 || refunded > captured) {
            throw new IllegalArgumentException("invalid captured/refunded payment amounts");
        }
    }

    private static PaymentCoreException conflict(String message) {
        return new PaymentCoreException("IDEMPOTENCY_KEY_REUSE", message);
    }

    private static String db(Enum<?> value) {
        return value.name().toLowerCase(Locale.ROOT);
    }

    private static <E extends Enum<E>> E enumValue(Class<E> type, String value) {
        return Enum.valueOf(type, value.toUpperCase(Locale.ROOT));
    }

    private record PaymentAmounts(UUID projectId, long capturedAmountMinor,
            long refundedAmountMinor, String currency) {
    }

    @FunctionalInterface
    private interface SqlBinder {
        void bind(PreparedStatement statement) throws SQLException;
    }
}
