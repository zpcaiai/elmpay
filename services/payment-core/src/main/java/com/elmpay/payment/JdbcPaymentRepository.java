package com.elmpay.payment;

import com.elmpay.money.Money;
import com.elmpay.payment.events.SemanticOutboxAppender;
import com.elmpay.security.CanonicalPayload;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.sql.DataSource;

/** PostgreSQL repository with tenant RLS context, optimistic locking and transactional outbox. */
public final class JdbcPaymentRepository implements PaymentRepository {
    private static final String INTENT_COLUMNS = """
            id, tenant_id, project_id, merchant_id, external_reference, amount_minor,
            currency, captured_amount_minor, refunded_amount_minor, state, allowed_methods,
            confirmation_mode, region, idempotency_key, expires_at, created_at, updated_at, version
            """;
    private static final String ATTEMPT_COLUMNS = """
            id, tenant_id, payment_intent_id, provider_account_id, provider, operation,
            sequence, request_digest, idempotency_key, state, outcome_class, response_digest,
            provider_request_id, provider_transaction_id, provider_code_namespace,
            provider_code, started_at, settled_at, lease_owner, fencing_token, lease_expires_at
            """;
    static final String CLAIM_RECOVERABLE_ATTEMPT_SQL = "SELECT " + ATTEMPT_COLUMNS + """
             FROM payment_attempt
            WHERE tenant_id = ?::uuid AND payment_intent_id = ?::uuid
              AND operation <> 'query' AND state IN ('initiated', 'pending', 'unknown')
              AND lease_expires_at <= ?
            ORDER BY sequence DESC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
            """;
    static final String FENCED_ATTEMPT_UPDATE_SQL = """
            UPDATE payment_attempt
               SET lease_owner = ?, fencing_token = fencing_token + 1,
                   lease_expires_at = ?
             WHERE tenant_id = ?::uuid AND id = ?::uuid
               AND lease_owner = ? AND fencing_token = ?
               AND state IN ('initiated', 'pending', 'unknown')
            """;

    private final DataSource dataSource;

    public JdbcPaymentRepository(DataSource dataSource) {
        this.dataSource = java.util.Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public PaymentIntent create(PaymentIntent intent) {
        String sql = "INSERT INTO payment_intent (" + INTENT_COLUMNS + ") VALUES ("
                + "?::uuid, ?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, intent.tenantId());
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    bindIntent(statement, connection, intent, 1);
                    statement.executeUpdate();
                }
                appendOutbox(connection, intent, null, "payment.intent.created.v1",
                        intent.id().toString());
                connection.commit();
                return intent;
            } catch (SQLException exception) {
                rollback(connection, exception);
                if ("23505".equals(exception.getSQLState())) {
                    throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                            "order reference or idempotency key already exists", exception);
                }
                throw new IllegalStateException("cannot create payment intent", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot create payment intent", exception);
        }
    }

    @Override
    public Optional<PaymentIntent> find(UUID tenantId, UUID intentId) {
        return queryOne(tenantId, "SELECT " + INTENT_COLUMNS
                + " FROM payment_intent WHERE tenant_id = ?::uuid AND id = ?::uuid",
                statement -> {
                    statement.setString(1, tenantId.toString());
                    statement.setString(2, intentId.toString());
                });
    }

    @Override
    public Optional<PaymentIntent> findByExternalReference(UUID tenantId, UUID projectId,
            String externalReference) {
        return queryOne(tenantId, "SELECT " + INTENT_COLUMNS + " FROM payment_intent"
                + " WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND external_reference = ?",
                statement -> {
                    statement.setString(1, tenantId.toString());
                    statement.setString(2, projectId.toString());
                    statement.setString(3, externalReference);
                });
    }

    @Override
    public Optional<PaymentIntent> findByCreateKey(UUID tenantId, UUID projectId,
            String idempotencyKey) {
        return queryOne(tenantId, "SELECT " + INTENT_COLUMNS + " FROM payment_intent"
                + " WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND idempotency_key = ?",
                statement -> {
                    statement.setString(1, tenantId.toString());
                    statement.setString(2, projectId.toString());
                    statement.setString(3, idempotencyKey);
                });
    }

    @Override
    public PaymentIntent update(PaymentIntent intent, long expectedVersion, String eventType,
            String correlationId) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, intent.tenantId());
                updateIntent(connection, intent, expectedVersion);
                appendOutbox(connection, intent, null, eventType, correlationId);
                connection.commit();
                return intent;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot update payment intent", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot update payment intent", exception);
        }
    }

    @Override
    public Optional<PaymentActionReceipt> findActionReceipt(UUID tenantId, UUID intentId,
            String idempotencyKey) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                PaymentActionReceipt receipt = findActionReceipt(connection, tenantId, intentId,
                        idempotencyKey);
                connection.commit();
                return Optional.ofNullable(receipt);
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot read payment action receipt", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot read payment action receipt", exception);
        }
    }

    @Override
    public PaymentIntent updateWithActionReceipt(PaymentIntent intent, long expectedVersion,
            PaymentActionReceipt receipt, String eventType, String correlationId) {
        requireReceiptMatchesIntent(intent, receipt);
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, intent.tenantId());
                advisoryLock(connection, intent.id());
                PaymentActionReceipt existing = findActionReceipt(connection, intent.tenantId(),
                        intent.id(), receipt.idempotencyKey());
                if (existing != null) {
                    requireSameReceipt(existing, receipt);
                    PaymentIntent replay = currentIntent(connection, intent.tenantId(), intent.id());
                    connection.commit();
                    return replay;
                }
                if (hasAttemptKey(connection, receipt)) {
                    throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                            "action key already belongs to a provider operation");
                }
                if (hasUnresolvedMoneyAttempt(connection, receipt.tenantId(), receipt.intentId())) {
                    throw new PaymentCoreException("ATTEMPT_IN_PROGRESS",
                            "an unresolved provider call blocks direct cancellation");
                }
                updateIntent(connection, intent, expectedVersion);
                insertActionReceipt(connection, receipt);
                appendOutbox(connection, intent, null, eventType, correlationId);
                connection.commit();
                return intent;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot update payment intent action", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot update payment intent action", exception);
        }
    }

    @Override
    public PaymentAttempt beginAttempt(AttemptDraft draft) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, draft.tenantId());
                advisoryLock(connection, draft.intentId());
                PaymentIntent current = currentIntent(connection, draft.tenantId(), draft.intentId());
                if (current.version() != draft.expectedIntentVersion()) {
                    throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                            "payment intent changed before provider dispatch");
                }
                PaymentAttempt replay = findAttemptByKey(connection, draft);
                if (replay != null) {
                    throw new PaymentCoreException("IDEMPOTENCY_REPLAY", "attempt key already exists");
                }
                if (findActionReceipt(connection, draft.tenantId(), draft.intentId(),
                        draft.idempotencyKey()) != null) {
                    throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                            "attempt key already belongs to a non-provider payment action");
                }
                if (hasConflictingAttempt(connection, draft)) {
                    throw new PaymentCoreException("ATTEMPT_IN_PROGRESS",
                            "an unresolved provider call blocks this operation");
                }
                int sequence = nextSequence(connection, draft);
                PaymentAttempt attempt = PaymentAttempt.begin(draft, sequence);
                String sql = "INSERT INTO payment_attempt (" + ATTEMPT_COLUMNS + ") VALUES ("
                        + "?::uuid, ?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                        + "?, ?, ?, ?, ?)";
                try (PreparedStatement statement = connection.prepareStatement(sql)) {
                    bindAttempt(statement, attempt);
                    statement.executeUpdate();
                }
                if (draft.operation() == AttemptOperation.CAPTURE
                        && Set.of("wechat", "alipay", "stripe", "paypal")
                                .contains(draft.provider())) {
                    new ProviderEffectExpectationService().registerCapture(connection,
                            draft.tenantId(), current.projectId(), draft.intentId(), attempt.id(),
                            draft.providerAccountId(), draft.provider(), draft.expectedDeltaMinor(),
                            draft.currency(), draft.businessOrderDigest(), attempt.startedAt());
                }
                connection.commit();
                return attempt;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot begin payment attempt", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot begin payment attempt", exception);
        }
    }

    @Override
    public Optional<PaymentAttempt> claimRecoverableAttempt(UUID tenantId, UUID intentId,
            String leaseOwner, Instant now, Instant leaseExpiresAt) {
        validateLease(leaseOwner, now, leaseExpiresAt);
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                advisoryLock(connection, intentId);
                currentIntent(connection, tenantId, intentId);
                PaymentAttempt candidate = null;
                try (PreparedStatement statement = connection.prepareStatement(
                        CLAIM_RECOVERABLE_ATTEMPT_SQL)) {
                    statement.setString(1, tenantId.toString());
                    statement.setString(2, intentId.toString());
                    statement.setTimestamp(3, Timestamp.from(now));
                    try (ResultSet result = statement.executeQuery()) {
                        if (result.next()) {
                            candidate = attempt(result);
                        }
                    }
                }
                if (candidate == null) {
                    connection.commit();
                    return Optional.empty();
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        FENCED_ATTEMPT_UPDATE_SQL)) {
                    statement.setString(1, leaseOwner);
                    statement.setTimestamp(2, Timestamp.from(leaseExpiresAt));
                    statement.setString(3, tenantId.toString());
                    statement.setString(4, candidate.id().toString());
                    statement.setString(5, candidate.leaseOwner());
                    statement.setLong(6, candidate.fencingToken());
                    requireAttemptLease(statement.executeUpdate());
                }
                PaymentAttempt claimed = candidate.withLease(leaseOwner,
                        Math.addExact(candidate.fencingToken(), 1), leaseExpiresAt);
                connection.commit();
                return Optional.of(claimed);
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot claim payment attempt recovery", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot claim payment attempt recovery", exception);
        }
    }

    @Override
    public void releaseAttemptLease(PaymentAttempt attempt, Instant releasedAt) {
        java.util.Objects.requireNonNull(attempt, "attempt");
        java.util.Objects.requireNonNull(releasedAt, "releasedAt");
        Instant release = releasedAt.isBefore(attempt.startedAt())
                ? attempt.startedAt() : releasedAt;
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, attempt.tenantId());
                advisoryLock(connection, attempt.intentId());
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE payment_attempt SET lease_expires_at = ?
                         WHERE tenant_id = ?::uuid AND id = ?::uuid
                           AND lease_owner = ? AND fencing_token = ?
                           AND state IN ('initiated', 'pending', 'unknown')
                        """)) {
                    statement.setTimestamp(1, Timestamp.from(release));
                    statement.setString(2, attempt.tenantId().toString());
                    statement.setString(3, attempt.id().toString());
                    statement.setString(4, attempt.leaseOwner());
                    statement.setLong(5, attempt.fencingToken());
                    requireAttemptLease(statement.executeUpdate());
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot release payment attempt recovery", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot release payment attempt recovery", exception);
        }
    }

    @Override
    public PaymentIntent resolveAttempt(PaymentAttempt attempt, PaymentIntent intent,
            long expectedIntentVersion, String eventType, String correlationId) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, intent.tenantId());
                advisoryLock(connection, intent.id());
                PaymentIntent previous = currentIntent(connection, intent.tenantId(), intent.id());
                updateResolvedAttempt(connection, attempt, false);
                if (intent.version() == expectedIntentVersion + 1) {
                    updateIntent(connection, intent, expectedIntentVersion);
                } else if (intent.version() != expectedIntentVersion
                        || currentVersion(connection, intent) != expectedIntentVersion) {
                    throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                            "payment intent changed during provider resolution");
                }
                appendOutbox(connection, intent, attempt, eventType, correlationId);
                appendCapturedEvent(connection, previous, intent, attempt, correlationId);
                connection.commit();
                return intent;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot resolve payment attempt", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot resolve payment attempt", exception);
        }
    }

    @Override
    public PaymentIntent resolveRecovery(PaymentAttempt originalAttempt,
            PaymentAttempt queryAttempt, PaymentIntent intent, long expectedIntentVersion,
            String eventType, String correlationId) {
        requireRecoveryScope(originalAttempt, queryAttempt, intent);
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenant(connection, intent.tenantId());
                advisoryLock(connection, intent.id());
                PaymentIntent previous = currentIntent(connection, intent.tenantId(), intent.id());
                updateResolvedAttempt(connection, originalAttempt, true);
                updateResolvedAttempt(connection, queryAttempt, false);
                if (intent.version() == expectedIntentVersion + 1) {
                    updateIntent(connection, intent, expectedIntentVersion);
                } else if (intent.version() != expectedIntentVersion
                        || currentVersion(connection, intent) != expectedIntentVersion) {
                    throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                            "payment intent changed during provider recovery");
                }
                appendOutbox(connection, intent, originalAttempt, eventType, correlationId);
                appendCapturedEvent(connection, previous, intent, originalAttempt, correlationId);
                connection.commit();
                return intent;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw translate("cannot resolve payment recovery", exception);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot resolve payment recovery", exception);
        }
    }

    @Override
    public List<PaymentAttempt> attempts(UUID tenantId, UUID intentId) {
        String sql = "SELECT " + ATTEMPT_COLUMNS + " FROM payment_attempt"
                + " WHERE tenant_id = ?::uuid AND payment_intent_id = ?::uuid ORDER BY sequence";
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, intentId.toString());
                List<PaymentAttempt> result = new ArrayList<>();
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        result.add(attempt(rows));
                    }
                }
                connection.commit();
                return List.copyOf(result);
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot list payment attempts", exception);
        }
    }

    private Optional<PaymentIntent> queryOne(UUID tenantId, String sql, SqlBinder binder) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                binder.bind(statement);
                Optional<PaymentIntent> result;
                try (ResultSet rows = statement.executeQuery()) {
                    result = rows.next() ? Optional.of(intent(rows)) : Optional.empty();
                }
                connection.commit();
                return result;
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("cannot query payment intent", exception);
        }
    }

    private static void updateResolvedAttempt(Connection connection, PaymentAttempt attempt,
            boolean requireRecoverySource) throws SQLException {
        String statePredicate = requireRecoverySource
                ? "operation <> 'query' AND state IN ('initiated', 'pending', 'unknown')"
                : "state IN ('initiated', 'pending', 'unknown')";
        String sql = """
                UPDATE payment_attempt
                   SET state = ?, outcome_class = ?, response_digest = ?,
                       provider_request_id = ?, provider_transaction_id = ?,
                       provider_code_namespace = ?, provider_code = ?, settled_at = ?,
                       lease_expires_at = ?
                 WHERE tenant_id = ?::uuid AND id = ?::uuid
                   AND lease_owner = ? AND fencing_token = ? AND %s
                """.formatted(statePredicate);
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, db(attempt.state()));
            statement.setString(2, db(attempt.outcomeClass()));
            statement.setString(3, attempt.responseDigest());
            statement.setString(4, attempt.providerRequestId());
            statement.setString(5, attempt.providerTransactionId());
            statement.setString(6, attempt.providerCodeNamespace());
            statement.setString(7, attempt.providerCode());
            statement.setTimestamp(8, Timestamp.from(attempt.finishedAt()));
            statement.setTimestamp(9, Timestamp.from(attempt.leaseExpiresAt()));
            statement.setString(10, attempt.tenantId().toString());
            statement.setString(11, attempt.id().toString());
            statement.setString(12, attempt.leaseOwner());
            statement.setLong(13, attempt.fencingToken());
            requireAttemptLease(statement.executeUpdate());
        }
    }

    private static PaymentActionReceipt findActionReceipt(Connection connection, UUID tenantId,
            UUID intentId, String idempotencyKey) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT tenant_id, payment_intent_id, operation, idempotency_key,
                       request_digest, result_intent_version, completed_at
                  FROM payment_action_receipt
                 WHERE tenant_id = ?::uuid AND payment_intent_id = ?::uuid
                   AND idempotency_key = ?
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, intentId.toString());
            statement.setString(3, idempotencyKey);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? actionReceipt(result) : null;
            }
        }
    }

    private static void insertActionReceipt(Connection connection, PaymentActionReceipt receipt)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO payment_action_receipt
                  (tenant_id, payment_intent_id, operation, idempotency_key, request_digest,
                   result_intent_version, completed_at)
                VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?)
                """)) {
            statement.setString(1, receipt.tenantId().toString());
            statement.setString(2, receipt.intentId().toString());
            statement.setString(3, receipt.operation());
            statement.setString(4, receipt.idempotencyKey());
            statement.setString(5, receipt.requestDigest());
            statement.setLong(6, receipt.resultIntentVersion());
            statement.setTimestamp(7, Timestamp.from(receipt.completedAt()));
            statement.executeUpdate();
        }
    }

    private static boolean hasAttemptKey(Connection connection, PaymentActionReceipt receipt)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1 FROM payment_attempt
                 WHERE tenant_id = ?::uuid AND payment_intent_id = ?::uuid
                   AND idempotency_key = ? LIMIT 1
                """)) {
            statement.setString(1, receipt.tenantId().toString());
            statement.setString(2, receipt.intentId().toString());
            statement.setString(3, receipt.idempotencyKey());
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private static boolean hasUnresolvedMoneyAttempt(Connection connection, UUID tenantId,
            UUID intentId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT 1 FROM payment_attempt
                 WHERE tenant_id = ?::uuid AND payment_intent_id = ?::uuid
                   AND operation <> 'query' AND state IN ('initiated', 'pending', 'unknown')
                 LIMIT 1
                """)) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, intentId.toString());
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private static PaymentIntent currentIntent(Connection connection, UUID tenantId, UUID intentId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT " + INTENT_COLUMNS
                        + " FROM payment_intent WHERE tenant_id = ?::uuid AND id = ?::uuid")) {
            statement.setString(1, tenantId.toString());
            statement.setString(2, intentId.toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new PaymentCoreException("RESOURCE_NOT_FOUND",
                            "payment intent is missing");
                }
                return intent(result);
            }
        }
    }

    private static void updateIntent(Connection connection, PaymentIntent intent,
            long expectedVersion) throws SQLException {
        String sql = """
                UPDATE payment_intent
                   SET captured_amount_minor = ?, refunded_amount_minor = ?, state = ?,
                       updated_at = ?, version = ?
                 WHERE tenant_id = ?::uuid AND id = ?::uuid AND version = ?
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, intent.capturedAmountMinor());
            statement.setLong(2, intent.refundedAmountMinor());
            statement.setString(3, db(intent.state()));
            statement.setTimestamp(4, Timestamp.from(intent.updatedAt()));
            statement.setLong(5, intent.version());
            statement.setString(6, intent.tenantId().toString());
            statement.setString(7, intent.id().toString());
            statement.setLong(8, expectedVersion);
            if (statement.executeUpdate() != 1) {
                throw new PaymentCoreException("CONCURRENT_MODIFICATION",
                        "payment intent changed during the operation");
            }
        }
    }

    private static long currentVersion(Connection connection, PaymentIntent intent)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT version FROM payment_intent WHERE tenant_id = ?::uuid AND id = ?::uuid")) {
            statement.setString(1, intent.tenantId().toString());
            statement.setString(2, intent.id().toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new PaymentCoreException("RESOURCE_NOT_FOUND", "payment intent is missing");
                }
                return result.getLong(1);
            }
        }
    }

    private static long currentVersion(Connection connection, AttemptDraft draft)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT version FROM payment_intent WHERE tenant_id = ?::uuid AND id = ?::uuid")) {
            statement.setString(1, draft.tenantId().toString());
            statement.setString(2, draft.intentId().toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new PaymentCoreException("RESOURCE_NOT_FOUND", "payment intent is missing");
                }
                return result.getLong(1);
            }
        }
    }

    private static void appendOutbox(Connection connection, PaymentIntent intent,
            PaymentAttempt attempt, String eventType, String correlationId) throws SQLException {
        Map<String, Object> payload = outboxPayload(intent, attempt, eventType);
        SemanticOutboxAppender.append(connection, new SemanticOutboxAppender.EventDraft(
                intent.tenantId(), intent.projectId(), "payment_intent", intent.id(), eventType,
                1, intent.updatedAt(), correlationId, payload));
    }

    private static void appendCapturedEvent(Connection connection, PaymentIntent previous,
            PaymentIntent current, PaymentAttempt attempt, String traceId) throws SQLException {
        long delta = Math.subtractExact(current.capturedAmountMinor(),
                previous.capturedAmountMinor());
        if (delta <= 0 || attempt.state() != AttemptState.SUCCEEDED) {
            return;
        }
        Instant capturedAt = Objects.requireNonNull(attempt.finishedAt(), "attempt.finishedAt");
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("payment_intent_id", current.id().toString());
        payload.put("project_id", current.projectId().toString());
        payload.put("provider", attempt.provider());
        payload.put("captured_at", capturedAt.toString());
        payload.put("amount_minor", delta);
        payload.put("currency", current.amount().currency().code());
        payload.put("business_order_digest",
                ProviderEffectExpectationService.businessOrderDigest(
                        current.externalReference()));
        SemanticOutboxAppender.append(connection, new SemanticOutboxAppender.EventDraft(
                current.tenantId(), current.projectId(), "payment_intent", current.id(),
                "payment_intent.captured", 1, capturedAt, traceId, payload));
    }

    static Map<String, Object> outboxPayload(PaymentIntent intent, PaymentAttempt attempt,
            String eventType) {
        java.util.Objects.requireNonNull(intent, "intent");
        java.util.Objects.requireNonNull(eventType, "eventType");
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("intent_id", intent.id().toString());
        payload.put("tenant_id", intent.tenantId().toString());
        payload.put("project_id", intent.projectId().toString());
        payload.put("state", db(intent.state()));
        payload.put("amount_minor", intent.amount().amountMinor());
        payload.put("currency", intent.amount().currency().code());
        payload.put("captured_amount_minor", intent.capturedAmountMinor());
        payload.put("refunded_amount_minor", intent.refundedAmountMinor());
        if (attempt != null) {
            payload.put("provider", attempt.provider());
            if (attempt.providerCode() != null) {
                payload.put("provider_status", attempt.providerCode());
            }
            payload.put("attempt_operation", db(attempt.operation()));
            payload.put("risk_outcome", riskOutcome(attempt.operation()));
            if (attempt.providerTransactionId() != null) {
                payload.put("provider_transaction_id", attempt.providerTransactionId());
            }
        } else if ("payment.intent.created.v1".equals(eventType)) {
            payload.put("risk_outcome", "APPROVED");
        }
        return Map.copyOf(payload);
    }

    private static String riskOutcome(AttemptOperation operation) {
        return switch (operation) {
            case PAYMENT, CAPTURE -> "APPROVED";
            case CANCEL, CLOSE, QUERY -> "NOT_EVALUATED";
        };
    }

    private static boolean hasConflictingAttempt(Connection connection, AttemptDraft draft)
            throws SQLException {
        String sql = draft.operation() == AttemptOperation.QUERY
                ? """
                  SELECT 1 FROM payment_attempt WHERE tenant_id = ?::uuid
                   AND payment_intent_id = ?::uuid AND operation = 'query'
                   AND state IN ('initiated', 'pending') AND lease_expires_at > ? LIMIT 1
                  """
                : """
                  SELECT 1 FROM payment_attempt WHERE tenant_id = ?::uuid
                   AND payment_intent_id = ?::uuid AND operation <> 'query'
                   AND state IN ('initiated', 'pending', 'unknown') LIMIT 1
                  """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, draft.tenantId().toString());
            statement.setString(2, draft.intentId().toString());
            if (draft.operation() == AttemptOperation.QUERY) {
                statement.setTimestamp(3, Timestamp.from(draft.startedAt()));
            }
            try (ResultSet result = statement.executeQuery()) {
                return result.next();
            }
        }
    }

    private static PaymentAttempt findAttemptByKey(Connection connection, AttemptDraft draft)
            throws SQLException {
        String sql = "SELECT " + ATTEMPT_COLUMNS + " FROM payment_attempt"
                + " WHERE tenant_id = ?::uuid AND payment_intent_id = ?::uuid"
                + " AND idempotency_key = ?";
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, draft.tenantId().toString());
            statement.setString(2, draft.intentId().toString());
            statement.setString(3, draft.idempotencyKey());
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? attempt(result) : null;
            }
        }
    }

    private static int nextSequence(Connection connection, AttemptDraft draft) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT COALESCE(MAX(sequence), 0) + 1 FROM payment_attempt
                 WHERE tenant_id = ?::uuid AND payment_intent_id = ?::uuid
                """)) {
            statement.setString(1, draft.tenantId().toString());
            statement.setString(2, draft.intentId().toString());
            try (ResultSet result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
    }

    private static void bindIntent(PreparedStatement statement, Connection connection,
            PaymentIntent intent, int offset) throws SQLException {
        int index = offset;
        statement.setString(index++, intent.id().toString());
        statement.setString(index++, intent.tenantId().toString());
        statement.setString(index++, intent.projectId().toString());
        statement.setString(index++, intent.merchantId().toString());
        statement.setString(index++, intent.externalReference());
        statement.setLong(index++, intent.amount().amountMinor());
        statement.setString(index++, intent.amount().currency().code());
        statement.setLong(index++, intent.capturedAmountMinor());
        statement.setLong(index++, intent.refundedAmountMinor());
        statement.setString(index++, db(intent.state()));
        Array methods = connection.createArrayOf("text", intent.allowedMethods().toArray());
        statement.setArray(index++, methods);
        statement.setString(index++, db(intent.confirmationMode()));
        statement.setString(index++, intent.region());
        statement.setString(index++, intent.createIdempotencyKey());
        statement.setTimestamp(index++, Timestamp.from(intent.expiresAt()));
        statement.setTimestamp(index++, Timestamp.from(intent.createdAt()));
        statement.setTimestamp(index++, Timestamp.from(intent.updatedAt()));
        statement.setLong(index, intent.version());
    }

    private static void bindAttempt(PreparedStatement statement, PaymentAttempt attempt)
            throws SQLException {
        statement.setString(1, attempt.id().toString());
        statement.setString(2, attempt.tenantId().toString());
        statement.setString(3, attempt.intentId().toString());
        statement.setString(4, attempt.providerAccountId().toString());
        statement.setString(5, attempt.provider());
        statement.setString(6, db(attempt.operation()));
        statement.setInt(7, attempt.sequence());
        statement.setString(8, attempt.requestDigest());
        statement.setString(9, attempt.idempotencyKey());
        statement.setString(10, db(attempt.state()));
        statement.setString(11, null);
        statement.setString(12, null);
        statement.setString(13, null);
        statement.setString(14, null);
        statement.setString(15, null);
        statement.setString(16, null);
        statement.setTimestamp(17, Timestamp.from(attempt.startedAt()));
        statement.setTimestamp(18, null);
        statement.setString(19, attempt.leaseOwner());
        statement.setLong(20, attempt.fencingToken());
        statement.setTimestamp(21, Timestamp.from(attempt.leaseExpiresAt()));
    }

    private static PaymentIntent intent(ResultSet result) throws SQLException {
        String[] allowed = (String[]) result.getArray("allowed_methods").getArray();
        Set<String> methods = Arrays.stream(allowed).collect(Collectors.toUnmodifiableSet());
        return new PaymentIntent(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                result.getObject("merchant_id", UUID.class),
                result.getString("external_reference"),
                Money.of(result.getLong("amount_minor"), result.getString("currency")),
                result.getLong("captured_amount_minor"), result.getLong("refunded_amount_minor"),
                enumValue(IntentState.class, result.getString("state")), methods,
                enumValue(ConfirmationMode.class, result.getString("confirmation_mode")),
                result.getString("region"), result.getString("idempotency_key"),
                result.getTimestamp("expires_at").toInstant(),
                result.getTimestamp("created_at").toInstant(),
                result.getTimestamp("updated_at").toInstant(), result.getLong("version"));
    }

    private static PaymentAttempt attempt(ResultSet result) throws SQLException {
        String outcome = result.getString("outcome_class");
        Timestamp finished = result.getTimestamp("settled_at");
        return new PaymentAttempt(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class),
                result.getObject("payment_intent_id", UUID.class),
                result.getObject("provider_account_id", UUID.class), result.getString("provider"),
                enumValue(AttemptOperation.class, result.getString("operation")),
                result.getInt("sequence"), result.getString("request_digest"),
                result.getString("idempotency_key"),
                enumValue(AttemptState.class, result.getString("state")),
                outcome == null ? null : enumValue(OutcomeClass.class, outcome),
                result.getString("response_digest"), result.getString("provider_request_id"),
                result.getString("provider_transaction_id"),
                result.getString("provider_code_namespace"), result.getString("provider_code"),
                result.getTimestamp("started_at").toInstant(),
                finished == null ? null : finished.toInstant(), result.getString("lease_owner"),
                result.getLong("fencing_token"),
                result.getTimestamp("lease_expires_at").toInstant());
    }

    private static PaymentActionReceipt actionReceipt(ResultSet result) throws SQLException {
        return new PaymentActionReceipt(result.getObject("tenant_id", UUID.class),
                result.getObject("payment_intent_id", UUID.class),
                result.getString("operation"), result.getString("idempotency_key"),
                result.getString("request_digest"), result.getLong("result_intent_version"),
                result.getTimestamp("completed_at").toInstant());
    }

    private static void requireReceiptMatchesIntent(PaymentIntent intent,
            PaymentActionReceipt receipt) {
        if (!receipt.tenantId().equals(intent.tenantId())
                || !receipt.intentId().equals(intent.id())
                || receipt.resultIntentVersion() != intent.version()) {
            throw new PaymentCoreException("ACTION_RECEIPT_INVALID",
                    "action receipt does not match the resulting payment intent");
        }
    }

    private static void requireSameReceipt(PaymentActionReceipt existing,
            PaymentActionReceipt proposed) {
        if (!existing.matches(proposed.operation(), proposed.requestDigest())) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "action key was reused for a different operation or canonical payload");
        }
    }

    private static void requireRecoveryScope(PaymentAttempt originalAttempt,
            PaymentAttempt queryAttempt, PaymentIntent intent) {
        if (!originalAttempt.tenantId().equals(queryAttempt.tenantId())
                || !originalAttempt.intentId().equals(queryAttempt.intentId())
                || !intent.tenantId().equals(originalAttempt.tenantId())
                || !intent.id().equals(originalAttempt.intentId())) {
            throw new PaymentCoreException("RECOVERY_SCOPE_MISMATCH",
                    "recovery attempts must belong to the same tenant and intent");
        }
    }

    private static void requireAttemptLease(int changedRows) {
        if (changedRows != 1) {
            throw new PaymentCoreException("ATTEMPT_LEASE_LOST",
                    "attempt recovery lease is no longer owned by this worker");
        }
    }

    private static void validateLease(String leaseOwner, Instant now, Instant leaseExpiresAt) {
        java.util.Objects.requireNonNull(leaseOwner, "leaseOwner");
        java.util.Objects.requireNonNull(now, "now");
        java.util.Objects.requireNonNull(leaseExpiresAt, "leaseExpiresAt");
        if (leaseOwner.isBlank() || leaseOwner.length() > 128 || !leaseExpiresAt.isAfter(now)) {
            throw new IllegalArgumentException("invalid payment attempt lease");
        }
    }

    private static void advisoryLock(Connection connection, UUID intentId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))")) {
            statement.setString(1, intentId.toString());
            statement.execute();
        }
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
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
        return exception instanceof RuntimeException runtime
                ? runtime : new IllegalStateException(message, exception);
    }

    private static String db(Enum<?> value) {
        return value.name().toLowerCase(Locale.ROOT);
    }

    private static <E extends Enum<E>> E enumValue(Class<E> type, String value) {
        return Enum.valueOf(type, value.toUpperCase(Locale.ROOT));
    }

    @FunctionalInterface
    private interface SqlBinder {
        void bind(PreparedStatement statement) throws SQLException;
    }
}
