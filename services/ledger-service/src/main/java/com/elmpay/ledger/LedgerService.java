package com.elmpay.ledger;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import javax.sql.DataSource;

/** Transactional, tenant-scoped, append-only double-entry ledger. */
public final class LedgerService {
    private static final Set<String> SOURCE_KINDS = Set.of(
            "payment", "refund", "fee", "fx", "dispute", "adjustment", "settlement");

    public enum Direction {
        DEBIT, CREDIT;

        Direction opposite() {
            return this == DEBIT ? CREDIT : DEBIT;
        }
    }

    public enum AccountKind {
        ASSET, LIABILITY, REVENUE, EXPENSE, CLEARING
    }

    public record Account(String id, String tenantId, String code, String currency, String name) {}

    public record EntryDraft(String accountId, Direction direction, long amountMinor, String currency) {
        public EntryDraft {
            required(accountId, "accountId");
            Objects.requireNonNull(direction, "direction");
            currency = normalizedCurrency(currency);
            if (amountMinor <= 0) {
                throw new IllegalArgumentException("entry amount must be positive");
            }
        }
    }

    public record PostRequest(String tenantId, String sourceType, String sourceId, Instant effectiveAt,
                              String description, List<EntryDraft> entries) {
        public PostRequest {
            tenantId = uuid(tenantId, "tenantId").toString();
            sourceType = normalizedSourceKind(sourceType);
            required(sourceId, "sourceId");
            required(description, "description");
            Objects.requireNonNull(effectiveAt, "effectiveAt");
            entries = List.copyOf(entries);
            validateBalanced(entries);
        }
    }

    public record PostedTransaction(String id, String tenantId, String sourceType, String sourceId,
                                    Instant effectiveAt, String requestHash, boolean idempotentReplay) {}

    private final DataSource dataSource;
    private final Clock clock;

    public LedgerService(DataSource dataSource, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Account createAccount(String tenantId, String code, String currency, String name)
            throws SQLException {
        return createAccount(tenantId, code, AccountKind.CLEARING, currency, name);
    }

    public Account createAccount(String tenantId, String code, AccountKind kind, String currency,
                                 String name) throws SQLException {
        UUID tenant = uuid(tenantId, "tenantId");
        required(code, "code");
        Objects.requireNonNull(kind, "kind");
        String normalizedCurrency = normalizedCurrency(currency);
        required(name, "name");
        UUID id = UUID.randomUUID();
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenantContext(connection, tenant);
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO ledger_account
                          (id,tenant_id,code,kind,currency,display_name,created_at)
                        VALUES (?,?,?,?,?,?,?)
                        """)) {
                    statement.setObject(1, id);
                    statement.setObject(2, tenant);
                    statement.setString(3, code);
                    statement.setString(4, kind.name().toLowerCase(Locale.ROOT));
                    statement.setString(5, normalizedCurrency);
                    statement.setString(6, name);
                    statement.setTimestamp(7, java.sql.Timestamp.from(clock.instant()));
                    statement.executeUpdate();
                }
                connection.commit();
            } catch (RuntimeException | SQLException failure) {
                rollback(connection, failure);
                throw failure;
            }
        }
        return new Account(id.toString(), tenant.toString(), code, normalizedCurrency, name);
    }

    public PostedTransaction post(PostRequest request) throws SQLException {
        Objects.requireNonNull(request, "request");
        UUID tenant = uuid(request.tenantId(), "tenantId");
        try (Connection connection = dataSource.getConnection()) {
            boolean previousAutoCommit = connection.getAutoCommit();
            int previousIsolation = connection.getTransactionIsolation();
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            try {
                setTenantContext(connection, tenant);
                PostedTransaction posted = postWithinTransaction(connection, request, null, null);
                connection.commit();
                return posted;
            } catch (RuntimeException | SQLException failure) {
                rollback(connection, failure);
                throw failure;
            } finally {
                restore(connection, previousIsolation, previousAutoCommit);
            }
        }
    }

    /**
     * Reverses a transaction once. A distinct approval identity is required for
     * the compensating adjustment; the original row is locked so concurrent
     * callers cannot both dispatch a reversal.
     */
    public PostedTransaction reverse(String tenantId, String transactionId, String reversalSourceId,
                                     String reason, String approvedBy, Instant effectiveAt)
            throws SQLException {
        UUID tenant = uuid(tenantId, "tenantId");
        UUID originalId = uuid(transactionId, "transactionId");
        required(reversalSourceId, "reversalSourceId");
        required(reason, "reason");
        required(approvedBy, "approvedBy");
        Objects.requireNonNull(effectiveAt, "effectiveAt");

        try (Connection connection = dataSource.getConnection()) {
            boolean previousAutoCommit = connection.getAutoCommit();
            int previousIsolation = connection.getTransactionIsolation();
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            try {
                setTenantContext(connection, tenant);
                lockOriginal(connection, tenant, originalId);
                List<EntryDraft> reversed = reversedEntries(connection, tenant, originalId);
                PostRequest request = new PostRequest(tenant.toString(), "adjustment",
                        reversalSourceId, effectiveAt,
                        "Reversal of " + originalId + ": " + reason, reversed);

                PostedTransaction previous = existingReversal(connection, tenant, originalId);
                if (previous != null) {
                    if (!previous.sourceId().equals(reversalSourceId)
                            || !MessageDigest.isEqual(bytes(previous.requestHash()),
                                    bytes(requestHash(request)))) {
                        throw new IllegalStateException("ledger transaction was already reversed");
                    }
                    connection.commit();
                    return replay(previous);
                }

                PostedTransaction posted = postWithinTransaction(
                        connection, request, approvedBy, originalId);
                connection.commit();
                return posted;
            } catch (RuntimeException | SQLException failure) {
                rollback(connection, failure);
                throw failure;
            } finally {
                restore(connection, previousIsolation, previousAutoCommit);
            }
        }
    }

    /** Retained as a fail-closed compatibility overload. */
    public PostedTransaction reverse(String tenantId, String transactionId, String reversalSourceId,
                                     String reason, Instant effectiveAt) throws SQLException {
        throw new IllegalArgumentException("approvedBy is required for a ledger reversal");
    }

    public long accountBalance(String tenantId, String accountId) throws SQLException {
        UUID tenant = uuid(tenantId, "tenantId");
        UUID account = uuid(accountId, "accountId");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setTenantContext(connection, tenant);
                long balance;
                try (PreparedStatement statement = connection.prepareStatement("""
                        SELECT COALESCE(SUM(
                          CASE direction WHEN 'credit' THEN amount_minor ELSE -amount_minor END
                        ),0)
                        FROM ledger_entry WHERE tenant_id=? AND account_id=?
                        """)) {
                    statement.setObject(1, tenant);
                    statement.setObject(2, account);
                    try (ResultSet result = statement.executeQuery()) {
                        result.next();
                        balance = result.getLong(1);
                    }
                }
                connection.commit();
                return balance;
            } catch (RuntimeException | SQLException failure) {
                rollback(connection, failure);
                throw failure;
            }
        }
    }

    public static void validateBalanced(List<EntryDraft> entries) {
        if (entries == null || entries.size() < 2) {
            throw new IllegalArgumentException("a posting requires at least two entries");
        }
        Map<String, Long> totals = new HashMap<>();
        for (EntryDraft entry : entries) {
            long signed = entry.direction() == Direction.DEBIT
                    ? entry.amountMinor() : Math.negateExact(entry.amountMinor());
            totals.merge(entry.currency(), signed, Math::addExact);
        }
        if (totals.values().stream().anyMatch(total -> total != 0L)) {
            throw new IllegalArgumentException("posting is not balanced by currency");
        }
    }

    private PostedTransaction postWithinTransaction(Connection connection, PostRequest request,
                                                    String approvedBy, UUID reversalOf)
            throws SQLException {
        validateAccounts(connection, request);
        String requestHash = requestHash(request);
        UUID id = UUID.randomUUID();
        Savepoint insertion = connection.setSavepoint("ledger_source_insert");
        try (PreparedStatement tx = connection.prepareStatement("""
                INSERT INTO ledger_transaction
                  (id,tenant_id,source_kind,source_id,posted_at,reason,approved_by,request_hash,reversal_of)
                VALUES (?,?,?,?,?,?,?,?,?)
                """)) {
            tx.setObject(1, id);
            tx.setObject(2, uuid(request.tenantId(), "tenantId"));
            tx.setString(3, request.sourceType());
            tx.setString(4, request.sourceId());
            tx.setTimestamp(5, java.sql.Timestamp.from(request.effectiveAt()));
            tx.setString(6, request.description());
            tx.setString(7, approvedBy);
            tx.setString(8, requestHash);
            tx.setObject(9, reversalOf);
            tx.executeUpdate();
            connection.releaseSavepoint(insertion);
        } catch (SQLException conflict) {
            // PostgreSQL marks a transaction failed after 23505. Roll back only
            // the insert before querying the durable replay record.
            rollbackUniqueConflict(connection, insertion, conflict);
            PostedTransaction existing = existing(connection, request.tenantId(),
                    request.sourceType(), request.sourceId());
            if (!MessageDigest.isEqual(bytes(existing.requestHash()), bytes(requestHash))) {
                throw new IllegalStateException(
                        "business source reused with a different posting", conflict);
            }
            return replay(existing);
        }

        try (PreparedStatement entry = connection.prepareStatement("""
                INSERT INTO ledger_entry
                  (id,tenant_id,transaction_id,account_id,direction,amount_minor,currency,posted_at)
                VALUES (?,?,?,?,?,?,?,?)
                """)) {
            UUID tenant = uuid(request.tenantId(), "tenantId");
            for (EntryDraft draft : request.entries()) {
                entry.setObject(1, UUID.randomUUID());
                entry.setObject(2, tenant);
                entry.setObject(3, id);
                entry.setObject(4, uuid(draft.accountId(), "accountId"));
                entry.setString(5, draft.direction().name().toLowerCase(Locale.ROOT));
                entry.setLong(6, draft.amountMinor());
                entry.setString(7, draft.currency());
                entry.setTimestamp(8, java.sql.Timestamp.from(clock.instant()));
                entry.addBatch();
            }
            entry.executeBatch();
        }
        return new PostedTransaction(id.toString(), request.tenantId(), request.sourceType(),
                request.sourceId(), request.effectiveAt(), requestHash, false);
    }

    private void validateAccounts(Connection connection, PostRequest request) throws SQLException {
        try (PreparedStatement account = connection.prepareStatement(
                "SELECT currency FROM ledger_account WHERE id=? AND tenant_id=? FOR SHARE")) {
            UUID tenant = uuid(request.tenantId(), "tenantId");
            for (EntryDraft draft : request.entries()) {
                account.setObject(1, uuid(draft.accountId(), "accountId"));
                account.setObject(2, tenant);
                try (ResultSet result = account.executeQuery()) {
                    if (!result.next()) {
                        throw new SecurityException("ledger account not found for tenant");
                    }
                    if (!result.getString(1).equals(draft.currency())) {
                        throw new IllegalArgumentException("entry/account currency mismatch");
                    }
                }
            }
        }
    }

    private static void lockOriginal(Connection connection, UUID tenant, UUID transaction)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM ledger_transaction WHERE tenant_id=? AND id=? FOR UPDATE")) {
            statement.setObject(1, tenant);
            statement.setObject(2, transaction);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SecurityException("transaction not found for tenant");
                }
            }
        }
    }

    private static List<EntryDraft> reversedEntries(Connection connection, UUID tenant,
                                                     UUID transaction) throws SQLException {
        List<EntryDraft> reversed = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT account_id,direction,amount_minor,currency
                  FROM ledger_entry
                 WHERE tenant_id=? AND transaction_id=? ORDER BY id
                """)) {
            statement.setObject(1, tenant);
            statement.setObject(2, transaction);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    reversed.add(new EntryDraft(rows.getString(1),
                            Direction.valueOf(rows.getString(2).toUpperCase(Locale.ROOT)).opposite(),
                            rows.getLong(3), rows.getString(4)));
                }
            }
        }
        if (reversed.isEmpty()) {
            throw new IllegalStateException("ledger transaction has no entries");
        }
        return reversed;
    }

    private static PostedTransaction existing(Connection connection, String tenant,
                                               String sourceType, String sourceId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id,posted_at,request_hash
                  FROM ledger_transaction
                 WHERE tenant_id=? AND source_kind=? AND source_id=?
                """)) {
            statement.setObject(1, uuid(tenant, "tenantId"));
            statement.setString(2, sourceType);
            statement.setString(3, sourceId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException("unique conflict without existing source");
                }
                return new PostedTransaction(result.getString(1), tenant, sourceType, sourceId,
                        result.getTimestamp(2).toInstant(), result.getString(3), true);
            }
        }
    }

    private static PostedTransaction existingReversal(Connection connection, UUID tenant,
                                                       UUID original) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id,source_kind,source_id,posted_at,request_hash
                  FROM ledger_transaction
                 WHERE tenant_id=? AND reversal_of=?
                """)) {
            statement.setObject(1, tenant);
            statement.setObject(2, original);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                return new PostedTransaction(result.getString(1), tenant.toString(),
                        result.getString(2), result.getString(3),
                        result.getTimestamp(4).toInstant(), result.getString(5), true);
            }
        }
    }

    private static PostedTransaction replay(PostedTransaction existing) {
        return new PostedTransaction(existing.id(), existing.tenantId(), existing.sourceType(),
                existing.sourceId(), existing.effectiveAt(), existing.requestHash(), true);
    }

    private static String requestHash(PostRequest request) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, request.tenantId());
            update(digest, request.sourceType());
            update(digest, request.sourceId());
            update(digest, request.effectiveAt().toString());
            update(digest, request.description());
            request.entries().stream().sorted(java.util.Comparator.comparing(EntryDraft::accountId)
                    .thenComparing(entry -> entry.direction().name())
                    .thenComparingLong(EntryDraft::amountMinor)
                    .thenComparing(EntryDraft::currency)).forEach(entry -> {
                        update(digest, entry.accountId());
                        update(digest, entry.direction().name());
                        update(digest, Long.toString(entry.amountMinor()));
                        update(digest, entry.currency());
                    });
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException(unavailable);
        }
    }

    private static void update(MessageDigest digest, String value) {
        byte[] bytes = bytes(value);
        digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
        digest.update(bytes);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    static void setTenantContext(Connection connection, UUID tenantId) throws SQLException {
        if (connection.getAutoCommit()) {
            throw new SQLException("tenant RLS context requires an explicit transaction");
        }
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    static void rollbackUniqueConflict(Connection connection, Savepoint savepoint,
                                       SQLException failure) throws SQLException {
        if (!"23505".equals(failure.getSQLState())) {
            throw failure;
        }
        connection.rollback(savepoint);
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static void restore(Connection connection, int isolation, boolean autoCommit) {
        try {
            connection.setTransactionIsolation(isolation);
            connection.setAutoCommit(autoCommit);
        } catch (SQLException ignored) {
            // Connection close will evict or reset a broken pooled connection.
        }
    }

    private static UUID uuid(String value, String label) {
        required(value, label);
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException(label + " must be a UUID", invalid);
        }
    }

    private static String normalizedCurrency(String currency) {
        required(currency, "currency");
        String normalized = currency.toUpperCase(Locale.ROOT);
        if (!normalized.matches("[A-Z]{3}")) {
            throw new IllegalArgumentException("currency must be ISO-4217 alpha-3");
        }
        return normalized;
    }

    private static String normalizedSourceKind(String sourceKind) {
        required(sourceKind, "sourceType");
        String normalized = sourceKind.toLowerCase(Locale.ROOT);
        if (!SOURCE_KINDS.contains(normalized)) {
            throw new IllegalArgumentException("unsupported ledger source kind");
        }
        return normalized;
    }

    private static void required(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " is required");
        }
    }
}
