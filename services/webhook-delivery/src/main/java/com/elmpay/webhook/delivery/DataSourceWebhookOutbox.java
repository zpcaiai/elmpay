package com.elmpay.webhook.delivery;

import java.net.URI;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL outbox repository with leases, retry scheduling and a durable dead-letter table. */
public final class DataSourceWebhookOutbox implements WebhookDeliveryService.Outbox {
    private final DataSource dataSource;

    public DataSourceWebhookOutbox(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    public void setEndpointStatus(String tenantId, String endpointId, String status,
            String actorId, String approverId, String reason, String ticketId, Instant now) {
        validateId(tenantId, "tenantId");
        validateId(endpointId, "endpointId");
        if (!java.util.Set.of("ACTIVE", "PAUSED", "REVOKED").contains(status)) {
            throw new IllegalArgumentException("invalid endpoint status");
        }
        validateApproval(actorId, approverId, reason, ticketId);
        Objects.requireNonNull(now, "now");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(
                    "UPDATE webhook_endpoint SET status=?, updated_at=? "
                            + "WHERE tenant_id=? AND endpoint_id=?")) {
                statement.setString(1, status);
                statement.setTimestamp(2, Timestamp.from(now));
                statement.setString(3, tenantId);
                statement.setString(4, endpointId);
                if (statement.executeUpdate() != 1) {
                    throw new IllegalArgumentException("unknown webhook endpoint");
                }
            }
            insertAudit(connection, tenantId, "ENDPOINT_STATUS", endpointId, actorId,
                    approverId, reason, ticketId, now);
            connection.commit();
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to change webhook endpoint status", exception);
        }
    }

    public void replayDeadLetter(String tenantId, long deliveryId, String actorId,
            String approverId, String reason, String ticketId, Instant now) {
        validateId(tenantId, "tenantId");
        if (deliveryId <= 0) {
            throw new IllegalArgumentException("deliveryId must be positive");
        }
        validateApproval(actorId, approverId, reason, ticketId);
        Objects.requireNonNull(now, "now");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try {
                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE webhook_delivery_outbox SET state='PENDING', attempt_count=0, "
                                + "next_attempt_at=?, lease_until=NULL, lease_owner=NULL, "
                                + "last_status_code=NULL, "
                                + "last_error_code=NULL, updated_at=? "
                                + "WHERE tenant_id=? AND delivery_id=? AND state='DEAD'")) {
                    statement.setTimestamp(1, Timestamp.from(now));
                    statement.setTimestamp(2, Timestamp.from(now));
                    statement.setString(3, tenantId);
                    statement.setLong(4, deliveryId);
                    if (statement.executeUpdate() != 1) {
                        throw new IllegalArgumentException("unknown or non-dead webhook delivery");
                    }
                }
                try (PreparedStatement statement = connection.prepareStatement(
                        "UPDATE webhook_delivery_dead_letter SET replayed_at=?, replayed_by=?, "
                                + "replay_ticket_id=? WHERE tenant_id=? AND delivery_id=? AND replayed_at IS NULL")) {
                    statement.setTimestamp(1, Timestamp.from(now));
                    statement.setString(2, actorId);
                    statement.setString(3, ticketId);
                    statement.setString(4, tenantId);
                    statement.setLong(5, deliveryId);
                    if (statement.executeUpdate() != 1) {
                        throw new IllegalArgumentException("dead letter was already replayed");
                    }
                }
                insertAudit(connection, tenantId, "DEAD_LETTER_REPLAY", Long.toString(deliveryId),
                        actorId, approverId, reason, ticketId, now);
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to replay webhook dead letter", exception);
        }
    }

    public boolean enqueue(String tenantId, String projectId, String endpointId, String eventId,
            String eventType, byte[] payload, Instant now) {
        validateId(tenantId, "tenantId");
        validateId(projectId, "projectId");
        validateId(endpointId, "endpointId");
        requireText(eventId, "eventId");
        requireText(eventType, "eventType");
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(now, "now");
        if (payload.length == 0 || payload.length > 1_048_576) {
            throw new IllegalArgumentException("payload has an invalid size");
        }
        String sql = "INSERT INTO webhook_delivery_outbox "
                + "(tenant_id, project_id, endpoint_id, event_id, event_type, payload, state, "
                + "attempt_count, next_attempt_at, created_at, updated_at) "
                + "VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 0, ?, ?, ?) "
                + "ON CONFLICT (tenant_id, endpoint_id, event_id) DO NOTHING";
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, tenantId);
                statement.setString(2, projectId);
                statement.setString(3, endpointId);
                statement.setString(4, eventId);
                statement.setString(5, eventType);
                statement.setBytes(6, payload);
                statement.setTimestamp(7, Timestamp.from(now));
                statement.setTimestamp(8, Timestamp.from(now));
                statement.setTimestamp(9, Timestamp.from(now));
                int changed = statement.executeUpdate();
                connection.commit();
                return changed == 1;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to enqueue webhook delivery", exception);
        }
    }

    @Override
    public Optional<WebhookDeliveryService.Delivery> claim(String tenantId, Instant now, Instant leaseUntil) {
        validateId(tenantId, "tenantId");
        Objects.requireNonNull(now, "now");
        Objects.requireNonNull(leaseUntil, "leaseUntil");
        if (!leaseUntil.isAfter(now)) {
            throw new IllegalArgumentException("leaseUntil must be after now");
        }
        String select = "SELECT o.delivery_id, o.project_id, o.endpoint_id, e.endpoint_uri, "
                + "o.event_id, o.event_type, o.payload, o.attempt_count, e.max_attempts "
                + "FROM webhook_delivery_outbox o JOIN webhook_endpoint e "
                + "ON e.tenant_id=o.tenant_id AND e.endpoint_id=o.endpoint_id "
                + "WHERE o.tenant_id=? AND e.status='ACTIVE' AND "
                + "((o.state IN ('PENDING','RETRY') AND o.next_attempt_at<=?) "
                + "OR (o.state='IN_FLIGHT' AND o.lease_until<?)) "
                + "ORDER BY o.next_attempt_at, o.delivery_id FOR UPDATE OF o SKIP LOCKED LIMIT 1";
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(select)) {
                statement.setString(1, tenantId);
                statement.setTimestamp(2, Timestamp.from(now));
                statement.setTimestamp(3, Timestamp.from(now));
                try (ResultSet rows = statement.executeQuery()) {
                    if (!rows.next()) {
                        connection.commit();
                        return Optional.empty();
                    }
                    long deliveryId = rows.getLong(1);
                    String projectId = rows.getString(2);
                    String endpointId = rows.getString(3);
                    URI endpoint = URI.create(rows.getString(4));
                    String eventId = rows.getString(5);
                    String eventType = rows.getString(6);
                    byte[] payload = rows.getBytes(7);
                    int attemptCount = rows.getInt(8);
                    int maxAttempts = rows.getInt(9);
                    String leaseOwner = UUID.randomUUID().toString();
                    long fencingToken;
                    try (PreparedStatement lease = connection.prepareStatement(
                            "UPDATE webhook_delivery_outbox SET state='IN_FLIGHT', lease_until=?, "
                                    + "lease_owner=?, fencing_token=fencing_token+1, updated_at=? "
                                    + "WHERE tenant_id=? AND delivery_id=? RETURNING fencing_token")) {
                        lease.setTimestamp(1, Timestamp.from(leaseUntil));
                        lease.setString(2, leaseOwner);
                        lease.setTimestamp(3, Timestamp.from(now));
                        lease.setString(4, tenantId);
                        lease.setLong(5, deliveryId);
                        try (ResultSet leased = lease.executeQuery()) {
                            if (!leased.next()) {
                                throw new SQLException("unable to lease webhook delivery");
                            }
                            fencingToken = leased.getLong(1);
                        }
                    }
                    WebhookDeliveryService.Delivery delivery = new WebhookDeliveryService.Delivery(
                            deliveryId, tenantId, projectId, endpointId, endpoint, eventId,
                            eventType, payload, attemptCount, maxAttempts, leaseOwner,
                            fencingToken);
                    connection.commit();
                    return Optional.of(delivery);
                }
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to claim webhook delivery", exception);
        }
    }

    @Override
    public void markDelivered(WebhookDeliveryService.Delivery delivery, int statusCode,
            Instant deliveredAt) {
        updateTerminal(delivery, statusCode, "DELIVERED", deliveredAt, null);
    }

    @Override
    public void reschedule(WebhookDeliveryService.Delivery delivery, int statusCode,
            String errorCode,
            Instant nextAttemptAt) {
        requireLease(delivery);
        String tenantId = delivery.tenantId();
        validateId(tenantId, "tenantId");
        requireText(errorCode, "errorCode");
        Objects.requireNonNull(nextAttemptAt, "nextAttemptAt");
        String sql = "UPDATE webhook_delivery_outbox SET state='RETRY', attempt_count=attempt_count+1, "
                + "last_status_code=?, last_error_code=?, next_attempt_at=?, lease_until=NULL, "
                + "lease_owner=NULL, updated_at=now() WHERE tenant_id=? AND delivery_id=? "
                + "AND state='IN_FLIGHT' AND lease_owner=? AND fencing_token=?";
        executeUpdate(tenantId, sql, statement -> {
            statement.setInt(1, statusCode);
            statement.setString(2, errorCode);
            statement.setTimestamp(3, Timestamp.from(nextAttemptAt));
            statement.setString(4, tenantId);
            statement.setLong(5, delivery.deliveryId());
            statement.setString(6, delivery.leaseOwner());
            statement.setLong(7, delivery.fencingToken());
        });
    }

    @Override
    public void deadLetter(WebhookDeliveryService.Delivery delivery, int statusCode,
            String errorCode,
            Instant failedAt) {
        requireLease(delivery);
        String tenantId = delivery.tenantId();
        long deliveryId = delivery.deliveryId();
        validateId(tenantId, "tenantId");
        requireText(errorCode, "errorCode");
        Objects.requireNonNull(failedAt, "failedAt");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try {
                try (PreparedStatement copy = connection.prepareStatement(
                        "INSERT INTO webhook_delivery_dead_letter "
                                + "(delivery_id, tenant_id, project_id, endpoint_id, event_id, event_type, payload, "
                                + "attempt_count, final_status_code, final_error_code, failed_at) "
                                + "SELECT delivery_id, tenant_id, project_id, endpoint_id, event_id, event_type, "
                                + "payload, attempt_count+1, ?, ?, ? FROM webhook_delivery_outbox "
                                + "WHERE tenant_id=? AND delivery_id=? AND state='IN_FLIGHT' "
                                + "AND lease_owner=? AND fencing_token=? "
                                + "ON CONFLICT (tenant_id, delivery_id) DO NOTHING")) {
                    copy.setInt(1, statusCode);
                    copy.setString(2, errorCode);
                    copy.setTimestamp(3, Timestamp.from(failedAt));
                    copy.setString(4, tenantId);
                    copy.setLong(5, deliveryId);
                    copy.setString(6, delivery.leaseOwner());
                    copy.setLong(7, delivery.fencingToken());
                    if (copy.executeUpdate() != 1) {
                        throw new SQLException("unable to create webhook dead letter");
                    }
                }
                try (PreparedStatement update = connection.prepareStatement(
                        "UPDATE webhook_delivery_outbox SET state='DEAD', attempt_count=attempt_count+1, "
                                + "last_status_code=?, last_error_code=?, lease_until=NULL, "
                                + "lease_owner=NULL, updated_at=? WHERE tenant_id=? AND delivery_id=? "
                                + "AND state='IN_FLIGHT' AND lease_owner=? AND fencing_token=?")) {
                    update.setInt(1, statusCode);
                    update.setString(2, errorCode);
                    update.setTimestamp(3, Timestamp.from(failedAt));
                    update.setString(4, tenantId);
                    update.setLong(5, deliveryId);
                    update.setString(6, delivery.leaseOwner());
                    update.setLong(7, delivery.fencingToken());
                    if (update.executeUpdate() != 1) {
                        throw new SQLException("unable to mark webhook delivery dead");
                    }
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to dead-letter webhook delivery", exception);
        }
    }

    private void updateTerminal(WebhookDeliveryService.Delivery delivery, int statusCode,
            String state,
            Instant at, String errorCode) {
        requireLease(delivery);
        String tenantId = delivery.tenantId();
        validateId(tenantId, "tenantId");
        Objects.requireNonNull(at, "at");
        String sql = "UPDATE webhook_delivery_outbox SET state=?, attempt_count=attempt_count+1, "
                + "last_status_code=?, last_error_code=?, lease_until=NULL, lease_owner=NULL, "
                + "delivered_at=?, updated_at=? WHERE tenant_id=? AND delivery_id=? "
                + "AND state='IN_FLIGHT' AND lease_owner=? AND fencing_token=?";
        executeUpdate(tenantId, sql, statement -> {
            statement.setString(1, state);
            statement.setInt(2, statusCode);
            statement.setString(3, errorCode);
            statement.setTimestamp(4, Timestamp.from(at));
            statement.setTimestamp(5, Timestamp.from(at));
            statement.setString(6, tenantId);
            statement.setLong(7, delivery.deliveryId());
            statement.setString(8, delivery.leaseOwner());
            statement.setLong(9, delivery.fencingToken());
        });
    }

    private static void requireLease(WebhookDeliveryService.Delivery delivery) {
        Objects.requireNonNull(delivery, "delivery");
        validateId(delivery.tenantId(), "tenantId");
        validateId(delivery.leaseOwner(), "leaseOwner");
        if (delivery.deliveryId() <= 0 || delivery.fencingToken() <= 0) {
            throw new IllegalArgumentException("delivery lease is invalid");
        }
    }

    private void executeUpdate(String tenantId, String sql, StatementBinder binder) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                binder.bind(statement);
                if (statement.executeUpdate() != 1) {
                    throw new SQLException("webhook delivery update lost its lease");
                }
                connection.commit();
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to update webhook delivery", exception);
        }
    }

    private static void setTenant(Connection connection, String tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId);
            statement.execute();
        }
    }

    private static void insertAudit(Connection connection, String tenantId, String action,
            String targetId, String actorId, String approverId, String reason, String ticketId,
            Instant at) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO webhook_delivery_admin_audit "
                        + "(tenant_id, action, target_id, actor_id, approver_id, reason, ticket_id, occurred_at) "
                        + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {
            statement.setString(1, tenantId);
            statement.setString(2, action);
            statement.setString(3, targetId);
            statement.setString(4, actorId);
            statement.setString(5, approverId);
            statement.setString(6, reason);
            statement.setString(7, ticketId);
            statement.setTimestamp(8, Timestamp.from(at));
            statement.executeUpdate();
        }
    }

    private static void validateApproval(String actorId, String approverId,
            String reason, String ticketId) {
        validateId(actorId, "actorId");
        validateId(approverId, "approverId");
        if (actorId.equals(approverId)) {
            throw new IllegalArgumentException("actor and approver must be different");
        }
        requireText(reason, "reason");
        requireText(ticketId, "ticketId");
    }

    @FunctionalInterface
    private interface StatementBinder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static void validateId(String value, String name) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{3,64}")) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 160) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }
}
