package com.elmpay.scheduler.events;

import com.elmpay.events.EventEnvelope;
import com.elmpay.events.StrictJson;
import com.elmpay.webhook.delivery.DataSourceWebhookOutbox;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;

/**
 * Fans a committed domain event out to every active endpoint for the exact tenant/project before
 * publishing the same canonical envelope to Kafka.
 *
 * <p>The webhook outbox has a unique {@code (tenant_id, endpoint_id, event_id)} key. Therefore a
 * crash after fanout or a Kafka failure is safely retried: already-enqueued deliveries remain
 * unchanged and missing deliveries are inserted. Kafka publication remains at-least-once, with
 * its existing durable consumer inbox providing business-effect idempotency.
 */
public final class WebhookFanoutPublisher implements OutboxRelay.Publisher {
    @FunctionalInterface
    interface EndpointSource {
        List<String> activeEndpointIds(UUID tenantId, UUID projectId);
    }

    @FunctionalInterface
    interface DeliveryOutbox {
        boolean enqueue(UUID tenantId, UUID projectId, String endpointId, UUID eventId,
                String eventType, byte[] payload, Instant now);
    }

    private final EndpointSource endpoints;
    private final DeliveryOutbox deliveries;
    private final OutboxRelay.Publisher broker;
    private final Clock clock;

    public WebhookFanoutPublisher(DataSource dataSource, OutboxRelay.Publisher broker, Clock clock) {
        Objects.requireNonNull(dataSource, "dataSource");
        DataSourceWebhookOutbox outbox = new DataSourceWebhookOutbox(dataSource);
        this.endpoints = (tenantId, projectId) -> activeEndpointIds(
                dataSource, tenantId, projectId);
        this.deliveries = (tenantId, projectId, endpointId, eventId, eventType, payload, now) ->
                outbox.enqueue(tenantId.toString(), projectId.toString(), endpointId,
                        eventId.toString(), eventType, payload, now);
        this.broker = Objects.requireNonNull(broker, "broker");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    WebhookFanoutPublisher(EndpointSource endpoints, DeliveryOutbox deliveries,
            OutboxRelay.Publisher broker, Clock clock) {
        this.endpoints = Objects.requireNonNull(endpoints, "endpoints");
        this.deliveries = Objects.requireNonNull(deliveries, "deliveries");
        this.broker = Objects.requireNonNull(broker, "broker");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public void publish(OutboxRelay.Message message) throws Exception {
        Objects.requireNonNull(message, "message");
        EventEnvelope envelope = new EventEnvelope(message.eventId(), message.eventName(),
                message.eventVersion(), message.tenantId(), message.projectId(),
                message.aggregateType(), message.aggregateId(), message.aggregateRevision(),
                message.occurredAt(), message.recordedAt(), message.traceId(),
                StrictJson.object(message.payloadJson()));
        byte[] payload = envelope.canonicalJson().getBytes(StandardCharsets.UTF_8);
        try {
            Instant now = clock.instant();
            for (String endpointId : endpoints.activeEndpointIds(
                    message.tenantId(), message.projectId())) {
                deliveries.enqueue(message.tenantId(), message.projectId(), endpointId,
                        message.eventId(), message.eventName(), payload, now);
            }
            broker.publish(message);
        } finally {
            java.util.Arrays.fill(payload, (byte) 0);
        }
    }

    private static List<String> activeEndpointIds(DataSource dataSource, UUID tenantId,
            UUID projectId) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            setTenant(connection, tenantId);
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT endpoint_id
                      FROM webhook_endpoint
                     WHERE tenant_id=? AND project_id=? AND status='ACTIVE'
                     ORDER BY endpoint_id
                    """)) {
                statement.setString(1, tenantId.toString());
                statement.setString(2, projectId.toString());
                try (ResultSet rows = statement.executeQuery()) {
                    List<String> endpointIds = new ArrayList<>();
                    while (rows.next()) {
                        endpointIds.add(rows.getString(1));
                    }
                    connection.commit();
                    return List.copyOf(endpointIds);
                }
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("unable to resolve active webhook endpoints", failure);
        }
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private static void rollback(Connection connection, Throwable original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }
}
