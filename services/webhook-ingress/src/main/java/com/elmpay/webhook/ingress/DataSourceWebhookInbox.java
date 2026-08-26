package com.elmpay.webhook.ingress;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Objects;
import javax.sql.DataSource;

/** PostgreSQL-backed verified provider webhook inbox. */
public final class DataSourceWebhookInbox implements WebhookIngressService.Inbox {
    private static final String INSERT = "INSERT INTO provider_webhook_inbox "
            + "(tenant_id, project_id, provider, merchant_account_id, provider_event_id, event_type, "
            + "provider_payment_id, business_order_no, occurred_at, received_at, signature_key_id, "
            + "raw_body_sha256, raw_body, canonical_payload, processing_status) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VERIFIED') "
            + "ON CONFLICT (tenant_id, provider, merchant_account_id, provider_event_id) DO NOTHING";

    private final DataSource dataSource;

    public DataSourceWebhookInbox(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public boolean store(WebhookIngressService.Context context,
            WebhookIngressService.VerifiedEvent event, byte[] rawBody, String rawBodySha256) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(event, "event");
        Objects.requireNonNull(rawBody, "rawBody");
        Objects.requireNonNull(rawBodySha256, "rawBodySha256");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement tenant = connection.prepareStatement(
                    "SELECT set_config('app.tenant_id', ?, true)")) {
                tenant.setString(1, context.tenantId());
                tenant.execute();
            }
            try (PreparedStatement statement = connection.prepareStatement(INSERT)) {
                statement.setString(1, context.tenantId());
                statement.setString(2, context.projectId());
                statement.setString(3, context.provider());
                statement.setString(4, context.merchantAccountId());
                statement.setString(5, event.providerEventId());
                statement.setString(6, event.eventType());
                statement.setString(7, event.providerPaymentId());
                statement.setString(8, event.businessOrderNo());
                statement.setTimestamp(9, Timestamp.from(event.occurredAt()));
                statement.setTimestamp(10, Timestamp.from(context.receivedAt()));
                statement.setString(11, event.signatureKeyId());
                statement.setString(12, rawBodySha256);
                statement.setBytes(13, rawBody);
                statement.setBytes(14, event.canonicalPayload());
                int changed = statement.executeUpdate();
                connection.commit();
                return changed == 1;
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("unable to persist verified provider webhook", exception);
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }
}
