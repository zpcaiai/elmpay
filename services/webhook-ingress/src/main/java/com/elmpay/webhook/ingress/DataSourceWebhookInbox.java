package com.elmpay.webhook.ingress;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Objects;
import javax.sql.DataSource;

/** PostgreSQL-backed verified provider webhook inbox. */
public final class DataSourceWebhookInbox implements WebhookIngressService.Inbox {
    private static final String INSERT = "INSERT INTO provider_webhook_inbox "
            + "(tenant_id, project_id, provider, merchant_account_id, provider_event_id, event_type, "
            + "provider_payment_id, business_order_no, occurred_at, received_at, signature_key_id, "
            + "amount_minor, currency, canonical_schema, raw_body_sha256, canonical_payload, "
            + "canonical_payload_sha256, verification_digest, "
            + "processing_status, next_attempt_at) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?) "
            + "ON CONFLICT (tenant_id, provider, merchant_account_id, provider_event_id) DO NOTHING";
    static final String SELECT_DUPLICATE = "SELECT raw_body_sha256, canonical_payload_sha256, "
            + "amount_minor, currency, canonical_schema "
            + "FROM provider_webhook_inbox "
            + "WHERE tenant_id = ? AND provider = ? AND merchant_account_id = ? "
            + "AND provider_event_id = ? FOR UPDATE";

    private final DataSource dataSource;

    public DataSourceWebhookInbox(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public boolean store(WebhookIngressService.Context context,
            WebhookIngressService.VerifiedEvent event, String rawBodySha256) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(event, "event");
        Objects.requireNonNull(rawBodySha256, "rawBodySha256");
        byte[] canonicalPayload = event.canonicalPayload();
        String canonicalPayloadSha256 = WebhookVerificationDigests.sha256(canonicalPayload);
        String verificationDigest = WebhookVerificationDigests.verificationDigest(context, event,
                rawBodySha256, canonicalPayloadSha256);
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
                statement.setObject(12, event.amountMinor());
                statement.setString(13, event.currency());
                statement.setString(14, event.canonicalSchema());
                statement.setString(15, rawBodySha256);
                statement.setBytes(16, canonicalPayload);
                statement.setString(17, canonicalPayloadSha256);
                statement.setString(18, verificationDigest);
                statement.setTimestamp(19, Timestamp.from(context.receivedAt()));
                int changed = statement.executeUpdate();
                if (changed == 0) {
                    requireSameDuplicate(connection, context, event, rawBodySha256,
                            canonicalPayloadSha256);
                }
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

    private static void requireSameDuplicate(Connection connection,
            WebhookIngressService.Context context, WebhookIngressService.VerifiedEvent event,
            String rawBodySha256, String canonicalPayloadSha256) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(SELECT_DUPLICATE)) {
            statement.setString(1, context.tenantId());
            statement.setString(2, context.provider());
            statement.setString(3, context.merchantAccountId());
            statement.setString(4, event.providerEventId());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) {
                    throw new ProviderEventIdentityConflictException(
                            "provider event conflict row is not visible in tenant scope");
                }
                if (!rawBodySha256.equals(row.getString("raw_body_sha256"))
                        || !canonicalPayloadSha256.equals(
                                row.getString("canonical_payload_sha256"))
                        || !Objects.equals(event.amountMinor(), nullableLong(row, "amount_minor"))
                        || !Objects.equals(event.currency(), row.getString("currency"))
                        || !event.canonicalSchema().equals(row.getString("canonical_schema"))) {
                    throw new ProviderEventIdentityConflictException(
                            "provider event id was reused with different verified content");
                }
            }
        }
    }

    private static Long nullableLong(ResultSet row, String column) throws SQLException {
        long value = row.getLong(column);
        return row.wasNull() ? null : value;
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    public static final class ProviderEventIdentityConflictException
            extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        ProviderEventIdentityConflictException(String message) {
            super(message);
        }
    }
}
