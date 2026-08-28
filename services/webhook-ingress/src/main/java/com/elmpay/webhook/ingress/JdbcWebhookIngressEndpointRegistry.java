package com.elmpay.webhook.ingress;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;

/** Looks up opaque endpoint-token digests through a least-privilege SECURITY DEFINER function. */
public final class JdbcWebhookIngressEndpointRegistry
        implements WebhookIngressRuntime.EndpointRegistry {
    private final DataSource dataSource;

    public JdbcWebhookIngressEndpointRegistry(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public Optional<WebhookIngressRuntime.EndpointBinding> resolve(String endpointToken) {
        WebhookIngressRuntime.requireEndpointToken(endpointToken);
        String digest = sha256(endpointToken);
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            try (PreparedStatement statement = connection.prepareStatement(
                    "SELECT tenant_id, project_id, provider, merchant_account_id "
                            + "FROM elmpay_resolve_webhook_ingress_endpoint(?)")) {
                statement.setString(1, digest);
                try (ResultSet result = statement.executeQuery()) {
                    Optional<WebhookIngressRuntime.EndpointBinding> binding = result.next()
                            ? Optional.of(new WebhookIngressRuntime.EndpointBinding(
                                    result.getString(1), result.getString(2),
                                    result.getString(3), result.getString(4)))
                            : Optional.empty();
                    if (result.next()) {
                        throw new SecurityException("provider webhook endpoint token is ambiguous");
                    }
                    connection.commit();
                    return binding;
                }
            } catch (SQLException | RuntimeException exception) {
                rollback(connection, exception);
                throw exception;
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("provider webhook endpoint lookup failed", exception);
        }
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
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
