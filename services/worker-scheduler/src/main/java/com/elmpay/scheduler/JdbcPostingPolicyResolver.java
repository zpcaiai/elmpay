package com.elmpay.scheduler;

import com.elmpay.scheduler.events.JdbcEventDeliveryStore;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Resolves one exact, approved tenant/project/provider/currency posting policy. */
public final class JdbcPostingPolicyResolver implements LedgerPostingConsumer.PostingPolicyResolver {
    @Override
    public LedgerPostingConsumer.PostingPolicy resolve(Connection connection,
            JdbcEventDeliveryStore.InboxMessage message,
            LedgerPostingConsumer.FinancialFact fact) throws SQLException {
        Objects.requireNonNull(connection, "connection");
        UUID policyId;
        long version;
        String sourceKind;
        String debitRole;
        String creditRole;
        String description;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT id, policy_version, source_kind, debit_role, credit_role, description
                  FROM ledger_posting_policy
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid
                   AND event_name = ? AND event_version = ? AND currency = ?
                   AND provider = ? AND active
                 FOR SHARE
                """)) {
            statement.setString(1, message.tenantId().toString());
            statement.setString(2, message.projectId().toString());
            statement.setString(3, message.eventName());
            statement.setInt(4, message.eventVersion());
            statement.setString(5, fact.currency());
            statement.setString(6, fact.provider());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw missing("posting policy is missing");
                }
                policyId = result.getObject("id", UUID.class);
                version = result.getLong("policy_version");
                sourceKind = result.getString("source_kind");
                debitRole = result.getString("debit_role");
                creditRole = result.getString("credit_role");
                description = result.getString("description");
                if (result.next()) {
                    throw missing("posting policy is ambiguous");
                }
            }
        }
        Map<String, String> accounts = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT account_role, account_id, currency
                  FROM ledger_posting_account_mapping
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND policy_id = ?::uuid
                 FOR SHARE
                """)) {
            statement.setString(1, message.tenantId().toString());
            statement.setString(2, message.projectId().toString());
            statement.setString(3, policyId.toString());
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    if (!fact.currency().equals(result.getString("currency"))
                            || accounts.put(result.getString("account_role"),
                                    result.getString("account_id")) != null) {
                        throw missing("posting account mapping is ambiguous");
                    }
                }
            }
        }
        if (accounts.size() != 2 || !accounts.containsKey(debitRole)
                || !accounts.containsKey(creditRole)) {
            throw missing("posting policy requires exactly one debit and one credit mapping");
        }
        return new LedgerPostingConsumer.PostingPolicy(version, sourceKind, description,
                accounts.get(debitRole), accounts.get(creditRole));
    }

    private static LedgerPostingConsumer.MissingPostingPolicyException missing(String message) {
        return new LedgerPostingConsumer.MissingPostingPolicyException(message);
    }
}
