package com.elmpay.ledger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Clock;
import java.util.Objects;
import java.util.UUID;

import javax.sql.DataSource;

/** Persists versioned fee/FX/settlement facts without taking custody of funds. */
public final class FinancialFactsRepository {
    private final DataSource dataSource;
    private final Clock clock;

    public FinancialFactsRepository(DataSource dataSource, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource);
        this.clock = Objects.requireNonNull(clock);
    }

    public void saveFee(String tenantId, String sourceType, String sourceId,
                        FeeFxSettlementService.FeeBreakdown fee) throws SQLException {
        UUID tenant = UUID.fromString(tenantId);
        inTenantTransaction(tenant, connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO fee_record
                      (id,tenant_id,source_type,source_id,currency,gross_minor,fixed_minor,
                       variable_minor,tax_minor,total_minor,rule_version,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """)) {
                statement.setObject(1, UUID.randomUUID());
                statement.setObject(2, tenant);
                statement.setString(3, sourceType);
                statement.setString(4, sourceId);
                statement.setString(5, fee.currency());
                statement.setLong(6, fee.grossMinor());
                statement.setLong(7, fee.fixedMinor());
                statement.setLong(8, fee.variableMinor());
                statement.setLong(9, fee.taxMinor());
                statement.setLong(10, fee.totalFeeMinor());
                statement.setString(11, fee.ruleVersion());
                statement.setTimestamp(12, java.sql.Timestamp.from(clock.instant()));
                statement.executeUpdate();
            }
        });
    }

    public void saveFx(String tenantId, FeeFxSettlementService.FxRate rate) throws SQLException {
        UUID tenant = UUID.fromString(tenantId);
        inTenantTransaction(tenant, connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO fx_rate
                      (id,tenant_id,source,base_currency,quote_currency,numerator,denominator,
                       observed_at,version,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """)) {
                statement.setObject(1, UUID.randomUUID());
                statement.setObject(2, tenant);
                statement.setString(3, rate.source());
                statement.setString(4, rate.baseCurrency());
                statement.setString(5, rate.quoteCurrency());
                statement.setLong(6, rate.numerator());
                statement.setLong(7, rate.denominator());
                statement.setTimestamp(8, java.sql.Timestamp.from(rate.observedAt()));
                statement.setString(9, rate.version());
                statement.setTimestamp(10, java.sql.Timestamp.from(clock.instant()));
                statement.executeUpdate();
            }
        });
    }

    /** Tenant-less FX persistence is deliberately disabled under FORCE RLS. */
    public void saveFx(FeeFxSettlementService.FxRate rate) {
        throw new IllegalArgumentException("tenantId is required to persist an FX rate");
    }

    public void saveSettlement(FeeFxSettlementService.SettlementView view) throws SQLException {
        UUID tenant = UUID.fromString(view.tenantId());
        inTenantTransaction(tenant, connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO settlement_instruction
                      (id,tenant_id,provider_batch_id,currency,gross_minor,fee_minor,
                       expected_bank_minor,expected_arrival,provider_status,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """)) {
                statement.setObject(1, UUID.randomUUID());
                statement.setObject(2, tenant);
                statement.setString(3, view.providerBatchId());
                statement.setString(4, view.currency());
                statement.setLong(5, view.grossMinor());
                statement.setLong(6, view.feeMinor());
                statement.setLong(7, view.expectedBankMinor());
                statement.setTimestamp(8, java.sql.Timestamp.from(view.expectedArrival()));
                statement.setString(9, view.providerStatus());
                statement.setTimestamp(10, java.sql.Timestamp.from(clock.instant()));
                statement.executeUpdate();
            }
        });
    }

    private void inTenantTransaction(UUID tenant, SqlWork work) throws SQLException {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                LedgerService.setTenantContext(connection, tenant);
                work.run(connection);
                connection.commit();
            } catch (RuntimeException | SQLException failure) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackFailure) {
                    failure.addSuppressed(rollbackFailure);
                }
                throw failure;
            }
        }
    }

    @FunctionalInterface
    private interface SqlWork {
        void run(Connection connection) throws SQLException;
    }
}
