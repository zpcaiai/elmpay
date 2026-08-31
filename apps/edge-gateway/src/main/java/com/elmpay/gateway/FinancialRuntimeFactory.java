package com.elmpay.gateway;

import com.elmpay.reconciliation.ExportManifestSigner;
import com.elmpay.reconciliation.FinancialOperationsService;
import com.elmpay.reconciliation.JdbcFinancialOperationsService;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import javax.sql.DataSource;

/** Fail-closed production financial runtime with exactly one KMS/HSM signer provider. */
public final class FinancialRuntimeFactory {
    private FinancialRuntimeFactory() {}

    public static Optional<FinancialOperationsService> create(Map<String, String> environment) {
        if (!"postgres".equals(environment.get("ELMPAY_RUNTIME_MODE"))) {
            return Optional.empty();
        }
        List<ExportManifestSigner> signers = new ArrayList<>();
        ServiceLoader.load(ExportManifestSigner.class).forEach(signers::add);
        if (signers.size() != 1 || !signers.getFirst().ready()) {
            throw new IllegalStateException(
                    "production financial runtime requires exactly one ready KMS/HSM signer");
        }
        DataSource dataSource = DriverManagerDataSource.fromEnvironment(environment,
                "elmpay-edge-financial");
        return Optional.of(new JdbcFinancialOperationsService(dataSource, Clock.systemUTC(),
                signers.getFirst(), positive(environment, "ELMPAY_STATEMENT_MAX_BYTES", 10_000_000),
                positive(environment, "ELMPAY_STATEMENT_MAX_ROWS", 100_000)));
    }

    private static int positive(Map<String, String> environment, String name, int fallback) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            int parsed = Integer.parseInt(value);
            if (parsed <= 0) {
                throw new NumberFormatException("non-positive");
            }
            return parsed;
        } catch (NumberFormatException invalid) {
            throw new IllegalStateException(name + " must be a positive integer", invalid);
        }
    }

    private static String required(Map<String, String> environment, String name) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for the financial runtime");
        }
        return value;
    }
}
