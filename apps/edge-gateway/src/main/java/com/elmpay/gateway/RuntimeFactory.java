package com.elmpay.gateway;

import com.elmpay.merchant.JdbcMerchantConfigurationRepository;
import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.RoutingService;
import com.elmpay.payment.InMemoryPaymentRepository;
import com.elmpay.payment.JdbcPaymentRepository;
import com.elmpay.payment.PaymentRepository;
import com.elmpay.payment.PaymentService;
import com.elmpay.payment.ProviderAdapterRegistry;
import com.elmpay.payment.refund.DefaultRefundChannelPolicy;
import com.elmpay.payment.refund.InMemoryRefundRepository;
import com.elmpay.payment.refund.JdbcRefundRepository;
import com.elmpay.payment.refund.RefundApplicationService;
import com.elmpay.payment.refund.RefundRiskDecision;
import com.elmpay.payment.refund.RulesRefundRiskPolicy;
import com.elmpay.provider.ProviderAdapter;
import java.time.Duration;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import javax.sql.DataSource;

public final class RuntimeFactory {
    private RuntimeFactory() {
    }

    public static RuntimeComponents create(Map<String, String> environment) {
        String mode = environment.getOrDefault("ELMPAY_RUNTIME_MODE", "disabled");
        ApiKeyAuthenticator authenticator = ApiKeyAuthenticator.parse(
                environment.get("ELMPAY_API_PRINCIPALS"), "local".equals(mode));
        return switch (mode) {
            case "local" -> local(environment, authenticator);
            case "postgres" -> postgres(environment, authenticator);
            default -> throw new IllegalStateException(
                    "ELMPAY_RUNTIME_MODE must be explicitly set to local or postgres");
        };
    }

    private static RuntimeComponents local(Map<String, String> environment,
            ApiKeyAuthenticator authenticator) {
        if (!"true".equals(environment.get("ELMPAY_ENABLE_LOCAL_SANDBOX"))) {
            throw new IllegalStateException("local sandbox requires ELMPAY_ENABLE_LOCAL_SANDBOX=true");
        }
        MerchantConfigurationRepository configuration =
                new LocalMerchantConfigurationRepository();
        InMemoryPaymentRepository paymentRepository = new InMemoryPaymentRepository();
        ProviderAdapterRegistry adapters = new ProviderAdapterRegistry(
                List.of(new LocalSandboxProviderAdapter()));
        PaymentService service = new PaymentService(paymentRepository, configuration,
                new RoutingService(configuration),
                adapters,
                Clock.systemUTC());
        RefundApplicationService refunds = new RefundApplicationService(new InMemoryRefundRepository(),
                paymentRepository, configuration, adapters, context -> RefundRiskDecision.AUTO_APPROVE,
                new DefaultRefundChannelPolicy(configuration), Clock.systemUTC(), Duration.ZERO);
        return new RuntimeComponents(service, authenticator, refunds,
                new InMemoryPaymentIntentMetadataRepository(), true, "local");
    }

    private static RuntimeComponents postgres(Map<String, String> environment,
            ApiKeyAuthenticator authenticator) {
        DataSource dataSource = new DriverManagerDataSource(required(environment, "ELMPAY_DATABASE_URL"),
                required(environment, "ELMPAY_DATABASE_USER"),
                required(environment, "ELMPAY_DATABASE_PASSWORD"));
        new DatabaseMigrator(dataSource).migrate();
        MerchantConfigurationRepository configuration =
                new JdbcMerchantConfigurationRepository(dataSource);
        PaymentRepository payments = new JdbcPaymentRepository(dataSource);
        List<ProviderAdapter> providers = new ArrayList<>();
        ServiceLoader.load(ProviderAdapter.class).forEach(providers::add);
        ProviderAdapterRegistry adapters = new ProviderAdapterRegistry(providers);
        PaymentService service = new PaymentService(payments, configuration,
                new RoutingService(configuration), adapters,
                Clock.systemUTC());
        RefundApplicationService refunds = new RefundApplicationService(new JdbcRefundRepository(dataSource),
                payments, configuration, adapters, productionRefundRiskPolicy(environment),
                new DefaultRefundChannelPolicy(configuration), Clock.systemUTC(),
                Duration.ofSeconds(30));
        return new RuntimeComponents(service, authenticator, refunds,
                new JdbcPaymentIntentMetadataRepository(dataSource), providersReady(providers),
                "postgres");
    }

    private static RulesRefundRiskPolicy productionRefundRiskPolicy(Map<String, String> environment) {
        return new RulesRefundRiskPolicy(context -> new RulesRefundRiskPolicy.Signals(
                environment.getOrDefault("ELMPAY_REFUND_REQUESTER_ROLE", "unknown"),
                false, configuredInt(environment, "ELMPAY_REFUND_ANOMALY_SCORE", 0),
                configuredLong(environment, "ELMPAY_REFUND_MANUAL_REVIEW_THRESHOLD_MINOR",
                        1_000_000_000L),
                Duration.ofDays(configuredLong(environment, "ELMPAY_REFUND_MAXIMUM_AGE_DAYS",
                        90L)),
                "true".equalsIgnoreCase(environment.get("ELMPAY_REFUND_FORCE_REVIEW"))),
                configuredInt(environment, "ELMPAY_REFUND_REVIEW_ANOMALY_SCORE", 50),
                configuredInt(environment, "ELMPAY_REFUND_DENY_ANOMALY_SCORE", 90));
    }

    private static int configuredInt(Map<String, String> environment, String key, int fallback) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            throw new IllegalStateException(key + " is invalid", exception);
        }
    }

    private static long configuredLong(Map<String, String> environment, String key, long fallback) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException exception) {
            throw new IllegalStateException(key + " is invalid", exception);
        }
    }

    static boolean providersReady(List<ProviderAdapter> providers) {
        return providers.stream().anyMatch(ProviderAdapter::configured);
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value;
    }
}
