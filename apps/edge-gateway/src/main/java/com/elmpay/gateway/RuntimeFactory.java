package com.elmpay.gateway;

import com.elmpay.merchant.JdbcMerchantConfigurationRepository;
import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.RoutingService;
import com.elmpay.payment.InMemoryPaymentRepository;
import com.elmpay.payment.JdbcPaymentRepository;
import com.elmpay.payment.PaymentRepository;
import com.elmpay.payment.PaymentService;
import com.elmpay.payment.ProviderAdapterRegistry;
import com.elmpay.payment.provider.AccountAwareProviderAdapterFactory;
import com.elmpay.payment.provider.JdbcProviderCallCircuitBreaker;
import com.elmpay.payment.provider.ProviderAccountAdapterFactory;
import com.elmpay.payment.provider.ProviderCredentialResolver;
import com.elmpay.payment.provider.ProviderReadinessBinding;
import com.elmpay.payment.provider.ProductionProviderAccountFactories;
import com.elmpay.payment.refund.DefaultRefundChannelPolicy;
import com.elmpay.payment.refund.InMemoryRefundRepository;
import com.elmpay.payment.refund.JdbcRefundRepository;
import com.elmpay.payment.refund.RefundApplicationService;
import com.elmpay.payment.refund.RefundRiskDecision;
import com.elmpay.payment.refund.RulesRefundRiskPolicy;
import com.elmpay.payment.refund.SynchronousRiskRefundPolicy;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.risk.RiskAction;
import com.elmpay.risk.SynchronousRiskGate;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.UUID;
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
        Clock clock = Clock.systemUTC();
        SynchronousRiskGate riskGate = localRiskGate(environment, clock);
        PaymentService service = new PaymentService(paymentRepository, configuration,
                new RoutingService(configuration),
                adapters,
                riskGate, clock);
        RefundApplicationService refunds = new RefundApplicationService(new InMemoryRefundRepository(),
                paymentRepository, configuration, adapters,
                new SynchronousRiskRefundPolicy(
                        context -> RefundRiskDecision.AUTO_APPROVE, riskGate),
                new DefaultRefundChannelPolicy(configuration), clock, Duration.ZERO);
        return new RuntimeComponents(service, authenticator, refunds,
                new InMemoryPaymentIntentMetadataRepository(), true, "local");
    }

    private static RuntimeComponents postgres(Map<String, String> environment,
            ApiKeyAuthenticator authenticator) {
        Clock clock = Clock.systemUTC();
        SynchronousRiskGate riskGate = remoteRiskGate(environment, clock, false);
        DataSource dataSource = new DriverManagerDataSource(required(environment, "ELMPAY_DATABASE_URL"),
                required(environment, "ELMPAY_DATABASE_USER"),
                required(environment, "ELMPAY_DATABASE_PASSWORD"));
        new DatabaseMigrator(dataSource).migrate();
        MerchantConfigurationRepository configuration =
                new JdbcMerchantConfigurationRepository(dataSource);
        PaymentRepository payments = new JdbcPaymentRepository(dataSource);
        List<ProviderAdapter> providers = accountAwareProviders(configuration, dataSource,
                environment, clock);
        ProviderAdapterRegistry adapters = new ProviderAdapterRegistry(providers);
        PaymentService service = new PaymentService(payments, configuration,
                new RoutingService(configuration), adapters,
                riskGate, clock);
        RefundApplicationService refunds = new RefundApplicationService(new JdbcRefundRepository(dataSource),
                payments, configuration, adapters,
                new SynchronousRiskRefundPolicy(productionRefundRiskPolicy(environment), riskGate),
                new DefaultRefundChannelPolicy(configuration), clock,
                Duration.ofSeconds(30));
        return new RuntimeComponents(service, authenticator, refunds,
                new JdbcPaymentIntentMetadataRepository(dataSource), providersReady(providers),
                "postgres");
    }

    private static SynchronousRiskGate localRiskGate(Map<String, String> environment, Clock clock) {
        String policy = required(environment, "ELMPAY_LOCAL_RISK_POLICY");
        return switch (policy) {
            case "approve-sandbox" -> new ExplicitSandboxRiskGate(RiskAction.APPROVE, clock);
            case "review-all" -> new ExplicitSandboxRiskGate(RiskAction.REVIEW, clock);
            case "remote-durable" -> remoteRiskGate(environment, clock, true);
            default -> throw new IllegalStateException(
                    "ELMPAY_LOCAL_RISK_POLICY must be approve-sandbox, review-all, or remote-durable");
        };
    }

    private static SynchronousRiskGate remoteRiskGate(Map<String, String> environment, Clock clock,
            boolean allowLoopbackHttp) {
        String endpoint = required(environment, "ELMPAY_RISK_ENDPOINT");
        String secret = required(environment, "ELMPAY_RISK_HMAC_SECRET");
        int timeoutMilliseconds = configuredInt(environment,
                "ELMPAY_RISK_TIMEOUT_MILLISECONDS", 250);
        return new RemoteSynchronousRiskGate(URI.create(endpoint),
                secret.getBytes(StandardCharsets.UTF_8), Duration.ofMillis(timeoutMilliseconds),
                clock, allowLoopbackHttp);
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
        return !providers.isEmpty() && providers.stream().allMatch(ProviderAdapter::configured);
    }

    private static List<ProviderAdapter> accountAwareProviders(
            MerchantConfigurationRepository configuration, DataSource dataSource,
            Map<String, String> environment, Clock clock) {
        List<ProviderAccountAdapterFactory> factories = new ArrayList<>(
                ProductionProviderAccountFactories.create(dataSource, environment, clock));
        ServiceLoader.load(ProviderAccountAdapterFactory.class).forEach(factories::add);
        List<ProviderCredentialResolver> resolvers = new ArrayList<>();
        ServiceLoader.load(ProviderCredentialResolver.class).forEach(resolvers::add);
        if (resolvers.size() != 1) {
            throw new IllegalStateException(
                    "account-aware provider runtime requires exactly one credential resolver");
        }
        JdbcProviderCallCircuitBreaker circuitBreaker = new JdbcProviderCallCircuitBreaker(
                dataSource, JdbcProviderCallCircuitBreaker.Policy.fromEnvironment(environment),
                clock);
        return new AccountAwareProviderAdapterFactory(configuration, resolvers.getFirst(), factories,
                circuitBreaker,
                readinessBindings(environment.get("ELMPAY_PROVIDER_READINESS_ACCOUNTS")))
                .createAdapters();
    }

    static List<ProviderReadinessBinding> readinessBindings(String configured) {
        if (configured == null || configured.isBlank()) {
            return List.of();
        }
        List<ProviderReadinessBinding> bindings = new ArrayList<>();
        for (String entry : configured.split(",", -1)) {
            String[] fields = entry.strip().split("\\|", -1);
            if (fields.length != 4) {
                throw new IllegalStateException(
                        "ELMPAY_PROVIDER_READINESS_ACCOUNTS has an invalid entry");
            }
            try {
                bindings.add(new ProviderReadinessBinding(fields[0].strip(),
                        UUID.fromString(fields[1].strip()), UUID.fromString(fields[2].strip()),
                        UUID.fromString(fields[3].strip())));
            } catch (IllegalArgumentException exception) {
                throw new IllegalStateException(
                        "ELMPAY_PROVIDER_READINESS_ACCOUNTS has an invalid entry", exception);
            }
        }
        return List.copyOf(bindings);
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value;
    }
}
