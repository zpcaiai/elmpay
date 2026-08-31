package com.elmpay.gateway;

import com.elmpay.merchant.JdbcMerchantConfigurationRepository;
import com.elmpay.merchant.JdbcMerchantControlPlane;
import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.MerchantControlPlane;
import com.elmpay.merchant.RoutingService;
import com.elmpay.payment.InMemoryPaymentRepository;
import com.elmpay.payment.JdbcPaymentRepository;
import com.elmpay.payment.PaymentRepository;
import com.elmpay.payment.PaymentService;
import com.elmpay.payment.ProviderAdapterRegistry;
import com.elmpay.payment.readmodel.JdbcPaymentTimeline;
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
import com.elmpay.risk.runtime.RiskTlsContexts;
import com.elmpay.webhook.ingress.DataSourceWebhookInbox;
import com.elmpay.webhook.ingress.JdbcWebhookIngressEndpointRegistry;
import com.elmpay.webhook.ingress.ProviderWebhookVerifiers;
import com.elmpay.webhook.ingress.WebhookIngressRuntime;
import com.elmpay.webhook.ingress.WebhookIngressService;
import java.net.URI;
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
        if ("postgres".equals(mode) && environment.get("ELMPAY_API_PRINCIPALS") != null
                && !environment.get("ELMPAY_API_PRINCIPALS").isBlank()) {
            throw new IllegalStateException(
                    "production runtime forbids static bearer API principals");
        }
        return switch (mode) {
            case "local" -> local(environment, ApiKeyAuthenticator.parse(
                    environment.get("ELMPAY_API_PRINCIPALS"), true));
            case "postgres" -> postgres(environment,
                    OidcJwtAuthenticator.fromEnvironment(environment, Clock.systemUTC()));
            default -> throw new IllegalStateException(
                    "ELMPAY_RUNTIME_MODE must be explicitly set to local or postgres");
        };
    }

    private static RuntimeComponents local(Map<String, String> environment,
            ApiAuthenticator authenticator) {
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
                new InMemoryPaymentIntentMetadataRepository(), null,
                PaymentTimelineRuntime.unavailable(), java.util.Optional.empty(), true, "local",
                PaymentAdminCommandRuntime.disabled(clock));
    }

    private static RuntimeComponents postgres(Map<String, String> environment,
            ApiAuthenticator authenticator) {
        Clock clock = Clock.systemUTC();
        if (!"elmpay_edge_gateway".equals(required(environment,
                "ELMPAY_DATABASE_USERNAME"))) {
            throw new IllegalStateException(
                    "PostgreSQL runtime requires the dedicated elmpay_edge_gateway role");
        }
        SynchronousRiskGate riskGate = remoteRiskGate(environment, clock);
        DataSource dataSource = DriverManagerDataSource.fromEnvironment(environment,
                "elmpay-edge-gateway");
        var tenantEvidenceVerifier = TenantEvidenceRuntimeFactory.create(environment, dataSource,
                clock);
        new DatabaseMigrator(dataSource).verifyApplied();
        MerchantControlPlane merchantControl = new MerchantControlPlane(
                new JdbcMerchantControlPlane(dataSource), tenantEvidenceVerifier, clock);
        MerchantConfigurationRepository configuration =
                new JdbcMerchantConfigurationRepository(dataSource);
        PaymentRepository payments = new JdbcPaymentRepository(dataSource);
        List<ProviderAdapter> providers = accountAwareProviders(configuration, dataSource,
                environment, clock);
        ProviderAdapterRegistry adapters = new ProviderAdapterRegistry(providers);
        PaymentService service = new PaymentService(payments, configuration,
                new RoutingService(configuration), adapters,
                riskGate, clock, Duration.ofSeconds(configuredLong(environment,
                        "ELMPAY_PAYMENT_ATTEMPT_LEASE_SECONDS", 30L)));
        RefundApplicationService refunds = new RefundApplicationService(new JdbcRefundRepository(dataSource),
                payments, configuration, adapters,
                new SynchronousRiskRefundPolicy(productionRefundRiskPolicy(environment), riskGate),
                new DefaultRefundChannelPolicy(configuration), clock,
                Duration.ofSeconds(30));
        WebhookIngressRuntime webhookIngress = new WebhookIngressRuntime(
                new JdbcWebhookIngressEndpointRegistry(dataSource),
                new WebhookIngressService(ProviderWebhookVerifiers.create(providers),
                        new DataSourceWebhookInbox(dataSource)));
        PaymentTimelineRuntime timeline = new JdbcPaymentTimelineRuntime(
                new JdbcPaymentTimeline(dataSource), environment.getOrDefault(
                        "ELMPAY_TIMELINE_PROJECTOR_NAME", "edge-gateway-payment-timeline-v1"),
                configuredInt(environment, "ELMPAY_TIMELINE_BATCH_SIZE", 100),
                configuredInt(environment, "ELMPAY_TIMELINE_MAXIMUM_BATCHES", 20), clock);
        return new RuntimeComponents(service, authenticator, refunds,
                new JdbcPaymentIntentMetadataRepository(dataSource), webhookIngress, timeline,
                java.util.Optional.of(merchantControl), providersReady(providers),
                "postgres", PaymentAdminCommandRuntime.production(dataSource, environment, clock));
    }

    private static SynchronousRiskGate localRiskGate(Map<String, String> environment, Clock clock) {
        String policy = required(environment, "ELMPAY_LOCAL_RISK_POLICY");
        return switch (policy) {
            case "approve-sandbox" -> new ExplicitSandboxRiskGate(RiskAction.APPROVE, clock);
            case "review-all" -> new ExplicitSandboxRiskGate(RiskAction.REVIEW, clock);
            case "remote-durable" -> remoteRiskGate(environment, clock);
            default -> throw new IllegalStateException(
                    "ELMPAY_LOCAL_RISK_POLICY must be approve-sandbox, review-all, or remote-durable");
        };
    }

    private static SynchronousRiskGate remoteRiskGate(Map<String, String> environment, Clock clock) {
        if (environment.containsKey("ELMPAY_RISK_HMAC_SECRET")
                || environment.containsKey("ELMPAY_RISK_HMAC_SECRET_FILE")) {
            throw new IllegalStateException(
                    "risk HMAC authentication is forbidden; configure the workload mTLS mount");
        }
        String endpoint = required(environment, "ELMPAY_RISK_ENDPOINT");
        int timeoutMilliseconds = configuredInt(environment,
                "ELMPAY_RISK_TIMEOUT_MILLISECONDS", 300);
        if (timeoutMilliseconds != 300) {
            throw new IllegalStateException(
                    "ELMPAY_RISK_TIMEOUT_MILLISECONDS must equal the 300ms topology budget");
        }
        return new RemoteSynchronousRiskGate(URI.create(endpoint),
                RiskTlsContexts.client(environment, "ELMPAY_RISK_", clock),
                Duration.ofMillis(timeoutMilliseconds), clock);
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
