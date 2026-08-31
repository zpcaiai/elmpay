package com.elmpay.gateway;

import com.elmpay.payment.checkout.HostedCheckoutService;
import com.elmpay.payment.PaymentCoreException;
import com.elmpay.security.CanonicalPayload;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Authorizes minimal checkout SDK configuration and durably binds every disclosure. */
public final class CheckoutProviderSdkRuntime {
    public record Configuration(String method, String provider, String sdkVersion,
            Map<String, String> publicParameters) {
        public Configuration {
            publicParameters = Map.copyOf(publicParameters);
        }
    }

    private final HostedCheckoutService checkout;
    private final CheckoutProviderSdkRegistry registry;
    private final CheckoutProviderSdkAudit audit;
    private final Clock clock;

    public CheckoutProviderSdkRuntime(HostedCheckoutService checkout,
            CheckoutProviderSdkRegistry registry, CheckoutProviderSdkAudit audit, Clock clock) {
        this.checkout = Objects.requireNonNull(checkout, "checkout");
        this.registry = Objects.requireNonNull(registry, "registry");
        this.audit = Objects.requireNonNull(audit, "audit");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Configuration authorizeBrowser(String sessionId, String accessToken, String method,
            String channel, String requestId) {
        HostedCheckoutService.ProviderSdkAuthorization authorization = checkout
                .authorizeProviderSdkForBrowser(sessionId, accessToken, method, "WEB");
        return authorize(authorization, channel, "checkout_session", sessionId, requestId);
    }

    public Configuration authorizePrincipal(ApiPrincipal principal, String sessionId, String method,
            String channel, String requestId) {
        HostedCheckoutService.ProviderSdkAuthorization authorization = checkout
                .authorizeProviderSdkForPrincipal(principal.tenantId(), principal.projectId(),
                        sessionId, method, "WEB");
        if (!authorization.merchantId().equals(principal.merchantId())) {
            throw new AccessDeniedException("checkout session is outside this merchant");
        }
        return authorize(authorization, channel, "oauth_client", principal.id(), requestId);
    }

    private Configuration authorize(HostedCheckoutService.ProviderSdkAuthorization authorization,
            String channel, String actorType, String actorId, String requestId) {
        if (channel == null || !channel.matches("[A-Za-z0-9_-]{20,128}")) {
            throw new IllegalArgumentException("provider SDK channel is invalid");
        }
        CheckoutProviderSdkRegistry.Configuration selected = registry.resolve(
                authorization.provider(), authorization.method()).orElseThrow(() ->
                new PaymentCoreException("PROVIDER_NOT_CONFIGURED",
                        "provider SDK is not enabled by server policy"));
        Configuration result = new Configuration(selected.method(), selected.provider(),
                selected.sdkVersion(), selected.publicParameters());
        String configurationDigest = CanonicalPayload.sha256Hex(Map.of(
                "method", result.method(), "provider", result.provider(),
                "sdk_version", result.sdkVersion(), "public_parameters", result.publicParameters()));
        Instant now = clock.instant();
        audit.append(new CheckoutProviderSdkAudit.Receipt(UUID.randomUUID(),
                authorization.tenantId(), authorization.projectId(), authorization.merchantId(),
                authorization.checkoutSessionId(), authorization.paymentIntentId(),
                authorization.providerAccountId(), authorization.method(), authorization.provider(),
                actorType, actorId, requestId,
                CanonicalPayload.sha256Hex(Map.of("channel", channel)),
                authorization.businessOrderDigest(), authorization.checkoutSnapshotDigest(),
                configurationDigest, authorization.capabilityVersion(), selected.policyVersion(),
                authorization.expiresAt(), now));
        return result;
    }
}
