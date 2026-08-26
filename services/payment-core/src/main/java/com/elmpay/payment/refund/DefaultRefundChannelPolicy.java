package com.elmpay.payment.refund;

import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.ProviderAccount;
import com.elmpay.merchant.ProviderRoute;
import com.elmpay.merchant.RoutingRequest;
import com.elmpay.payment.PaymentCoreException;
import com.elmpay.payment.PaymentIntent;
import java.util.Objects;

/**
 * Resolves refund capability from the server-side merchant configuration snapshot.
 * A provider account being present is not enough: the selected route must advertise
 * partial-refund support for the intent's immutable method, currency and region.
 */
public final class DefaultRefundChannelPolicy implements RefundChannelPolicy {
    private final MerchantConfigurationRepository configuration;

    public DefaultRefundChannelPolicy(MerchantConfigurationRepository configuration) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
    }

    @Override
    public void validate(ProviderAccount account, PaymentIntent intent, long amountMinor,
            RefundReason reason) {
        Objects.requireNonNull(account, "account");
        Objects.requireNonNull(intent, "intent");
        Objects.requireNonNull(reason, "reason");
        if (!account.status().permitsRefunds()) {
            throw new PaymentCoreException("PROVIDER_ACCOUNT_REFUND_DISABLED",
                    "provider account is not permitted to issue refunds");
        }
        boolean capable = intent.allowedMethods().stream().anyMatch(method ->
                configuration.eligibleRoutes(new RoutingRequest(intent.tenantId(),
                        intent.projectId(), intent.merchantId(), method,
                        intent.amount().currency().code(), intent.region(), amountMinor,
                        intent.id().toString())).stream().anyMatch(route -> matches(route,
                                account, method, intent)));
        if (!capable) {
            throw new PaymentCoreException("REFUND_CAPABILITY_MISSING",
                    "no configured provider route supports refunds for this payment");
        }
    }

    private static boolean matches(ProviderRoute route, ProviderAccount account, String method,
            PaymentIntent intent) {
        return route.account().id().equals(account.id())
                && route.account().tenantId().equals(intent.tenantId())
                && route.account().projectId().equals(intent.projectId())
                && route.capability().partialRefund()
                && route.capability().supports(method, intent.amount().currency().code(),
                        intent.region());
    }
}
