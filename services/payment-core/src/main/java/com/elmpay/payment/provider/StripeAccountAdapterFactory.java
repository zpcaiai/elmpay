package com.elmpay.payment.provider;

import com.elmpay.connectors.stripe.StripeAdapter;
import com.elmpay.connectors.stripe.StripeProviderBridge;
import com.elmpay.merchant.ProviderAccount;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Account-bound Stripe PaymentIntents runtime; raw card data never enters this factory. */
public final class StripeAccountAdapterFactory implements ProviderAccountAdapterFactory {
    private final ProviderRuntimeLookup lookup;
    private final URI approvedReturnBase;
    private final Duration timeout;
    private final Duration webhookTolerance;
    private final int attempts;
    private final Clock clock;

    public StripeAccountAdapterFactory(ProviderRuntimeLookup lookup, URI approvedReturnBase,
            Duration timeout, Duration webhookTolerance, int attempts, Clock clock) {
        this.lookup = Objects.requireNonNull(lookup, "lookup");
        this.approvedReturnBase = requireHttpsBase(approvedReturnBase);
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.webhookTolerance = Objects.requireNonNull(webhookTolerance, "webhookTolerance");
        this.attempts = attempts;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String provider() {
        return "stripe";
    }

    @Override
    public ProviderRuntimeAdapter create(ProviderAccount account, ProviderCredential credential) {
        requireAccount(account);
        SecretMaterialProviderCredential material = ProviderCredentialMaterial.require(credential);
        ProviderCredentialMaterial.requireAccountBinding(material, account.providerMerchantId());
        String webhookKeyId = ProviderCredentialMaterial.text(material, "webhook_key_id", 128);
        byte[] webhookSecret = ProviderCredentialMaterial.bytes(material, "webhook_secret", 16,
                8_192);
        StripeAdapter adapter;
        try {
            Instant now = clock.instant();
            StripeAdapter.WebhookSecret secret = new StripeAdapter.WebhookSecret(webhookKeyId,
                    webhookSecret, now.minus(webhookTolerance), material.expiresAt());
            StripeAdapter.SecretProvider secretProvider = () -> ProviderCredentialMaterial.text(
                    material, "api_key", 8_192);
            adapter = new StripeAdapter(new StripeAdapter.Config(
                    URI.create("https://api.stripe.com/"), approvedReturnBase, secretProvider,
                    List.of(secret), timeout, webhookTolerance, attempts, clock),
                    new StripeAdapter.JdkTransport(timeout));
        } finally {
            Arrays.fill(webhookSecret, (byte) 0);
        }
        StripeProviderBridge bridge = new StripeProviderBridge(new StripeProviderBridge.Runtime(
                adapter,
                request -> {
                    String providerObjectId = ProviderWebhookLookupKeys.stripeProviderObject(
                            request.rawBody());
                    ProviderRuntimeLookup.PaymentFacts facts = lookup.byProviderObject(
                            request.tenantId(), request.merchantAccountId(), provider(),
                            providerObjectId);
                    return new StripeAdapter.ExpectedWebhook(facts.providerObjectId(),
                            facts.amountMinor(), facts.currency(), facts.businessReference());
                }));
        return new ScopedProviderRuntimeAdapter(bridge, adapter::close);
    }

    private static void requireAccount(ProviderAccount account) {
        Objects.requireNonNull(account, "account");
        if (!"stripe".equals(account.provider())) {
            throw new SecurityException("Stripe factory received a different provider account");
        }
    }

    private static URI requireHttpsBase(URI value) {
        Objects.requireNonNull(value, "approvedReturnBase");
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getQuery() != null
                || value.getFragment() != null || !value.getPath().endsWith("/")) {
            throw new IllegalArgumentException("Stripe return base must be an HTTPS directory");
        }
        return value;
    }
}
