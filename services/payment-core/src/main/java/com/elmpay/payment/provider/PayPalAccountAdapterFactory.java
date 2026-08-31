package com.elmpay.payment.provider;

import com.elmpay.connectors.paypal.PayPalAdapter;
import com.elmpay.connectors.paypal.PayPalProviderBridge;
import com.elmpay.merchant.ProviderAccount;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/** Account-bound PayPal Orders v2 runtime using official remote webhook verification. */
public final class PayPalAccountAdapterFactory implements ProviderAccountAdapterFactory {
    private final ProviderRuntimeLookup lookup;
    private final URI approvedCheckoutBase;
    private final Set<String> certificateHosts;
    private final Duration timeout;
    private final int attempts;
    private final Clock clock;

    public PayPalAccountAdapterFactory(ProviderRuntimeLookup lookup, URI approvedCheckoutBase,
            Set<String> certificateHosts, Duration timeout, int attempts, Clock clock) {
        this.lookup = Objects.requireNonNull(lookup, "lookup");
        this.approvedCheckoutBase = requireHttpsBase(approvedCheckoutBase);
        Objects.requireNonNull(certificateHosts, "certificateHosts");
        this.certificateHosts = certificateHosts.stream().map(host -> host.toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        if (this.certificateHosts.isEmpty()
                || this.certificateHosts.stream().anyMatch(host ->
                        !host.matches("[a-z0-9.-]{3,253}"))) {
            throw new IllegalArgumentException("PayPal certificate hosts are invalid");
        }
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.attempts = attempts;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String provider() {
        return "paypal";
    }

    @Override
    public ProviderRuntimeAdapter create(ProviderAccount account, ProviderCredential credential) {
        requireAccount(account);
        SecretMaterialProviderCredential material = ProviderCredentialMaterial.require(credential);
        ProviderCredentialMaterial.requireAccountBinding(material, account.providerMerchantId());
        String webhookId = ProviderCredentialMaterial.text(material, "webhook_id", 256);
        PayPalAdapter.CredentialProvider credentials = () -> new PayPalAdapter.ClientCredentials(
                ProviderCredentialMaterial.text(material, "client_id", 512),
                ProviderCredentialMaterial.text(material, "client_secret", 8_192));
        URI apiBase = "sandbox".equals(account.environment())
                ? URI.create("https://api-m.sandbox.paypal.com/")
                : URI.create("https://api-m.paypal.com/");
        PayPalAdapter adapter = new PayPalAdapter(new PayPalAdapter.Config(apiBase,
                approvedCheckoutBase, webhookId, certificateHosts, credentials, timeout, attempts,
                clock), new PayPalAdapter.JdkTransport(timeout));
        PayPalProviderBridge bridge = new PayPalProviderBridge(new PayPalProviderBridge.Runtime(
                adapter,
                request -> {
                    String providerObjectId = ProviderWebhookLookupKeys.payPalProviderObject(
                            request.rawBody());
                    ProviderRuntimeLookup.PaymentFacts facts = lookup.byProviderObject(
                            request.tenantId(), request.merchantAccountId(), provider(),
                            providerObjectId);
                    int exponent = com.elmpay.money.CurrencyCatalog.require(
                            facts.currency()).fractionDigits();
                    return new PayPalAdapter.ExpectedWebhook(facts.providerObjectId(),
                            account.providerMerchantId(), facts.amountMinor(), facts.currency(),
                            exponent, facts.businessReference());
                }));
        return new ScopedProviderRuntimeAdapter(bridge, adapter::close);
    }

    private static void requireAccount(ProviderAccount account) {
        Objects.requireNonNull(account, "account");
        if (!"paypal".equals(account.provider())) {
            throw new SecurityException("PayPal factory received a different provider account");
        }
    }

    private static URI requireHttpsBase(URI value) {
        Objects.requireNonNull(value, "approvedCheckoutBase");
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getQuery() != null
                || value.getFragment() != null || !value.getPath().endsWith("/")) {
            throw new IllegalArgumentException("PayPal checkout base must be an HTTPS directory");
        }
        return value;
    }
}
