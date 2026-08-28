package com.elmpay.payment.provider;

import com.elmpay.connectors.applepay.ApplePayAdapter;
import com.elmpay.connectors.applepay.ApplePayProviderBridge;
import com.elmpay.connectors.applepay.DataSourceApplePayLifecycle;
import com.elmpay.merchant.ProviderAccount;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import javax.net.ssl.SSLContext;
import javax.sql.DataSource;

/** Durable Apple Pay domain/certificate/token policy with delegated PSP token forwarding. */
public final class ApplePayAccountAdapterFactory implements ProviderAccountAdapterFactory {
    private final DataSourceApplePayLifecycle lifecycle;
    private final URI pspEndpoint;
    private final SSLContext mutualTlsContext;
    private final Duration timeout;
    private final Clock clock;

    public ApplePayAccountAdapterFactory(DataSource dataSource, URI pspEndpoint,
            SSLContext mutualTlsContext, Duration timeout, Clock clock) {
        lifecycle = new DataSourceApplePayLifecycle(Objects.requireNonNull(dataSource, "dataSource"));
        this.pspEndpoint = Objects.requireNonNull(pspEndpoint, "pspEndpoint");
        this.mutualTlsContext = Objects.requireNonNull(mutualTlsContext, "mutualTlsContext");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String provider() {
        return "apple_pay";
    }

    @Override
    public ProviderRuntimeAdapter create(ProviderAccount account, ProviderCredential credential) {
        Objects.requireNonNull(account, "account");
        if (!provider().equals(account.provider())) {
            throw new SecurityException("Apple Pay factory received a different provider account");
        }
        SecretMaterialProviderCredential material = ProviderCredentialMaterial.require(credential);
        ProviderCredentialMaterial.requireAccountBinding(material, account.providerMerchantId());
        String delegated = ProviderCredentialMaterial.text(material, "delegated_psp", 32)
                .toUpperCase(Locale.ROOT);
        ApplePayAdapter.Psp psp;
        try {
            psp = ApplePayAdapter.Psp.valueOf(delegated);
        } catch (IllegalArgumentException exception) {
            throw new SecurityException("Apple Pay delegated PSP is unsupported", exception);
        }
        ApplePayAdapter adapter = new ApplePayAdapter(lifecycle,
                new HttpsApplePayPspTokenProcessor(pspEndpoint, material, psp,
                        mutualTlsContext, timeout));
        ApplePayProviderBridge bridge = new ApplePayProviderBridge(
                new ApplePayProviderBridge.Runtime(adapter, clock));
        return new ScopedProviderRuntimeAdapter(bridge);
    }
}
