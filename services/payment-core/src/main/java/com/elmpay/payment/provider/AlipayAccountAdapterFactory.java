package com.elmpay.payment.provider;

import com.elmpay.connectors.alipay.AlipayAdapter;
import com.elmpay.connectors.alipay.AlipayProviderBridge;
import com.elmpay.merchant.ProviderAccount;
import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Account-bound Alipay certificate-mode runtime with server-owned callback expectations. */
public final class AlipayAccountAdapterFactory implements ProviderAccountAdapterFactory {
    private final ProviderRuntimeLookup lookup;
    private final ApprovedReturnRouteRegistry returnRoutes;
    private final URI notifyUri;
    private final Duration timeout;
    private final int attempts;
    private final Clock clock;

    public AlipayAccountAdapterFactory(ProviderRuntimeLookup lookup,
            ApprovedReturnRouteRegistry returnRoutes, URI notifyUri, Duration timeout,
            int attempts, Clock clock) {
        this.lookup = Objects.requireNonNull(lookup, "lookup");
        this.returnRoutes = Objects.requireNonNull(returnRoutes, "returnRoutes");
        this.notifyUri = requireHttps(notifyUri);
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.attempts = attempts;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String provider() {
        return "alipay";
    }

    @Override
    public ProviderRuntimeAdapter create(ProviderAccount account, ProviderCredential credential) {
        requireAccount(account);
        SecretMaterialProviderCredential material = ProviderCredentialMaterial.require(credential);
        ProviderCredentialMaterial.requireAccountBinding(material, account.providerMerchantId());
        String appId = ProviderCredentialMaterial.text(material, "app_id", 128);
        String appCertificateSerial = ProviderCredentialMaterial.text(material,
                "app_certificate_serial", 256);
        String rootCertificateSerial = ProviderCredentialMaterial.text(material,
                "root_certificate_serial", 1_024);
        String alipayCertificateSerial = ProviderCredentialMaterial.text(material,
                "alipay_certificate_serial", 256);
        PrivateKey credentialSigningMaterial = ProviderCredentialMaterial.rsaPrivateKey(material,
                "app_private_key_pkcs8");
        PublicKey publicKey = ProviderCredentialMaterial.rsaPublicKey(material,
                "alipay_public_key_x509");
        Instant now = clock.instant();
        AlipayAdapter.VerificationKey verificationKey = new AlipayAdapter.VerificationKey(
                alipayCertificateSerial, publicKey, now.minusSeconds(60), material.expiresAt());
        URI gateway = "sandbox".equals(account.environment())
                ? URI.create("https://openapi-sandbox.dl.alipaydev.com/gateway.do")
                : URI.create("https://openapi.alipay.com/gateway.do");
        AlipayAdapter adapter = new AlipayAdapter(new AlipayAdapter.Config(gateway, notifyUri,
                returnRoutes.hosts(), appId, account.providerMerchantId(), appCertificateSerial,
                rootCertificateSerial, credentialSigningMaterial, List.of(verificationKey), timeout, attempts,
                clock), new AlipayAdapter.JdkTransport(timeout));
        AlipayProviderBridge bridge = new AlipayProviderBridge(new AlipayProviderBridge.Runtime(
                adapter, returnRoutes::resolve,
                request -> {
                    String reference = ProviderWebhookLookupKeys.alipayBusinessReference(
                            request.rawBody());
                    ProviderRuntimeLookup.PaymentFacts facts = lookup.byBusinessReference(
                            request.tenantId(), request.merchantAccountId(), provider(), reference);
                    return new AlipayAdapter.ExpectedNotify(appId, account.providerMerchantId(),
                            facts.businessReference(), facts.amountMinor(), facts.currency());
                },
                (providerRefundId, refundReference) -> lookup.refundBusinessReference(
                        account.tenantId(), account.id(), provider(), providerRefundId,
                        refundReference)));
        return new ScopedProviderRuntimeAdapter(bridge, adapter::close);
    }

    private static void requireAccount(ProviderAccount account) {
        Objects.requireNonNull(account, "account");
        if (!"alipay".equals(account.provider())) {
            throw new SecurityException("Alipay factory received a different provider account");
        }
    }

    private static URI requireHttps(URI value) {
        Objects.requireNonNull(value, "notifyUri");
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getFragment() != null) {
            throw new IllegalArgumentException("Alipay notify URI must be HTTPS");
        }
        return value;
    }
}
