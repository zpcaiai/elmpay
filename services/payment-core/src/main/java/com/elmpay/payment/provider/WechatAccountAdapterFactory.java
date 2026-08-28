package com.elmpay.payment.provider;

import com.elmpay.connectors.wechatpay.WechatPayAdapter;
import com.elmpay.connectors.wechatpay.WechatProviderBridge;
import com.elmpay.merchant.ProviderAccount;
import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

/** Builds one account-bound WeChat APIv3 runtime from a short-lived KMS/Vault lease. */
public final class WechatAccountAdapterFactory implements ProviderAccountAdapterFactory {
    private final ProviderRuntimeLookup lookup;
    private final URI notifyUri;
    private final Duration timeout;
    private final Duration webhookTolerance;
    private final int attempts;
    private final Clock clock;

    public WechatAccountAdapterFactory(ProviderRuntimeLookup lookup, URI notifyUri,
            Duration timeout, Duration webhookTolerance, int attempts, Clock clock) {
        this.lookup = Objects.requireNonNull(lookup, "lookup");
        this.notifyUri = requireHttps(notifyUri);
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.webhookTolerance = Objects.requireNonNull(webhookTolerance, "webhookTolerance");
        this.attempts = attempts;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public String provider() {
        return "wechat";
    }

    @Override
    public ProviderRuntimeAdapter create(ProviderAccount account, ProviderCredential credential) {
        requireAccount(account);
        SecretMaterialProviderCredential material = ProviderCredentialMaterial.require(credential);
        ProviderCredentialMaterial.requireAccountBinding(material, account.providerMerchantId());
        String appId = ProviderCredentialMaterial.text(material, "app_id", 128);
        String merchantSerial = ProviderCredentialMaterial.text(material, "merchant_serial", 128);
        String platformSerial = ProviderCredentialMaterial.text(material, "platform_serial", 128);
        PrivateKey credentialSigningMaterial = ProviderCredentialMaterial.rsaPrivateKey(material,
                "merchant_private_key_pkcs8");
        PublicKey platformKey = ProviderCredentialMaterial.rsaPublicKey(material,
                "platform_public_key_x509");
        byte[] apiV3CredentialMaterial = ProviderCredentialMaterial.bytes(
                material, "api_v3_key", 32, 32);
        WechatPayAdapter adapter;
        try {
            URI apiBase = URI.create("https://api.mch.weixin.qq.com/");
            adapter = new WechatPayAdapter(new WechatPayAdapter.Config(apiBase, notifyUri,
                    account.providerMerchantId(), appId, merchantSerial, credentialSigningMaterial,
                    apiV3CredentialMaterial,
                    Map.of(platformSerial, platformKey), timeout, webhookTolerance, attempts, clock),
                    new WechatPayAdapter.JdkTransport(timeout));
        } finally {
            Arrays.fill(apiV3CredentialMaterial, (byte) 0);
        }
        WechatProviderBridge bridge = new WechatProviderBridge(new WechatProviderBridge.Runtime(
                adapter,
                command -> lookup.originalAmountMinor(command, provider()),
                (request, identity) -> {
                    ProviderRuntimeLookup.PaymentFacts facts = lookup.byBusinessReference(
                            request.tenantId(), request.merchantAccountId(), provider(),
                            identity.outTradeNo());
                    return new WechatPayAdapter.ExpectedWebhook(account.providerMerchantId(), appId,
                            facts.businessReference(), facts.providerObjectId(), facts.amountMinor(),
                            facts.currency());
                }));
        return new ScopedProviderRuntimeAdapter(bridge, adapter::close);
    }

    private static void requireAccount(ProviderAccount account) {
        Objects.requireNonNull(account, "account");
        if (!"wechat".equals(account.provider())) {
            throw new SecurityException("WeChat factory received a different provider account");
        }
    }

    private static URI requireHttps(URI value) {
        Objects.requireNonNull(value, "notifyUri");
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getFragment() != null) {
            throw new IllegalArgumentException("WeChat notify URI must be HTTPS");
        }
        return value;
    }
}
