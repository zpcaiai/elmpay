package com.elmpay.payment.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.merchant.AccountStatus;
import com.elmpay.merchant.ProviderAccount;
import com.elmpay.provider.RefundCommand;
import com.elmpay.security.SecretReference;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.net.ssl.SSLContext;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

final class ProductionProviderAccountFactoriesTest {
    private static KeyPair rsa;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        rsa = generator.generateKeyPair();
    }

    @Test
    void allFiveFactoriesBuildOnlyAccountBoundScopedRuntimes() throws Exception {
        ProviderRuntimeLookup lookup = new FixedLookup();
        ApprovedReturnRouteRegistry routes = new ApprovedReturnRouteRegistry(Map.of(
                "checkout-complete", URI.create("https://merchant.example/complete")));
        DataSource unused = unusedDataSource();
        List<FactoryCase> cases = List.of(
                new FactoryCase(new WechatAccountAdapterFactory(lookup,
                        URI.create("https://pay.example/wechat/notify"), Duration.ofSeconds(2),
                        Duration.ofMinutes(5), 2, Clock.systemUTC()), "wechat",
                        wechatMaterial()),
                new FactoryCase(new AlipayAccountAdapterFactory(lookup, routes,
                        URI.create("https://pay.example/alipay/notify"), Duration.ofSeconds(2),
                        2, Clock.systemUTC()), "alipay", alipayMaterial()),
                new FactoryCase(new StripeAccountAdapterFactory(lookup,
                        URI.create("https://pay.example/return/"), Duration.ofSeconds(2),
                        Duration.ofMinutes(5), 2, Clock.systemUTC()), "stripe",
                        stripeMaterial()),
                new FactoryCase(new PayPalAccountAdapterFactory(lookup,
                        URI.create("https://pay.example/return/"),
                        java.util.Set.of("api.paypal.com"), Duration.ofSeconds(2), 2,
                        Clock.systemUTC()), "paypal", paypalMaterial()),
                new FactoryCase(new ApplePayAccountAdapterFactory(unused,
                        URI.create("https://psp-broker.internal.example/"),
                        SSLContext.getDefault(), Duration.ofSeconds(2), Clock.systemUTC()),
                        "apple_pay", appleMaterial()));

        for (FactoryCase item : cases) {
            ProviderAccount account = account(item.provider());
            SecretMaterialProviderCredential credential = credential(account, item.material());
            ProviderRuntimeAdapter runtime = item.factory().create(account, credential);
            assertEquals(item.provider(), runtime.provider());
            assertTrue(runtime.configured());
            runtime.close();
            runtime.close();
            assertFalse(runtime.configured());
            credential.close();
            assertThrows(IllegalStateException.class,
                    () -> credential.require("provider_merchant_id"));
        }
    }

    @Test
    void credentialMerchantBindingCannotBeSubstitutedAcrossAccounts() {
        ProviderAccount account = account("stripe");
        Map<String, byte[]> wrong = stripeMaterial();
        wrong.put("provider_merchant_id", bytes("acct-other"));
        SecretMaterialProviderCredential credential = credential(account, wrong);
        StripeAccountAdapterFactory factory = new StripeAccountAdapterFactory(new FixedLookup(),
                URI.create("https://pay.example/return/"), Duration.ofSeconds(2),
                Duration.ofMinutes(5), 2, Clock.systemUTC());
        assertThrows(SecurityException.class, () -> factory.create(account, credential));
        credential.close();
    }

    @Test
    void productionAggregatorRejectsLegacyMtlsBooleanAndReturnsEveryProviderWithInjectedContext()
            throws Exception {
        Map<String, String> environment = new LinkedHashMap<>();
        environment.put("ELMPAY_CHECKOUT_RETURN_ROUTES",
                "checkout-complete=https://merchant.example/complete");
        environment.put("ELMPAY_WECHAT_NOTIFY_URI", "https://pay.example/wechat/notify");
        environment.put("ELMPAY_ALIPAY_NOTIFY_URI", "https://pay.example/alipay/notify");
        environment.put("ELMPAY_STRIPE_RETURN_BASE", "https://pay.example/stripe/");
        environment.put("ELMPAY_PAYPAL_CHECKOUT_BASE", "https://pay.example/paypal/");
        environment.put("ELMPAY_PAYPAL_CERTIFICATE_HOSTS", "api.paypal.com");
        environment.put("ELMPAY_APPLE_PAY_PSP_FORWARD_ENDPOINT",
                "https://psp-broker.internal.example/");
        assertThrows(IllegalStateException.class, () ->
                ProductionProviderAccountFactories.create(unusedDataSource(), environment,
                        Clock.systemUTC()));
        environment.put("ELMPAY_APPLE_PAY_PSP_MTLS", "true");
        assertThrows(IllegalStateException.class, () ->
                ProductionProviderAccountFactories.create(unusedDataSource(), environment,
                        Clock.systemUTC()));
        assertEquals(List.of("wechat", "alipay", "stripe", "paypal", "apple_pay"),
                ProductionProviderAccountFactories.create(unusedDataSource(), environment,
                        Clock.systemUTC(), SSLContext.getDefault()).stream()
                        .map(ProviderAccountAdapterFactory::provider)
                        .toList());
    }

    private static ProviderAccount account(String provider) {
        UUID id = UUID.randomUUID();
        return new ProviderAccount(id, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                provider, "sandbox", "acct-" + provider,
                SecretReference.parse("vault://providers/" + provider + "/" + id),
                "credential-v1", AccountStatus.ACTIVE);
    }

    private static SecretMaterialProviderCredential credential(ProviderAccount account,
            Map<String, byte[]> fields) {
        fields.putIfAbsent("provider_merchant_id", bytes(account.providerMerchantId()));
        return new SecretMaterialProviderCredential(account.credentialVersion(),
                "lease-" + account.id(), Instant.now().plusSeconds(600), fields, () -> { });
    }

    private static Map<String, byte[]> wechatMaterial() {
        Map<String, byte[]> value = new LinkedHashMap<>();
        value.put("app_id", bytes("wx-app-001"));
        value.put("merchant_serial", bytes("merchant-serial-001"));
        value.put("platform_serial", bytes("platform-serial-001"));
        value.put("merchant_private_key_pkcs8", rsa.getPrivate().getEncoded());
        value.put("platform_public_key_x509", rsa.getPublic().getEncoded());
        value.put("api_v3_key", bytes("0123456789abcdef0123456789abcdef"));
        return value;
    }

    private static Map<String, byte[]> alipayMaterial() {
        Map<String, byte[]> value = new LinkedHashMap<>();
        value.put("app_id", bytes("alipay-app-001"));
        value.put("app_certificate_serial", bytes("app-cert-001"));
        value.put("root_certificate_serial", bytes("root-cert-001"));
        value.put("alipay_certificate_serial", bytes("alipay-cert-001"));
        value.put("app_private_key_pkcs8", rsa.getPrivate().getEncoded());
        value.put("alipay_public_key_x509", rsa.getPublic().getEncoded());
        return value;
    }

    private static Map<String, byte[]> stripeMaterial() {
        Map<String, byte[]> value = new LinkedHashMap<>();
        value.put("api_key", bytes("sk_test_synthetic_only"));
        value.put("webhook_key_id", bytes("wh-key-v1"));
        value.put("webhook_secret", bytes("synthetic-webhook-secret-32-bytes"));
        return value;
    }

    private static Map<String, byte[]> paypalMaterial() {
        Map<String, byte[]> value = new LinkedHashMap<>();
        value.put("client_id", bytes("sandbox-client-id"));
        value.put("client_secret", bytes("sandbox-client-secret"));
        value.put("webhook_id", bytes("WH-sandbox-webhook"));
        return value;
    }

    private static Map<String, byte[]> appleMaterial() {
        Map<String, byte[]> value = new LinkedHashMap<>();
        value.put("delegated_psp", bytes("stripe"));
        value.put("psp_broker_access_token", bytes("synthetic-short-lived-token"));
        return value;
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static DataSource unusedDataSource() {
        return (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(),
                new Class<?>[] {DataSource.class}, (proxy, method, arguments) -> {
                    throw new AssertionError("data source must not be used while building a runtime");
                });
    }

    private record FactoryCase(ProviderAccountAdapterFactory factory, String provider,
            Map<String, byte[]> material) {
    }

    private static final class FixedLookup implements ProviderRuntimeLookup {
        @Override
        public PaymentFacts byBusinessReference(UUID tenantId, UUID providerAccountId,
                String provider, String businessReference) {
            return new PaymentFacts(businessReference, "provider-object-001", 1250, "USD");
        }

        @Override
        public PaymentFacts byProviderObject(UUID tenantId, UUID providerAccountId,
                String provider, String providerObjectId) {
            return new PaymentFacts("order-001", providerObjectId, 1250, "USD");
        }

        @Override
        public long originalAmountMinor(RefundCommand command, String provider) {
            return 1250;
        }

        @Override
        public String refundBusinessReference(UUID tenantId, UUID providerAccountId,
                String provider, String providerRefundId, String refundReference) {
            return "order-001";
        }
    }
}
