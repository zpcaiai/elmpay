package com.elmpay.connectors.alipay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderRequestContext;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

final class AlipayAdapterTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");
    private static KeyPair appKeys;
    private static KeyPair alipayKeys;
    private static KeyPair nextAlipayKeys;

    @Test
    void transportResponseIsDefensiveWipeableAndRejectsUseAfterClose() {
        byte[] supplied = {1, 2, 3};
        AlipayAdapter.HttpResult response = new AlipayAdapter.HttpResult(200, supplied);
        supplied[0] = 9;
        assertEquals(1, response.body()[0]);
        assertEquals(3, response.bodyLength());
        response.close();
        response.close();
        assertThrows(IllegalStateException.class, response::body);
        assertThrows(IllegalStateException.class, response::bodyLength);
    }

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        appKeys = generator.generateKeyPair();
        alipayKeys = generator.generateKeyPair();
        nextAlipayKeys = generator.generateKeyPair();
    }

    @Test
    void verifiesCanonicalRsa2FormRegardlessOfParameterOrder() throws Exception {
        AlipayAdapter adapter = adapter(request -> new AlipayAdapter.HttpResult(200, "{}".getBytes(StandardCharsets.UTF_8)));
        byte[] body = signedNotify(alipayKeys.getPrivate(), "cert-old", "10.25", "seller-001");

        AlipayAdapter.VerifiedNotify result = adapter.verifyNotify(body, NOW,
                new AlipayAdapter.ExpectedNotify("app-001", "seller-001", "order_123456", 1025, "CNY"));

        assertEquals("TRADE_SUCCESS", result.tradeStatus());
        assertEquals(1025, result.amountMinor());
    }

    @Test
    void rejectsAmountMerchantAndSignatureTampering() throws Exception {
        AlipayAdapter adapter = adapter(request -> new AlipayAdapter.HttpResult(200, new byte[0]));
        byte[] body = signedNotify(alipayKeys.getPrivate(), "cert-old", "10.25", "seller-001");
        assertThrows(SecurityException.class, () -> adapter.verifyNotify(body, NOW,
                new AlipayAdapter.ExpectedNotify("app-001", "seller-001", "order_123456", 1026, "CNY")));

        byte[] badMerchant = signedNotify(alipayKeys.getPrivate(), "cert-old", "10.25", "seller-999");
        assertThrows(SecurityException.class, () -> adapter.verifyNotify(badMerchant, NOW,
                new AlipayAdapter.ExpectedNotify("app-001", "seller-001", "order_123456", 1025, "CNY")));

        byte[] wrongKey = signedNotify(nextAlipayKeys.getPrivate(), "cert-old", "10.25", "seller-001");
        assertThrows(SecurityException.class, () -> adapter.verifyNotify(wrongKey, NOW,
                new AlipayAdapter.ExpectedNotify("app-001", "seller-001", "order_123456", 1025, "CNY")));
    }

    @Test
    void blocksOpenRedirectAndRequiresOverlappingCertificateRotation() {
        AlipayAdapter adapter = adapter(request -> new AlipayAdapter.HttpResult(200, "{}".getBytes(StandardCharsets.UTF_8)));
        AlipayAdapter.PaymentRequest request = new AlipayAdapter.PaymentRequest("order_123456", 1025, "CNY",
                "fixture", AlipayAdapter.Channel.WEB, null, "idem-alipay-00000001");
        assertThrows(IllegalArgumentException.class,
                () -> adapter.createOrder(request, URI.create("https://attacker.example/return")));

        AlipayAdapter.VerificationKey next = new AlipayAdapter.VerificationKey("cert-new",
                nextAlipayKeys.getPublic(), NOW.minusSeconds(60), NOW.plusSeconds(600));
        assertThrows(IllegalArgumentException.class, () -> adapter.rotateVerificationKeys(List.of(next)));
        AlipayAdapter.VerificationKey old = activeOldKey();
        adapter.rotateVerificationKeys(List.of(old, next));
        adapter.rotateVerificationKeys(List.of(next));
    }

    @Test
    void returnsUnknownAfterFiniteTimeoutRetriesWithStableHeader() {
        AtomicInteger calls = new AtomicInteger();
        List<String> keys = new ArrayList<>();
        AlipayAdapter adapter = adapter(request -> {
            calls.incrementAndGet();
            keys.add(request.headers().firstValue("X-Elmpay-Idempotency-Key").orElseThrow());
            throw new IOException("synthetic timeout");
        });
        AlipayAdapter.OperationResult result = adapter.createOrder(new AlipayAdapter.PaymentRequest(
                "order_123456", 1025, "CNY", "fixture", AlipayAdapter.Channel.APP, null,
                "idem-alipay-00000001"), null);
        assertEquals(AlipayAdapter.State.UNKNOWN, result.state());
        assertEquals(2, calls.get());
        assertEquals(List.of("idem-alipay-00000001", "idem-alipay-00000001"), keys);
    }

    @Test
    void rejectsForgedSuccessfulSynchronousResponse() throws Exception {
        AlipayAdapter.HttpResult forged = signedResponse("alipay.trade.app.pay",
                "{\"code\":\"10000\",\"trade_no\":\"trade_forged\"}",
                "{\"code\":\"10000\",\"trade_no\":\"trade_trusted\"}",
                alipayKeys.getPrivate());
        AlipayAdapter.OperationResult result = adapter(request -> forged).createOrder(
                new AlipayAdapter.PaymentRequest("order_123456", 1025, "CNY", "fixture",
                        AlipayAdapter.Channel.APP, null, "idem-alipay-00000001"), null);
        assertEquals(AlipayAdapter.State.UNKNOWN, result.state());
        assertFalse(result.finalState());
        assertEquals("", result.providerReference());
    }

    @Test
    void duplicateSignedBusinessFieldsFailToUnknown() throws Exception {
        String duplicate = "{\"code\":\"10000\",\"code\":\"40004\","
                + "\"trade_no\":\"trade_123456\"}";
        AlipayAdapter.HttpResult response = signedResponse("alipay.trade.app.pay", duplicate,
                null, alipayKeys.getPrivate());

        AlipayAdapter.OperationResult result = adapter(request -> response).createOrder(
                new AlipayAdapter.PaymentRequest("order_123456", 1025, "CNY", "fixture",
                        AlipayAdapter.Channel.APP, null, "idem-alipay-00000001"), null);

        assertEquals(AlipayAdapter.State.UNKNOWN, result.state());
        assertFalse(result.finalState());
    }

    @Test
    void commonBridgeDelegatesToConcreteAdapterAndMissingConfigFailsClosed() throws Exception {
        AlipayAdapter.HttpResult response = signedResponse("alipay.trade.app.pay",
                "{\"code\":\"10000\",\"trade_no\":\"trade_123456\"}", null,
                alipayKeys.getPrivate());
        AlipayProviderBridge bridge = new AlipayProviderBridge(new AlipayProviderBridge.Runtime(
                adapter(request -> response),
                route -> URI.create("https://pay.example.test/alipay/return"),
                request -> new AlipayAdapter.ExpectedNotify("app-001", "seller-001", "order_123456",
                        1025, "CNY"),
                (providerRefundId, refundReference) -> "order_123456"));
        assertEquals(true, bridge.configured());
        assertEquals(ProviderOutcome.REQUIRES_ACTION, bridge.createPayment(command()).outcome());

        String previous = System.getProperty("elmpay.alipay.adapterFactory");
        System.clearProperty("elmpay.alipay.adapterFactory");
        try {
            AlipayProviderBridge missing = new AlipayProviderBridge();
            assertFalse(missing.configured());
            assertThrows(ProviderException.class, () -> missing.createPayment(command()));
        } finally {
            restore("elmpay.alipay.adapterFactory", previous);
        }
    }

    private static CreatePaymentCommand command() {
        ProviderRequestContext context = new ProviderRequestContext(
                UUID.fromString("20000000-0000-0000-0000-000000000001"),
                UUID.fromString("20000000-0000-0000-0000-000000000002"),
                UUID.fromString("20000000-0000-0000-0000-000000000003"),
                "idem-alipay-00000001", "corr-alipay", "cred-v1");
        return new CreatePaymentCommand(context,
                UUID.fromString("20000000-0000-0000-0000-000000000004"), "order_123456",
                Money.of(1025, "CNY"), "alipay_app", null, Map.of("subject", "fixture"));
    }

    private static void restore(String name, String value) {
        if (value == null) System.clearProperty(name); else System.setProperty(name, value);
    }

    private static AlipayAdapter adapter(AlipayAdapter.Transport transport) {
        AlipayAdapter.Config config = new AlipayAdapter.Config(URI.create("https://openapi.alipay.com/gateway.do"),
                URI.create("https://pay.example.test/alipay"), Set.of("pay.example.test"), "app-001",
                "seller-001", "app-cert", "root-cert", appKeys.getPrivate(), List.of(activeOldKey()),
                Duration.ofSeconds(2), 2, Clock.fixed(NOW, ZoneOffset.UTC));
        return new AlipayAdapter(config, transport);
    }

    private static AlipayAdapter.VerificationKey activeOldKey() {
        return new AlipayAdapter.VerificationKey("cert-old", alipayKeys.getPublic(),
                NOW.minusSeconds(600), NOW.plusSeconds(600));
    }

    private static byte[] signedNotify(PrivateKey key, String certificateSerial, String amount,
            String sellerId) throws Exception {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("trade_status", "TRADE_SUCCESS");
        values.put("notify_id", "notify-001");
        values.put("total_amount", amount);
        values.put("trade_no", "trade_123456");
        values.put("out_trade_no", "order_123456");
        values.put("seller_id", sellerId);
        values.put("app_id", "app-001");
        values.put("alipay_cert_sn", certificateSerial);
        values.put("sign_type", "RSA2");
        String canonical = values.entrySet().stream()
                .filter(entry -> !entry.getKey().equals("sign_type"))
                .sorted(Comparator.comparing(Map.Entry::getKey))
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(java.util.stream.Collectors.joining("&"));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(canonical.getBytes(StandardCharsets.UTF_8));
        values.put("sign", Base64.getEncoder().encodeToString(signer.sign()));
        List<Map.Entry<String, String>> shuffled = new ArrayList<>(values.entrySet());
        java.util.Collections.reverse(shuffled);
        String form = shuffled.stream().map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .collect(java.util.stream.Collectors.joining("&"));
        return form.getBytes(StandardCharsets.UTF_8);
    }

    private static AlipayAdapter.HttpResult signedResponse(String method, String body,
            String signedBodyOverride, PrivateKey key) throws Exception {
        String signedBody = signedBodyOverride == null ? body : signedBodyOverride;
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(signedBody.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getEncoder().encodeToString(signer.sign());
        String responseName = method.replace('.', '_') + "_response";
        String response = "{\"" + responseName + "\":" + body + ",\"sign\":\""
                + signature + "\",\"alipay_cert_sn\":\"cert-old\"}";
        return new AlipayAdapter.HttpResult(200, response.getBytes(StandardCharsets.UTF_8));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
