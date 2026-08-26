package com.elmpay.connectors.wechatpay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderRequestContext;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

final class WechatPayAdapterTest {
    private static final Instant NOW = Instant.parse("2026-08-26T00:00:00Z");
    private static final byte[] API_V3_KEY = "0123456789abcdef0123456789abcdef"
            .getBytes(StandardCharsets.UTF_8);
    private static KeyPair merchantKeys;
    private static KeyPair platformKeys;
    private static KeyPair nextPlatformKeys;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        merchantKeys = generator.generateKeyPair();
        platformKeys = generator.generateKeyPair();
        nextPlatformKeys = generator.generateKeyPair();
    }

    @Test
    void verifiesRsaThenDecryptsAndBindsEveryCriticalField() throws Exception {
        WechatPayAdapter adapter = adapter(request -> new WechatPayAdapter.HttpResult(200, "{}".getBytes(StandardCharsets.UTF_8)));
        Fixture fixture = fixture(platformKeys.getPrivate(), "serial-old", 1250, "merchant-001");

        WechatPayAdapter.VerifiedWebhook event = adapter.verifyWebhook(fixture.headers(), fixture.body(), NOW,
                new WechatPayAdapter.ExpectedWebhook("merchant-001", "wx-app-001", "order_123456",
                        "tx_123456", 1250, "CNY"));

        assertEquals("event-001", event.eventId());
        assertEquals("tx_123456", event.transactionId());
        assertTrue(new String(event.canonicalPayload(), StandardCharsets.UTF_8).contains("\"amount_minor\":1250"));
    }

    @Test
    void rejectsWrongSignatureAndAmountOrMerchantTampering() throws Exception {
        WechatPayAdapter adapter = adapter(request -> new WechatPayAdapter.HttpResult(200, new byte[0]));
        Fixture signedByUnknownKey = fixture(nextPlatformKeys.getPrivate(), "serial-old", 1250, "merchant-001");
        assertThrows(SecurityException.class, () -> adapter.verifyWebhook(signedByUnknownKey.headers(),
                signedByUnknownKey.body(), NOW, expected(1250, "merchant-001")));

        Fixture valid = fixture(platformKeys.getPrivate(), "serial-old", 1250, "merchant-001");
        assertThrows(SecurityException.class,
                () -> adapter.verifyWebhook(valid.headers(), valid.body(), NOW, expected(1251, "merchant-001")));
        assertThrows(SecurityException.class,
                () -> adapter.verifyWebhook(valid.headers(), valid.body(), NOW, expected(1250, "merchant-999")));
    }

    @Test
    void enforcesOverlappingPlatformKeyRotation() {
        WechatPayAdapter adapter = adapter(request -> new WechatPayAdapter.HttpResult(200, new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> adapter.rotatePlatformKeys(Map.of("serial-new", nextPlatformKeys.getPublic())));
        adapter.rotatePlatformKeys(Map.of("serial-old", platformKeys.getPublic(),
                "serial-new", nextPlatformKeys.getPublic()));
        adapter.rotatePlatformKeys(Map.of("serial-new", nextPlatformKeys.getPublic()));
    }

    @Test
    void retriesOnlyAFiniteNumberAndReturnsUnknownWithStableIdempotencyHeader() {
        AtomicInteger calls = new AtomicInteger();
        List<String> keys = new ArrayList<>();
        WechatPayAdapter adapter = adapter(request -> {
            calls.incrementAndGet();
            keys.add(request.headers().firstValue("X-Elmpay-Idempotency-Key").orElseThrow());
            throw new IOException("synthetic timeout");
        });
        WechatPayAdapter.OperationResult result = adapter.createPayment(new WechatPayAdapter.PaymentRequest(
                "order_123456", 1250, "CNY", "fixture", WechatPayAdapter.Channel.NATIVE, null,
                "idem-wechat-00000001"));
        assertEquals(WechatPayAdapter.State.UNKNOWN, result.state());
        assertEquals(2, calls.get());
        assertEquals(List.of("idem-wechat-00000001", "idem-wechat-00000001"), keys);
    }

    @Test
    void commonBridgeDelegatesToConcreteAdapterAndMissingConfigFailsClosed() {
        WechatProviderBridge bridge = new WechatProviderBridge(new WechatProviderBridge.Runtime(
                adapter(request -> new WechatPayAdapter.HttpResult(200,
                        "{\"code_url\":\"weixin://fixture\"}".getBytes(StandardCharsets.UTF_8))),
                command -> 1250, request -> expected(1250, "merchant-001")));
        assertTrue(bridge.configured());
        assertEquals(ProviderOutcome.REQUIRES_ACTION, bridge.createPayment(command()).outcome());

        String previous = System.getProperty("elmpay.wechat.adapterFactory");
        System.clearProperty("elmpay.wechat.adapterFactory");
        try {
            WechatProviderBridge missing = new WechatProviderBridge();
            assertFalse(missing.configured());
            assertThrows(ProviderException.class, () -> missing.createPayment(command()));
        } finally {
            restore("elmpay.wechat.adapterFactory", previous);
        }
    }

    private static CreatePaymentCommand command() {
        ProviderRequestContext context = new ProviderRequestContext(
                UUID.fromString("10000000-0000-0000-0000-000000000001"),
                UUID.fromString("10000000-0000-0000-0000-000000000002"),
                UUID.fromString("10000000-0000-0000-0000-000000000003"),
                "idem-wechat-00000001", "corr-wechat", "cred-v1");
        return new CreatePaymentCommand(context,
                UUID.fromString("10000000-0000-0000-0000-000000000004"), "order_123456",
                Money.of(1250, "CNY"), "wechat_native", null, Map.of("description", "fixture"));
    }

    private static void restore(String name, String value) {
        if (value == null) System.clearProperty(name); else System.setProperty(name, value);
    }

    private static WechatPayAdapter adapter(WechatPayAdapter.Transport transport) {
        return new WechatPayAdapter(new WechatPayAdapter.Config(
                URI.create("https://api.mch.weixin.qq.com"), URI.create("https://pay.example.test/wechat"),
                "merchant-001", "wx-app-001", "merchant-serial", merchantKeys.getPrivate(), API_V3_KEY,
                Map.of("serial-old", platformKeys.getPublic()), Duration.ofSeconds(2), Duration.ofMinutes(5),
                2, Clock.fixed(NOW, ZoneOffset.UTC)), transport);
    }

    private static WechatPayAdapter.ExpectedWebhook expected(long amount, String merchantId) {
        return new WechatPayAdapter.ExpectedWebhook(merchantId, "wx-app-001", "order_123456",
                "tx_123456", amount, "CNY");
    }

    private static Fixture fixture(PrivateKey signingKey, String serial, long amount, String merchantId)
            throws Exception {
        String resource = "{\"mchid\":\"" + merchantId + "\",\"appid\":\"wx-app-001\","
                + "\"out_trade_no\":\"order_123456\",\"transaction_id\":\"tx_123456\","
                + "\"trade_state\":\"SUCCESS\",\"amount\":{\"total\":" + amount
                + ",\"currency\":\"CNY\"}}";
        String nonce = "0123456789ab";
        String associatedData = "transaction";
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(API_V3_KEY, "AES"),
                new GCMParameterSpec(128, nonce.getBytes(StandardCharsets.UTF_8)));
        cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
        String ciphertext = Base64.getEncoder().encodeToString(
                cipher.doFinal(resource.getBytes(StandardCharsets.UTF_8)));
        String body = "{\"id\":\"event-001\",\"event_type\":\"TRANSACTION.SUCCESS\","
                + "\"resource\":{\"ciphertext\":\"" + ciphertext + "\",\"nonce\":\"" + nonce
                + "\",\"associated_data\":\"" + associatedData + "\"}}";
        String timestamp = Long.toString(NOW.getEpochSecond());
        String webhookNonce = "notification-nonce";
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signingKey);
        signature.update((timestamp + "\n" + webhookNonce + "\n" + body + "\n")
                .getBytes(StandardCharsets.UTF_8));
        Map<String, String> headers = Map.of(
                "Wechatpay-Timestamp", timestamp,
                "Wechatpay-Nonce", webhookNonce,
                "Wechatpay-Serial", serial,
                "Wechatpay-Signature", Base64.getEncoder().encodeToString(signature.sign()));
        return new Fixture(headers, body.getBytes(StandardCharsets.UTF_8));
    }

    private record Fixture(Map<String, String> headers, byte[] body) {
        private Fixture {
            body = body.clone();
        }
    }
}
