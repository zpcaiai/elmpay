package com.elmpay.payment.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.connectors.applepay.ApplePayAdapter;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class HttpsApplePayPspTokenProcessorTest {
    private static final HttpHeaders JSON_HEADERS = HttpHeaders.of(
            Map.of("Content-Type", java.util.List.of("application/json")),
            (name, value) -> true);
    @Test
    void forwardsOnlyToBoundPspAndWipesSerializedTokenBody() {
        Map<String, byte[]> fields = new LinkedHashMap<>();
        fields.put("psp_broker_access_token", "short-lived-token".getBytes(StandardCharsets.UTF_8));
        SecretMaterialProviderCredential credential = new SecretMaterialProviderCredential(
                "v1", "lease-1", Instant.now().plusSeconds(60), fields, () -> { });
        RecordingTransport transport = new RecordingTransport();
        HttpsApplePayPspTokenProcessor processor = new HttpsApplePayPspTokenProcessor(
                URI.create("https://psp-broker.internal.example/"), credential,
                ApplePayAdapter.Psp.STRIPE, transport, Duration.ofSeconds(2));
        ApplePayAdapter.PspRequest request = new ApplePayAdapter.PspRequest("tenant-001",
                "account-001", 1250, "USD",
                "{\"data\":\"opaque\"}".getBytes(StandardCharsets.UTF_8),
                "idem-applepay-00000001");

        ApplePayAdapter.Result result = processor.process(ApplePayAdapter.Psp.STRIPE, request);

        assertEquals("pi_synthetic01", result.providerPaymentId());
        assertEquals("PROCESSING", result.state());
        assertEquals("Bearer short-lived-token", transport.headers.get("Authorization"));
        assertTrue(allZero(transport.body));
        assertThrows(IllegalStateException.class, transport.response::body);
        assertThrows(SecurityException.class,
                () -> processor.process(ApplePayAdapter.Psp.PAYPAL, request));
        credential.close();
    }

    @Test
    void invalidUtf8ResponseAndUnvalidatedDirectRequestFailClosed() {
        Map<String, byte[]> fields = new LinkedHashMap<>();
        fields.put("psp_broker_access_token",
                "short-lived-token".getBytes(StandardCharsets.UTF_8));
        SecretMaterialProviderCredential credential = new SecretMaterialProviderCredential(
                "v1", "lease-1", Instant.now().plusSeconds(60), fields, () -> { });
        RecordingTransport transport = new RecordingTransport(new byte[] {
                '{', '"', 'p', 'r', 'o', 'v', 'i', 'd', 'e', 'r', '_', 'p', 'a', 'y',
                'm', 'e', 'n', 't', '_', 'i', 'd', '"', ':', '"', (byte) 0xc3,
                (byte) 0x28, '"', '}'});
        HttpsApplePayPspTokenProcessor processor = new HttpsApplePayPspTokenProcessor(
                URI.create("https://psp-broker.internal.example/"), credential,
                ApplePayAdapter.Psp.STRIPE, transport, Duration.ofSeconds(2));
        ApplePayAdapter.PspRequest request = new ApplePayAdapter.PspRequest("tenant-001",
                "account-001", 1250, "USD", new byte[16],
                "idem-applepay-00000001");
        assertThrows(SecurityException.class,
                () -> processor.process(ApplePayAdapter.Psp.STRIPE, request));
        assertTrue(allZero(transport.body));
        assertThrows(IllegalStateException.class, transport.response::body);

        ApplePayAdapter.PspRequest injected = new ApplePayAdapter.PspRequest("tenant\"x",
                "account-001", 1250, "USD", new byte[] {1, 2, 3, 4},
                "idem-applepay-00000001");
        assertThrows(SecurityException.class,
                () -> processor.process(ApplePayAdapter.Psp.STRIPE, injected));

        RecordingTransport wrongType = new RecordingTransport();
        wrongType.responseHeaders = HttpHeaders.of(
                Map.of("Content-Type", java.util.List.of("text/plain")),
                (name, value) -> true);
        HttpsApplePayPspTokenProcessor wrongTypeProcessor =
                new HttpsApplePayPspTokenProcessor(
                        URI.create("https://psp-broker.internal.example/"), credential,
                        ApplePayAdapter.Psp.STRIPE, wrongType, Duration.ofSeconds(2));
        assertThrows(SecurityException.class,
                () -> wrongTypeProcessor.process(ApplePayAdapter.Psp.STRIPE, request));
        assertTrue(allZero(wrongType.body));
        assertThrows(IllegalStateException.class, wrongType.response::body);
        credential.close();
    }

    private static boolean allZero(byte[] value) {
        for (byte item : value) {
            if (item != 0) {
                return false;
            }
        }
        return true;
    }

    private static final class RecordingTransport
            implements HttpsApplePayPspTokenProcessor.Transport {
        private final byte[] responseBody;
        private byte[] body;
        private Map<String, String> headers;
        private HttpsApplePayPspTokenProcessor.Response response;
        private HttpHeaders responseHeaders = JSON_HEADERS;

        private RecordingTransport() {
            this("{\"provider_payment_id\":\"pi_synthetic01\",\"state\":\"PROCESSING\",\"final\":false}"
                    .getBytes(StandardCharsets.UTF_8));
        }

        private RecordingTransport(byte[] responseBody) {
            this.responseBody = responseBody.clone();
        }

        @Override
        public HttpsApplePayPspTokenProcessor.Response post(URI endpoint,
                Map<String, String> requestHeaders, byte[] requestBody, Duration timeout) {
            body = requestBody;
            headers = requestHeaders;
            response = new HttpsApplePayPspTokenProcessor.Response(
                    200, responseHeaders, responseBody);
            return response;
        }
    }
}
