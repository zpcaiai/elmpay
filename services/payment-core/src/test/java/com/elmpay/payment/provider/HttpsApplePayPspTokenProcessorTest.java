package com.elmpay.payment.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.connectors.applepay.ApplePayAdapter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class HttpsApplePayPspTokenProcessorTest {
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
        assertThrows(SecurityException.class,
                () -> processor.process(ApplePayAdapter.Psp.PAYPAL, request));
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
        private byte[] body;
        private Map<String, String> headers;

        @Override
        public HttpsApplePayPspTokenProcessor.Response post(URI endpoint,
                Map<String, String> requestHeaders, byte[] requestBody, Duration timeout) {
            body = requestBody;
            headers = requestHeaders;
            return new HttpsApplePayPspTokenProcessor.Response(200,
                    "{\"provider_payment_id\":\"pi_synthetic01\",\"state\":\"PROCESSING\",\"final\":false}"
                            .getBytes(StandardCharsets.UTF_8));
        }
    }
}
