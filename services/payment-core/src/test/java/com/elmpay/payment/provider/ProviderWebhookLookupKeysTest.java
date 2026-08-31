package com.elmpay.payment.provider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class ProviderWebhookLookupKeysTest {
    @Test
    void alipayLookupRequiresOneStrictlyDecodedBusinessReference() {
        assertEquals("order_123456", ProviderWebhookLookupKeys.alipayBusinessReference(
                "trade_status=TRADE_SUCCESS&out%5Ftrade%5Fno=order_123456"
                        .getBytes(StandardCharsets.UTF_8)));
        assertThrows(SecurityException.class,
                () -> ProviderWebhookLookupKeys.alipayBusinessReference(
                        "out_trade_no=order_123456&out_trade_no=order_654321"
                                .getBytes(StandardCharsets.UTF_8)));
        assertThrows(SecurityException.class,
                () -> ProviderWebhookLookupKeys.alipayBusinessReference(
                        "out_trade_no=%FF".getBytes(StandardCharsets.UTF_8)));
        assertThrows(SecurityException.class,
                () -> ProviderWebhookLookupKeys.alipayBusinessReference(
                        "out_trade_no".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void stripeLookupUsesOnlyTheExactDataObjectPath() {
        assertEquals("pi_expected123", ProviderWebhookLookupKeys.stripeProviderObject(
                ("{\"id\":\"evt_ignored123\",\"metadata\":{\"id\":\"pi_decoy123\"},"
                        + "\"data\":{\"object\":{\"id\":\"pi_expected123\"}}}")
                        .getBytes(StandardCharsets.UTF_8)));
        assertThrows(SecurityException.class,
                () -> ProviderWebhookLookupKeys.stripeProviderObject(
                        ("{\"data\":{\"object\":{\"id\":\"pi_one123\","
                                + "\"id\":\"pi_two123\"}}}")
                                .getBytes(StandardCharsets.UTF_8)));
        assertThrows(SecurityException.class,
                () -> ProviderWebhookLookupKeys.stripeProviderObject(
                        "{\"id\":\"pi_decoy123\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void paypalLookupUsesOnlyTheExactResourcePath() {
        assertEquals("CAPTURE-EXPECTED123", ProviderWebhookLookupKeys.payPalProviderObject(
                ("{\"id\":\"WH-EVENT-123456\",\"metadata\":{"
                        + "\"id\":\"CAPTURE-DECOY123\"},\"resource\":{"
                        + "\"id\":\"CAPTURE-EXPECTED123\"}}")
                        .getBytes(StandardCharsets.UTF_8)));
        assertThrows(SecurityException.class,
                () -> ProviderWebhookLookupKeys.payPalProviderObject(
                        "{\"id\":\"CAPTURE-DECOY123\"}".getBytes(StandardCharsets.UTF_8)));
    }
}
