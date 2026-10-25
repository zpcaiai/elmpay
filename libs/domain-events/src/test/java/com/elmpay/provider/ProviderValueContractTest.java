package com.elmpay.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.money.Money;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class ProviderValueContractTest {
    private static final UUID TENANT = UUID.fromString("33aa53b7-6901-4a0e-a757-a2c3c86503f5");
    private static final UUID PROJECT = UUID.fromString("e91e8671-2ac8-45a0-bb86-45ab160557af");
    private static final UUID ACCOUNT = UUID.fromString("9d65d39d-43a3-4664-9bdd-d0600162c147");
    private static final Instant AT = Instant.parse("2026-01-01T00:00:00Z");
    private static final Money AMOUNT = Money.of(1000, "CNY");

    private static ProviderRequestContext context() {
        return new ProviderRequestContext(TENANT, PROJECT, ACCOUNT, "k".repeat(16),
                "correlation-test", "version-test");
    }

    @Test
    void requestContextPreservesTheTenantProjectAccountAndKeyBoundaries() {
        ProviderRequestContext value = context();
        assertEquals(TENANT, value.tenantId());
        assertEquals(PROJECT, value.projectId());
        assertEquals(ACCOUNT, value.merchantAccountId());
        assertEquals("k".repeat(16), value.idempotencyKey());
        assertEquals("correlation-test", value.correlationId());
        assertEquals("version-test", value.credentialVersion());
        assertEquals("x".repeat(128), new ProviderRequestContext(TENANT, PROJECT, ACCOUNT,
                "x".repeat(128), "c", "v").idempotencyKey());
        for (String invalid : new String[] {"", "x".repeat(15), "x".repeat(129)}) {
            assertThrows(IllegalArgumentException.class, () -> new ProviderRequestContext(
                    TENANT, PROJECT, ACCOUNT, invalid, "c", "v"));
        }
        assertThrows(NullPointerException.class,
                () -> new ProviderRequestContext(null, PROJECT, ACCOUNT, "k".repeat(16), "c", "v"));
        assertThrows(NullPointerException.class,
                () -> new ProviderRequestContext(TENANT, null, ACCOUNT, "k".repeat(16), "c", "v"));
        assertThrows(NullPointerException.class,
                () -> new ProviderRequestContext(TENANT, PROJECT, null, "k".repeat(16), "c", "v"));
        assertThrows(NullPointerException.class,
                () -> new ProviderRequestContext(TENANT, PROJECT, ACCOUNT, null, "c", "v"));
        assertThrows(NullPointerException.class,
                () -> new ProviderRequestContext(TENANT, PROJECT, ACCOUNT, "k".repeat(16), null, "v"));
        assertThrows(NullPointerException.class,
                () -> new ProviderRequestContext(TENANT, PROJECT, ACCOUNT, "k".repeat(16), "c", null));
    }

    @Test
    void createCommandCopiesProviderParametersAndKeepsExactMinorUnits() {
        Map<String, String> parameters = new LinkedHashMap<>(Map.of("mode", "native"));
        CreatePaymentCommand command = new CreatePaymentCommand(context(), PROJECT,
                "order-test", AMOUNT, "wechat", null, parameters);
        parameters.put("mode", "changed");
        assertEquals(context(), command.context());
        assertEquals(PROJECT, command.paymentIntentId());
        assertEquals("order-test", command.businessOrderNo());
        assertEquals(AMOUNT, command.amount());
        assertEquals(1000L, command.amount().amountMinor());
        assertEquals("wechat", command.method());
        assertNull(command.approvedReturnRouteId());
        assertEquals(Map.of("mode", "native"), command.providerParameters());
        assertThrows(UnsupportedOperationException.class, () -> command.providerParameters().clear());
        for (String blank : new String[] {"", " \n"}) {
            assertThrows(IllegalArgumentException.class, () -> new CreatePaymentCommand(context(),
                    PROJECT, blank, AMOUNT, "wechat", "approved", Map.of()));
            assertThrows(IllegalArgumentException.class, () -> new CreatePaymentCommand(context(),
                    PROJECT, "order", AMOUNT, blank, "approved", Map.of()));
        }
    }

    @Test
    void createCommandRequiresAllMandatoryBindings() {
        assertThrows(NullPointerException.class, () -> new CreatePaymentCommand(null,
                PROJECT, "order", AMOUNT, "wechat", null, Map.of()));
        assertThrows(NullPointerException.class, () -> new CreatePaymentCommand(context(),
                null, "order", AMOUNT, "wechat", null, Map.of()));
        assertThrows(NullPointerException.class, () -> new CreatePaymentCommand(context(),
                PROJECT, null, AMOUNT, "wechat", null, Map.of()));
        assertThrows(NullPointerException.class, () -> new CreatePaymentCommand(context(),
                PROJECT, "order", null, "wechat", null, Map.of()));
        assertThrows(NullPointerException.class, () -> new CreatePaymentCommand(context(),
                PROJECT, "order", AMOUNT, null, null, Map.of()));
        assertThrows(NullPointerException.class, () -> new CreatePaymentCommand(context(),
                PROJECT, "order", AMOUNT, "wechat", null, null));
    }

    @Test
    void refundCommandRetainsEveryRequiredReference() {
        RefundCommand value = new RefundCommand(context(), PROJECT, "provider-test", AMOUNT,
                "customer-request");
        assertEquals(context(), value.context());
        assertEquals(PROJECT, value.refundId());
        assertEquals("provider-test", value.providerPaymentId());
        assertEquals(AMOUNT, value.amount());
        assertEquals("customer-request", value.reason());
        assertThrows(NullPointerException.class,
                () -> new RefundCommand(null, PROJECT, "p", AMOUNT, "reason"));
        assertThrows(NullPointerException.class,
                () -> new RefundCommand(context(), null, "p", AMOUNT, "reason"));
        assertThrows(NullPointerException.class,
                () -> new RefundCommand(context(), PROJECT, null, AMOUNT, "reason"));
        assertThrows(NullPointerException.class,
                () -> new RefundCommand(context(), PROJECT, "p", null, "reason"));
        assertThrows(NullPointerException.class,
                () -> new RefundCommand(context(), PROJECT, "p", AMOUNT, null));
    }

    @Test
    void unknownPaymentAndRefundOutcomesCannotBeDeclaredFinal() {
        for (ProviderOutcome outcome : ProviderOutcome.values()) {
            ProviderRefund pending = new ProviderRefund("refund-test", outcome, AMOUNT, false);
            ProviderPayment payment = new ProviderPayment("request-test", "payment-test", outcome,
                    AMOUNT, AMOUNT, false, Map.of());
            assertEquals(outcome, pending.outcome());
            assertEquals(AMOUNT, pending.refunded());
            assertEquals("refund-test", pending.providerRefundId());
            assertFalse(pending.finalOutcome());
            assertEquals(outcome, payment.outcome());
            assertFalse(payment.finalOutcome());
            if (outcome == ProviderOutcome.UNKNOWN) {
                assertThrows(IllegalArgumentException.class,
                        () -> new ProviderRefund("r", outcome, AMOUNT, true));
                assertThrows(IllegalArgumentException.class,
                        () -> new ProviderPayment("p", null, outcome, null, null, true, Map.of()));
            } else {
                assertTrue(new ProviderRefund("r", outcome, AMOUNT, true).finalOutcome());
                assertTrue(new ProviderPayment("p", null, outcome, null, null, true, Map.of())
                        .finalOutcome());
            }
        }
        assertThrows(NullPointerException.class, () -> new ProviderRefund("r", null, AMOUNT, false));
    }

    @Test
    void paymentClientActionsAreCopiedAndRequestIdentityIsMandatory() {
        Map<String, String> action = new LinkedHashMap<>(Map.of("action", "display"));
        ProviderPayment value = new ProviderPayment("request-test", "payment-test",
                ProviderOutcome.REQUIRES_ACTION, AMOUNT, null, false, action);
        action.clear();
        assertEquals("request-test", value.providerRequestId());
        assertEquals("payment-test", value.providerPaymentId());
        assertEquals(AMOUNT, value.authorized());
        assertNull(value.captured());
        assertEquals(Map.of("action", "display"), value.clientAction());
        assertThrows(UnsupportedOperationException.class, () -> value.clientAction().clear());
        assertThrows(NullPointerException.class,
                () -> new ProviderPayment(null, null, ProviderOutcome.UNKNOWN, null, null, false, Map.of()));
        assertThrows(NullPointerException.class,
                () -> new ProviderPayment("p", null, null, null, null, false, Map.of()));
        assertThrows(NullPointerException.class,
                () -> new ProviderPayment("p", null, ProviderOutcome.UNKNOWN, null, null, false, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ProviderPayment(" \n", null, ProviderOutcome.UNKNOWN, null, null, false, Map.of()));
    }

    @Test
    void webhookOwnsItsBodyAndHeadersAndErasesOnlyItsCopyOnClose() {
        byte[] body = "synthetic webhook".getBytes(StandardCharsets.US_ASCII);
        byte[] original = body.clone();
        Map<String, String> headers = new LinkedHashMap<>(Map.of("content-type", "application/json"));
        WebhookRequest value = new WebhookRequest(TENANT, ACCOUNT, headers, body, AT);
        headers.clear();
        body[0] = 'X';
        assertEquals(TENANT, value.tenantId());
        assertEquals(ACCOUNT, value.merchantAccountId());
        assertEquals(AT, value.receivedAt());
        assertEquals(Map.of("content-type", "application/json"), value.headers());
        assertThrows(UnsupportedOperationException.class, () -> value.headers().clear());
        assertArrayEquals(original, value.rawBody());
        byte[] returned = value.rawBody();
        returned[0] = 'Y';
        assertArrayEquals(original, value.rawBody());
        value.close();
        value.close();
        assertArrayEquals(new byte[original.length], value.rawBody());
        assertEquals('X', body[0]);
        assertEquals('Y', returned[0]);
    }

    @Test
    void webhookRequiresBoundedNonEmptyBodyAndEveryBinding() {
        for (int length : new int[] {1, 1_048_576}) {
            try (WebhookRequest value = new WebhookRequest(TENANT, ACCOUNT, Map.of(),
                    new byte[length], AT)) {
                assertEquals(length, value.rawBody().length);
            }
        }
        for (int length : new int[] {0, 1_048_577}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new WebhookRequest(TENANT, ACCOUNT, Map.of(), new byte[length], AT));
        }
        assertThrows(NullPointerException.class,
                () -> new WebhookRequest(null, ACCOUNT, Map.of(), new byte[1], AT));
        assertThrows(NullPointerException.class,
                () -> new WebhookRequest(TENANT, null, Map.of(), new byte[1], AT));
        assertThrows(NullPointerException.class,
                () -> new WebhookRequest(TENANT, ACCOUNT, null, new byte[1], AT));
        assertThrows(NullPointerException.class,
                () -> new WebhookRequest(TENANT, ACCOUNT, Map.of(), null, AT));
        assertThrows(NullPointerException.class,
                () -> new WebhookRequest(TENANT, ACCOUNT, Map.of(), new byte[1], null));
    }

    @Test
    void verifiedEventsCopyCanonicalDataAndKeepOptionalUnsettledFields() {
        Map<String, String> data = new LinkedHashMap<>(Map.of("outcome", "unknown"));
        VerifiedProviderEvent value = new VerifiedProviderEvent(TENANT, ACCOUNT, "event-test",
                "payment.unknown", null, null, null, "key-id-test", AT, data);
        data.clear();
        assertEquals(TENANT, value.tenantId());
        assertEquals(ACCOUNT, value.merchantAccountId());
        assertEquals("event-test", value.providerEventId());
        assertEquals("payment.unknown", value.eventType());
        assertEquals("key-id-test", value.signatureKeyId());
        assertEquals(AT, value.providerOccurredAt());
        assertNull(value.providerPaymentId());
        assertNull(value.businessOrderNo());
        assertNull(value.amount());
        assertEquals(Map.of("outcome", "unknown"), value.canonicalData());
        assertThrows(UnsupportedOperationException.class, () -> value.canonicalData().clear());
    }

    @Test
    void verifiedEventsRequireEveryAuthorityAndEvidenceBinding() {
        assertThrows(NullPointerException.class, () -> new VerifiedProviderEvent(null, ACCOUNT,
                "e", "t", null, null, null, "key", AT, Map.of()));
        assertThrows(NullPointerException.class, () -> new VerifiedProviderEvent(TENANT, null,
                "e", "t", null, null, null, "key", AT, Map.of()));
        assertThrows(NullPointerException.class, () -> new VerifiedProviderEvent(TENANT, ACCOUNT,
                null, "t", null, null, null, "key", AT, Map.of()));
        assertThrows(NullPointerException.class, () -> new VerifiedProviderEvent(TENANT, ACCOUNT,
                "e", null, null, null, null, "key", AT, Map.of()));
        assertThrows(NullPointerException.class, () -> new VerifiedProviderEvent(TENANT, ACCOUNT,
                "e", "t", null, null, null, null, AT, Map.of()));
        assertThrows(NullPointerException.class, () -> new VerifiedProviderEvent(TENANT, ACCOUNT,
                "e", "t", null, null, null, "key", null, Map.of()));
        assertThrows(NullPointerException.class, () -> new VerifiedProviderEvent(TENANT, ACCOUNT,
                "e", "t", null, null, null, "key", AT, null));
    }

    @Test
    void providerFailureClassificationPreservesUnknownAndRetryDecisionsSeparately() {
        for (boolean retryable : new boolean[] {true, false}) {
            for (boolean unknown : new boolean[] {true, false}) {
                ProviderException failure = new ProviderException("TEST_UNAVAILABLE", "synthetic failure",
                        retryable, unknown);
                assertEquals("TEST_UNAVAILABLE", failure.code());
                assertEquals("synthetic failure", failure.getMessage());
                assertEquals(retryable, failure.retryable());
                assertEquals(unknown, failure.outcomeUnknown());
            }
        }
    }
}
