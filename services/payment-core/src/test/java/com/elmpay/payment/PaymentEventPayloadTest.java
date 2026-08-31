package com.elmpay.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.elmpay.money.Money;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class PaymentEventPayloadTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void providerAndRiskFactsAreProjectedFromResolvedMoneyAttempt() {
        PaymentIntent intent = intent();
        PaymentAttempt attempt = PaymentAttempt.begin(new AttemptDraft(intent.tenantId(),
                intent.id(), UUID.randomUUID(), "stripe", AttemptOperation.PAYMENT, 0,
                "a".repeat(64), "event-attempt-key-0001", NOW, "event-worker",
                NOW.plusSeconds(30)), 1).resolve(new AttemptResolution(AttemptState.SUCCEEDED,
                        OutcomeClass.SUCCEEDED, "b".repeat(64), "request-1", "pi_1",
                        "adapter.normalized", "SUCCEEDED", NOW.plusSeconds(1)));

        Map<String, Object> payload = JdbcPaymentRepository.outboxPayload(intent, attempt,
                "payment.attempt.resolved.v1");

        assertEquals("stripe", payload.get("provider"));
        assertEquals("pi_1", payload.get("provider_transaction_id"));
        assertEquals("SUCCEEDED", payload.get("provider_status"));
        assertEquals("APPROVED", payload.get("risk_outcome"));
        assertEquals("payment", payload.get("attempt_operation"));
    }

    @Test
    void creationRecordsTheCompletedSynchronousRiskGate() {
        Map<String, Object> payload = JdbcPaymentRepository.outboxPayload(intent(), null,
                "payment.intent.created.v1");
        assertEquals("APPROVED", payload.get("risk_outcome"));
    }

    private static PaymentIntent intent() {
        CreateIntentCommand command = new CreateIntentCommand(UUID.randomUUID(), UUID.randomUUID(),
                UUID.randomUUID(), "event-order-1", Money.of(1_000, "USD"), Set.of("card"),
                ConfirmationMode.AUTOMATIC, "US", Duration.ofHours(1),
                "event-create-key-0001");
        return PaymentIntent.create(command, Clock.fixed(NOW, ZoneOffset.UTC));
    }
}
