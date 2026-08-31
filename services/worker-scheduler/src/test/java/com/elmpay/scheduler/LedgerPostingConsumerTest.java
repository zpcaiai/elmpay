package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.scheduler.events.JdbcEventDeliveryStore;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class LedgerPostingConsumerTest {
    private static final UUID EVENT = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID TENANT = UUID.fromString("10000000-0000-0000-0000-000000000002");
    private static final UUID PROJECT = UUID.fromString("10000000-0000-0000-0000-000000000003");
    private static final UUID AGGREGATE = UUID.fromString("10000000-0000-0000-0000-000000000004");
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void extractsExactCaptureDeltaAndSemanticTimestamp() {
        LedgerPostingConsumer.FinancialFact fact =
                LedgerPostingConsumer.FinancialFact.from(capture(PROJECT, AGGREGATE, 1, 125));
        assertEquals("payment", fact.sourceKind());
        assertEquals(125, fact.amountMinor());
        assertEquals("USD", fact.currency());
        assertEquals(NOW, fact.effectiveAt());
    }

    @Test
    void crossProjectAggregateRevisionAndNonPositiveMoneyTamperingFailClosed() {
        assertThrows(SecurityException.class, () -> LedgerPostingConsumer.FinancialFact.from(
                capture(UUID.randomUUID(), AGGREGATE, 1, 125)));
        assertThrows(SecurityException.class, () -> LedgerPostingConsumer.FinancialFact.from(
                capture(PROJECT, AGGREGATE, 2, 125)));
        assertThrows(IllegalArgumentException.class,
                () -> LedgerPostingConsumer.FinancialFact.from(
                        capture(PROJECT, AGGREGATE, 1, 0)));
    }

    @Test
    void unknownCatalogFieldsAndInvalidOrderDigestFailClosed() {
        JdbcEventDeliveryStore.InboxMessage valid = capture(PROJECT, AGGREGATE, 1, 125);
        assertThrows(IllegalArgumentException.class, () ->
                LedgerPostingConsumer.FinancialFact.from(withPayload(valid,
                        valid.payloadJson().replace("}", ",\"untrusted\":true}"))));
        assertThrows(IllegalArgumentException.class, () ->
                LedgerPostingConsumer.FinancialFact.from(withPayload(valid,
                        valid.payloadJson().replace("a".repeat(64), "not-a-digest"))));
    }

    @Test
    void unsupportedCatalogEventAndAmbiguousAccountsCannotBecomePostingPolicy() {
        JdbcEventDeliveryStore.InboxMessage unsupported = new JdbcEventDeliveryStore.InboxMessage(
                EVENT, TENANT, PROJECT, "payment_intent", AGGREGATE, 1,
                "payment_intent.authorized", 1,
                "{\"aggregate_revision\":1}", NOW, NOW, "trace-1");
        assertThrows(LedgerPostingConsumer.MissingPostingPolicyException.class,
                () -> LedgerPostingConsumer.FinancialFact.from(unsupported));
        UUID same = UUID.randomUUID();
        assertThrows(IllegalArgumentException.class,
                () -> new LedgerPostingConsumer.PostingPolicy(1, "payment", "capture",
                        same.toString(), same.toString()));
    }

    private static JdbcEventDeliveryStore.InboxMessage capture(UUID payloadProject,
            UUID payloadIntent, long payloadRevision, long amount) {
        String payload = "{\"aggregate_revision\":" + payloadRevision
                + ",\"amount_minor\":" + amount
                + ",\"business_order_digest\":\"" + "a".repeat(64)
                + "\",\"captured_at\":\"" + NOW
                + "\",\"currency\":\"USD\",\"payment_intent_id\":\""
                + payloadIntent + "\",\"project_id\":\"" + payloadProject
                + "\",\"provider\":\"stripe\"}";
        return new JdbcEventDeliveryStore.InboxMessage(EVENT, TENANT, PROJECT,
                "payment_intent", AGGREGATE, 1, "payment_intent.captured", 1,
                payload, NOW, NOW, "trace-1");
    }

    private static JdbcEventDeliveryStore.InboxMessage withPayload(
            JdbcEventDeliveryStore.InboxMessage message, String payload) {
        return new JdbcEventDeliveryStore.InboxMessage(message.eventId(), message.tenantId(),
                message.projectId(), message.aggregateType(), message.aggregateId(),
                message.aggregateRevision(), message.eventName(), message.eventVersion(), payload,
                message.occurredAt(), message.recordedAt(), message.traceId());
    }
}
