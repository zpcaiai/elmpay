package com.elmpay.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class EventEnvelopeTest {
    @Test
    void canonicalEnvelopeRoundTripsAllTenantAggregateOrderingFields() {
        EventEnvelope expected = envelope(Map.of("amount_minor", 125L, "currency", "USD"));
        EventEnvelope actual = EventEnvelope.parse(expected.canonicalJson());
        assertEquals(expected, actual);
        assertEquals(expected.tenantId() + ":payment_intent:" + expected.aggregateId(),
                expected.aggregateKey());
    }

    @Test
    void duplicateKeysDecimalsUnknownFieldsAndRevisionZeroFailClosed() {
        assertThrows(IllegalArgumentException.class,
                () -> StrictJson.parse("{\"a\":1,\"a\":2}"));
        assertThrows(IllegalArgumentException.class,
                () -> StrictJson.parse("{\"amount\":1.5}"));
        String withUnknown = envelope(Map.of()).canonicalJson().replaceFirst("\\{",
                "{\"unknown\":true,");
        assertThrows(IllegalArgumentException.class, () -> EventEnvelope.parse(withUnknown));
        EventEnvelope value = envelope(Map.of());
        assertThrows(IllegalArgumentException.class, () -> new EventEnvelope(value.eventId(),
                value.eventName(), 1, value.tenantId(), value.projectId(), value.aggregateType(),
                value.aggregateId(), 0, value.occurredAt(), value.recordedAt(), value.traceId(),
                Map.of()));
    }

    @Test
    void malformedTypedFieldsOverflowAndNonObjectPayloadFailClosed() {
        EventEnvelope value = envelope(Map.of());
        String json = value.canonicalJson();
        assertThrows(IllegalArgumentException.class, () -> EventEnvelope.parse(json.replace(
                "\"event_id\":\"" + value.eventId() + "\"",
                "\"event_id\":\"not-a-uuid\"")));
        assertThrows(IllegalArgumentException.class, () -> EventEnvelope.parse(json.replace(
                "\"event_version\":1", "\"event_version\":2147483648")));
        assertThrows(IllegalArgumentException.class, () -> EventEnvelope.parse(json.replace(
                "\"revision\":7", "\"revision\":0")));
        assertThrows(IllegalArgumentException.class, () -> EventEnvelope.parse(json.replace(
                "\"occurred_at\":\"2026-08-30T00:00:00Z\"",
                "\"occurred_at\":\"not-an-instant\"")));
        assertThrows(IllegalArgumentException.class,
                () -> EventEnvelope.parse(json.replace("\"payload\":{}", "\"payload\":[]")));
    }

    private static EventEnvelope envelope(Map<String, Object> payload) {
        Instant occurred = Instant.parse("2026-08-30T00:00:00Z");
        return new EventEnvelope(UUID.randomUUID(), "payment_intent.captured", 1,
                UUID.randomUUID(), UUID.randomUUID(), "payment_intent", UUID.randomUUID(), 7,
                occurred, occurred.plusMillis(1), "trace-123", payload);
    }
}
