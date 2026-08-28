package com.elmpay.scheduler;

import com.elmpay.ledger.LedgerService;
import com.elmpay.scheduler.events.JdbcEventDeliveryStore;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Durable financial-event consumer: inbox marker and balanced ledger posting share one commit. */
public final class LedgerPostingConsumer {
    private static final Set<String> EVENT_TYPES = Set.of(
            "payment.captured.v1", "refund.succeeded.v1", "fee.assessed.v1",
            "fx.applied.v1", "dispute.opened.v1", "dispute.resolved.v1",
            "settlement.confirmed.v1", "financial.adjustment.approved.v1");

    public record PostingEvent(UUID eventId, UUID tenantId, UUID projectId, String eventType,
            String sourceKind, String sourceId, Instant effectiveAt, String description,
            List<LedgerService.EntryDraft> entries) {
        public PostingEvent {
            Objects.requireNonNull(eventId, "eventId");
            Objects.requireNonNull(tenantId, "tenantId");
            Objects.requireNonNull(projectId, "projectId");
            if (!EVENT_TYPES.contains(eventType)) {
                throw new IllegalArgumentException("unsupported financial event type");
            }
            if (sourceKind == null || sourceKind.isBlank() || sourceId == null
                    || sourceId.isBlank() || description == null || description.isBlank()) {
                throw new IllegalArgumentException("financial source identity is required");
            }
            Objects.requireNonNull(effectiveAt, "effectiveAt");
            entries = List.copyOf(entries);
            LedgerService.validateBalanced(entries);
        }
    }

    private final JdbcEventDeliveryStore delivery;
    private final LedgerService ledger;
    private final Duration leaseTtl;
    private final Duration retryDelay;

    public LedgerPostingConsumer(JdbcEventDeliveryStore delivery, LedgerService ledger,
            Duration leaseTtl, Duration retryDelay) {
        this.delivery = Objects.requireNonNull(delivery, "delivery");
        this.ledger = Objects.requireNonNull(ledger, "ledger");
        this.leaseTtl = positive(leaseTtl, "leaseTtl");
        this.retryDelay = positive(retryDelay, "retryDelay");
    }

    public JdbcEventDeliveryStore.InboxOutcome consume(
            JdbcEventDeliveryStore.InboxMessage message, PostingEvent event,
            String workerId, Instant now) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(event, "event");
        if (!message.eventId().equals(event.eventId())
                || !message.tenantId().equals(event.tenantId())
                || !message.projectId().equals(event.projectId())
                || !message.eventType().equals(event.eventType())) {
            throw new SecurityException("financial event envelope does not match verified message");
        }
        return delivery.consume("immutable-ledger-v1", message, workerId, now, leaseTtl,
                retryDelay, (connection, ignored) -> ledger.post(connection,
                        new LedgerService.PostRequest(event.tenantId().toString(),
                                event.sourceKind(), event.sourceId(), event.effectiveAt(),
                                event.description(), event.entries())));
    }

    private static Duration positive(Duration value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(field + " must be positive");
        }
        return value;
    }
}
