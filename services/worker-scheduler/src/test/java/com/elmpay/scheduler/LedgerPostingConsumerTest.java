package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.elmpay.ledger.LedgerService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class LedgerPostingConsumerTest {
    @Test
    void postingEnvelopeRequiresSupportedEventAndBalancedEntries() {
        UUID event = UUID.randomUUID();
        UUID tenant = UUID.randomUUID();
        UUID project = UUID.randomUUID();
        List<LedgerService.EntryDraft> balanced = List.of(
                new LedgerService.EntryDraft(UUID.randomUUID().toString(),
                        LedgerService.Direction.DEBIT, 100, "USD"),
                new LedgerService.EntryDraft(UUID.randomUUID().toString(),
                        LedgerService.Direction.CREDIT, 100, "USD"));
        assertDoesNotThrow(() -> new LedgerPostingConsumer.PostingEvent(event, tenant, project,
                "payment.captured.v1", "payment", "payment-1", Instant.EPOCH, "capture",
                balanced));
        assertThrows(IllegalArgumentException.class, () -> new LedgerPostingConsumer.PostingEvent(
                event, tenant, project, "unknown.v1", "payment", "payment-1", Instant.EPOCH,
                "capture", balanced));
        assertThrows(IllegalArgumentException.class, () -> new LedgerPostingConsumer.PostingEvent(
                event, tenant, project, "payment.captured.v1", "payment", "payment-1",
                Instant.EPOCH, "capture", balanced.subList(0, 1)));
    }
}
