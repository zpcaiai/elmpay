package com.elmpay.scheduler;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

final class PaymentTimelineProjectionSettingsTest {
    @Test
    void productionSettingsRequireExplicitBoundedValues() {
        PaymentTimelineProjectionSettings settings = PaymentTimelineProjectionSettings.from(Map.of(
                PaymentTimelineProjectionSettings.PROJECTOR_NAME, "payment-status-v1",
                PaymentTimelineProjectionSettings.BATCH_SIZE, "250",
                PaymentTimelineProjectionSettings.MAXIMUM_BATCHES, "20"));
        assertEquals("payment-status-v1", settings.projectorName());
        assertEquals(250, settings.batchSize());
        assertEquals(20, settings.maximumBatchesPerRun());
        assertThrows(IllegalStateException.class,
                () -> PaymentTimelineProjectionSettings.from(Map.of()));
        assertThrows(IllegalArgumentException.class,
                () -> new PaymentTimelineProjectionSettings("payment-status-v1", 0, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new PaymentTimelineProjectionSettings("payment-status-v1", 1, 10_001));
    }
}
