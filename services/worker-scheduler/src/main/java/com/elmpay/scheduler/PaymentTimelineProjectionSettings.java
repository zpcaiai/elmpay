package com.elmpay.scheduler;

import java.util.Map;
import java.util.Objects;

/** Fail-fast worker configuration for one tenant/project payment timeline projection. */
public record PaymentTimelineProjectionSettings(String projectorName, int batchSize,
        int maximumBatchesPerRun) {
    public static final String PROJECTOR_NAME = "ELMPAY_PAYMENT_TIMELINE_PROJECTOR";
    public static final String BATCH_SIZE = "ELMPAY_PAYMENT_TIMELINE_BATCH_SIZE";
    public static final String MAXIMUM_BATCHES = "ELMPAY_PAYMENT_TIMELINE_MAXIMUM_BATCHES";

    public PaymentTimelineProjectionSettings {
        if (projectorName == null || projectorName.isBlank() || projectorName.length() > 128) {
            throw new IllegalArgumentException(PROJECTOR_NAME + " is invalid");
        }
        if (batchSize < 1 || batchSize > 1_000) {
            throw new IllegalArgumentException(BATCH_SIZE + " must be between 1 and 1000");
        }
        if (maximumBatchesPerRun < 1 || maximumBatchesPerRun > 10_000) {
            throw new IllegalArgumentException(MAXIMUM_BATCHES
                    + " must be between 1 and 10000");
        }
    }

    public static PaymentTimelineProjectionSettings from(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        return new PaymentTimelineProjectionSettings(required(environment, PROJECTOR_NAME),
                positiveInteger(environment, BATCH_SIZE),
                positiveInteger(environment, MAXIMUM_BATCHES));
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        return value;
    }

    private static int positiveInteger(Map<String, String> environment, String key) {
        String value = required(environment, key);
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            throw new IllegalStateException(key + " must be an integer", exception);
        }
    }
}
