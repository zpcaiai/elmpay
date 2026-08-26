package com.elmpay.gateway;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public final class FixedWindowRateLimiter {
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();
    private final int limit;
    private final long windowSeconds;
    private final Clock clock;

    public FixedWindowRateLimiter(int limit, long windowSeconds, Clock clock) {
        if (limit < 1 || windowSeconds < 1) {
            throw new IllegalArgumentException("invalid rate limit");
        }
        this.limit = limit;
        this.windowSeconds = windowSeconds;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public boolean allow(String key) {
        long epoch = clock.instant().getEpochSecond() / windowSeconds;
        Window updated = windows.compute(key, (ignored, current) ->
                current == null || current.epoch() != epoch
                        ? new Window(epoch, 1) : new Window(epoch, current.count() + 1));
        if (windows.size() > 10_000) {
            windows.entrySet().removeIf(entry -> entry.getValue().epoch() < epoch - 1);
        }
        return updated.count() <= limit;
    }

    private record Window(long epoch, int count) {
    }
}
