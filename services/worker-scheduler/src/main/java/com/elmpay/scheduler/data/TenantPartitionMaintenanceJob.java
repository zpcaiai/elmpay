package com.elmpay.scheduler.data;

import java.time.Clock;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.Objects;

/** Bounded scheduler entrypoint that keeps current and future monthly partitions available. */
public final class TenantPartitionMaintenanceJob implements Runnable {
    private final JdbcTenantPartitionManager manager;
    private final Clock clock;
    private final int monthsAhead;
    private final String actorId;
    private final String ticketId;

    public TenantPartitionMaintenanceJob(JdbcTenantPartitionManager manager, Clock clock,
            int monthsAhead, String actorId, String ticketId) {
        this.manager = Objects.requireNonNull(manager, "manager");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (monthsAhead < 1 || monthsAhead > 23) {
            throw new IllegalArgumentException("monthsAhead must be 1..23");
        }
        this.monthsAhead = monthsAhead;
        this.actorId = Objects.requireNonNull(actorId, "actorId");
        this.ticketId = Objects.requireNonNull(ticketId, "ticketId");
    }

    @Override
    public void run() {
        YearMonth current = YearMonth.from(clock.instant().atZone(ZoneOffset.UTC));
        manager.ensureMonthlyPartitions(current, monthsAhead + 1, actorId,
                "scheduled partition precreation", ticketId);
    }
}
