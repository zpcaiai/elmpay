package com.elmpay.scheduler.data;

import com.elmpay.scheduler.FileBackedPostgresDataSource;
import java.time.Clock;
import java.time.YearMonth;
import java.time.ZoneOffset;

/** Bounded entrypoint used by the initial GitOps Job and the daily maintenance CronJob. */
public final class PartitionMaintenanceApplication {
    private PartitionMaintenanceApplication() { }

    public static void main(String[] arguments) {
        if (arguments.length != 0) {
            throw new IllegalArgumentException("partition maintenance accepts no arguments");
        }
        if (!"precreate".equals(System.getenv("ELMPAY_PARTITION_MODE"))) {
            throw new IllegalStateException("ELMPAY_PARTITION_MODE must be precreate");
        }
        PartitionMaintenanceSettings settings =
                PartitionMaintenanceSettings.from(System.getenv());
        FileBackedPostgresDataSource dataSource = new FileBackedPostgresDataSource(
                settings.databaseUrl(), settings.databaseUsername(),
                settings.databasePasswordFile(), settings.databaseCaFile(),
                settings.databaseClientCertificateFile(),
                settings.databaseClientPrivateKeyFile(), "elmpay-partition-precreator");
        new PartitionMaintenanceSchemaVerifier(dataSource).verify();
        Clock clock = Clock.systemUTC();
        JdbcTenantPartitionManager manager = new JdbcTenantPartitionManager(dataSource, clock);
        YearMonth current = YearMonth.from(clock.instant().atZone(ZoneOffset.UTC));
        manager.ensureMonthlyPartitions(current, settings.monthsAhead() + 1,
                settings.actorId(), "scheduled partition precreation", settings.ticketId());
    }
}
