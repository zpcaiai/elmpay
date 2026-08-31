package com.elmpay.scheduler.data;

import com.elmpay.scheduler.FileBackedPostgresDataSource;
import java.util.Map;

/** One-shot, externally authorized destructive partition detach entrypoint. */
public final class ArchivePartitionDetacherApplication {
    private ArchivePartitionDetacherApplication() { }

    public static void main(String[] arguments) {
        if (arguments.length != 0) {
            throw new IllegalArgumentException("archive partition detacher accepts no arguments");
        }
        Map<String, String> environment = System.getenv();
        if (!"detach-authorized".equals(environment.get("ELMPAY_ARCHIVE_DETACH_MODE"))) {
            throw new IllegalStateException("archive detach mode must be detach-authorized");
        }
        ArchivePartitionDetacherSettings settings =
                ArchivePartitionDetacherSettings.from(environment);
        FileBackedPostgresDataSource dataSource = new FileBackedPostgresDataSource(
                settings.databaseUrl(), settings.databaseUsername(), settings.databasePasswordFile(),
                settings.databaseCaFile(), settings.databaseClientCertificateFile(),
                settings.databaseClientPrivateKeyFile(), "elmpay-archive-partition-detacher");
        new ArchivePartitionDetacherSchemaVerifier(dataSource).verify();
        ArchiveDetachExecutionRequest request = ArchiveDetachExecutionRequest.load(
                settings.executionRequestFile());
        new JdbcArchivePartitionDetacher(dataSource).detach(request);
    }
}
