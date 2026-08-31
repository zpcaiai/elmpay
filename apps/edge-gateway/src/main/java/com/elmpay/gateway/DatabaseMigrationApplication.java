package com.elmpay.gateway;

import java.nio.file.Path;
import java.util.Map;

/** One-shot schema migration entrypoint for the separately credentialed GitOps PreSync job. */
public final class DatabaseMigrationApplication {
    private DatabaseMigrationApplication() { }

    public static void main(String[] arguments) {
        if (arguments.length != 0) {
            throw new IllegalArgumentException("database migration accepts no arguments");
        }
        Map<String, String> environment = System.getenv();
        if (!"apply".equals(required(environment, "ELMPAY_MIGRATION_MODE"))) {
            throw new IllegalStateException("ELMPAY_MIGRATION_MODE must be apply");
        }
        String username = required(environment, "ELMPAY_MIGRATION_DATABASE_USERNAME");
        if (!DatabaseMigrator.MIGRATION_ROLE.equals(username)) {
            throw new IllegalStateException(
                    "migration database username must be the dedicated elmpay_migrator role");
        }
        for (String forbidden : new String[] {"ELMPAY_DATABASE_PASSWORD",
                "ELMPAY_DATABASE_PASSWORD_FILE", "ELMPAY_DATABASE_USERNAME"}) {
            if (environment.containsKey(forbidden)) {
                throw new IllegalStateException(
                        "runtime database credentials are forbidden in the migration job");
            }
        }
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                required(environment, "ELMPAY_MIGRATION_DATABASE_URL"), username,
                absolute(environment, "ELMPAY_MIGRATION_DATABASE_PASSWORD_FILE"),
                absolute(environment, "ELMPAY_MIGRATION_DATABASE_CA_FILE"),
                absolute(environment, "ELMPAY_MIGRATION_DATABASE_CLIENT_CERTIFICATE_FILE"),
                absolute(environment, "ELMPAY_MIGRATION_DATABASE_CLIENT_PRIVATE_KEY_FILE"),
                "elmpay-database-migrator");
        new DatabaseMigrator(dataSource).migrate();
    }

    private static Path absolute(Map<String, String> environment, String key) {
        Path path = Path.of(required(environment, key)).normalize();
        if (!path.isAbsolute()) {
            throw new IllegalStateException(key + " must be an absolute mounted path");
        }
        return path;
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank() || !value.equals(value.trim())) {
            throw new IllegalStateException(key + " is required without surrounding whitespace");
        }
        return value;
    }
}
