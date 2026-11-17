package com.elmpay.gateway;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Resolves the explicit task-owned loopback PostgreSQL cluster from {@code ELMPAY_P1_TEST_JDBC_URL}
 * when provided, or lazily provisions an isolated loopback PostgreSQL cluster for local Gradle runs.
 */
final class LoopbackPostgresTestCluster {
    private static final String ADMIN_USER = "elmpay_p1_admin";
    private static final String DATABASE_NAME = "elmpay_p1_test";
    private static final Object LOCK = new Object();
    private static String provisionedJdbcUrl;

    private LoopbackPostgresTestCluster() {
    }

    static String jdbcUrl() {
        String configured = System.getenv("ELMPAY_P1_TEST_JDBC_URL");
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        synchronized (LOCK) {
            if (provisionedJdbcUrl == null) {
                provisionedJdbcUrl = startEphemeralCluster();
            }
            return provisionedJdbcUrl;
        }
    }

    static String adminUser() {
        String configured = System.getenv("ELMPAY_P1_TEST_ADMIN_USER");
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        jdbcUrl();
        return ADMIN_USER;
    }

    private static String startEphemeralCluster() {
        Path pgBin = findPgBinDirectory();
        String initdb = pgBin.resolve("initdb").toString();
        String pgCtl = pgBin.resolve("pg_ctl").toString();
        try {
            Path rootDir = Files.createTempDirectory("elmpay_p1_pg_");
            Path dataDir = rootDir.resolve("data");
            Path logFile = rootDir.resolve("postgres.log");
            int port = allocateLoopbackPort();
            runCommand(List.of(
                    initdb,
                    "-D", dataDir.toString(),
                    "-U", ADMIN_USER,
                    "--auth=trust",
                    "--no-instructions",
                    "--encoding=UTF8",
                    "--locale=C"));
            String pgOptions = "-F -h 127.0.0.1 -p " + port + " -k " + rootDir;
            runCommand(List.of(
                    pgCtl,
                    "-D", dataDir.toString(),
                    "-l", logFile.toString(),
                    "-w",
                    "-o", pgOptions,
                    "start"));
            Runtime.getRuntime().addShutdownHook(new Thread(() -> stopAndClean(pgCtl, dataDir, rootDir),
                    "elmpay-p1-pg-shutdown"));
            String maintenanceUrl = "jdbc:postgresql://127.0.0.1:" + port + "/postgres";
            try (Connection connection = DriverManager.getConnection(maintenanceUrl, ADMIN_USER, "");
                    Statement statement = connection.createStatement()) {
                statement.execute("CREATE DATABASE " + DATABASE_NAME + " OWNER " + ADMIN_USER);
            }
            return "jdbc:postgresql://127.0.0.1:" + port + "/" + DATABASE_NAME;
        } catch (IOException | InterruptedException | SQLException failure) {
            if (failure instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("failed to provision loopback PostgreSQL test cluster", failure);
        }
    }

    private static Path findPgBinDirectory() {
        String envBin = System.getenv("ELMPAY_PG_BIN_DIR");
        List<String> candidates = List.of(
                envBin == null ? "" : envBin,
                "/opt/homebrew/opt/postgresql@17/bin",
                "/opt/homebrew/opt/postgresql@16/bin",
                "/opt/homebrew/bin",
                "/usr/local/opt/postgresql@17/bin",
                "/usr/local/bin",
                "/usr/lib/postgresql/17/bin",
                "/usr/lib/postgresql/16/bin",
                "/usr/bin");
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                Path dir = Path.of(candidate);
                if (Files.isExecutable(dir.resolve("initdb")) && Files.isExecutable(dir.resolve("pg_ctl"))) {
                    return dir;
                }
            }
        }
        String pathEnv = System.getenv("PATH");
        if (pathEnv != null) {
            for (String entry : pathEnv.split(File.pathSeparator)) {
                if (!entry.isBlank()) {
                    Path dir = Path.of(entry);
                    if (Files.isExecutable(dir.resolve("initdb")) && Files.isExecutable(dir.resolve("pg_ctl"))) {
                        return dir;
                    }
                }
            }
        }
        throw new IllegalStateException("PostgreSQL binaries (initdb, pg_ctl) not found for loopback test cluster");
    }

    private static int allocateLoopbackPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return socket.getLocalPort();
        }
    }

    private static void runCommand(List<String> command) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();
        byte[] outputBytes = process.getInputStream().readAllBytes();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("command timed out: " + String.join(" ", command));
        }
        if (process.exitValue() != 0) {
            String output = new String(outputBytes, StandardCharsets.UTF_8);
            throw new IOException("command exited with " + process.exitValue() + ": " + output);
        }
    }

    private static void stopAndClean(String pgCtl, Path dataDir, Path rootDir) {
        try {
            new ProcessBuilder(pgCtl, "-D", dataDir.toString(), "-m", "immediate", "-w", "stop")
                    .redirectErrorStream(true)
                    .start()
                    .waitFor(15, TimeUnit.SECONDS);
        } catch (IOException | InterruptedException ignored) {
            if (ignored instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
        try (var stream = Files.walk(rootDir)) {
            stream.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }
}
