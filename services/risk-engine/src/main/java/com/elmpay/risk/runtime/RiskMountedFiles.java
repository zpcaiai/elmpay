package com.elmpay.risk.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Fixed, bounded file mounts used by the risk process and its edge client. */
final class RiskMountedFiles {
    private static final Path SECRET_ROOT = Path.of("/var/run/secrets/elmpay");
    private static final Set<PosixFilePermission> WRITE = Set.of(
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.GROUP_WRITE,
            PosixFilePermission.OTHERS_WRITE);
    private static final Map<String, Binding> BINDINGS = Map.ofEntries(
            entry("ELMPAY_RISK_TLS_SERVER_CERTIFICATE_FILE", "risk-server-mtls", "tls.crt",
                    256 * 1024),
            entry("ELMPAY_RISK_TLS_SERVER_PRIVATE_KEY_FILE", "risk-server-mtls", "tls.key",
                    64 * 1024),
            entry("ELMPAY_RISK_TLS_CLIENT_CA_BUNDLE_FILE", "risk-server-mtls",
                    "client-ca.crt", 256 * 1024),
            entry("ELMPAY_RISK_SIGNAL_CLIENT_CERTIFICATE_FILE", "risk-signal-mtls", "tls.crt",
                    256 * 1024),
            entry("ELMPAY_RISK_SIGNAL_CLIENT_PRIVATE_KEY_FILE", "risk-signal-mtls", "tls.key",
                    64 * 1024),
            entry("ELMPAY_RISK_SIGNAL_CA_BUNDLE_FILE", "risk-signal-mtls", "ca.crt",
                    256 * 1024),
            entry("ELMPAY_RISK_MODEL_CLIENT_CERTIFICATE_FILE", "risk-model-mtls", "tls.crt",
                    256 * 1024),
            entry("ELMPAY_RISK_MODEL_CLIENT_PRIVATE_KEY_FILE", "risk-model-mtls", "tls.key",
                    64 * 1024),
            entry("ELMPAY_RISK_MODEL_CA_BUNDLE_FILE", "risk-model-mtls", "ca.crt",
                    256 * 1024),
            entry("ELMPAY_RISK_CLIENT_CERTIFICATE_FILE", "risk-client-mtls", "tls.crt",
                    256 * 1024),
            entry("ELMPAY_RISK_CLIENT_PRIVATE_KEY_FILE", "risk-client-mtls", "tls.key",
                    64 * 1024),
            entry("ELMPAY_RISK_CA_BUNDLE_FILE", "risk-client-mtls", "ca.crt",
                    256 * 1024),
            entry("ELMPAY_RISK_DATABASE_PASSWORD_FILE", "risk-database-credentials", "password",
                    8 * 1024),
            entry("ELMPAY_RISK_DATABASE_CA_FILE", "risk-database-mtls", "ca.crt",
                    2 * 1024 * 1024),
            entry("ELMPAY_RISK_DATABASE_CLIENT_CERTIFICATE_FILE", "risk-database-mtls",
                    "tls.crt", 2 * 1024 * 1024),
            entry("ELMPAY_RISK_DATABASE_CLIENT_PRIVATE_KEY_FILE", "risk-database-mtls",
                    "tls.key", 64 * 1024),
            entry("ELMPAY_RISK_GOVERNANCE_POLICY_FILE", "risk-governance", "policy.json",
                    256 * 1024),
            entry("ELMPAY_RISK_CALLER_POLICY_FILE", "risk-governance", "callers.json",
                    256 * 1024));

    private RiskMountedFiles() { }

    static MountedPath configured(Map<String, String> environment, String key) {
        Binding binding = BINDINGS.get(key);
        if (binding == null) {
            throw new IllegalStateException(key + " is not an approved risk mount");
        }
        String raw = environment.get(key);
        if (raw == null || raw.isBlank()) {
            throw new IllegalStateException(key + " is required");
        }
        Path expectedRoot = SECRET_ROOT.resolve(binding.directory()).normalize();
        Path expected = expectedRoot.resolve(binding.filename()).normalize();
        Path configured = Path.of(raw).normalize();
        if (!configured.isAbsolute() || !configured.equals(expected)) {
            throw new IllegalStateException(key + " must use its fixed read-only mount path");
        }
        return new MountedPath(configured, expectedRoot, binding.filename(), binding.maximum());
    }

    static byte[] read(Map<String, String> environment, String key, int maximum)
            throws IOException {
        return read(configured(environment, key), maximum);
    }

    static byte[] read(MountedPath mounted, long maximum) throws IOException {
        Path real = inspect(mounted, maximum);
        try (var input = Files.newInputStream(real)) {
            byte[] value = input.readNBytes(Math.toIntExact(maximum + 1));
            if (value.length < 1 || value.length > maximum) {
                throw new IllegalStateException(mounted.filename() + " mount has an invalid size");
            }
            return value;
        }
    }

    static Path inspect(MountedPath mounted, long maximum) throws IOException {
        Objects.requireNonNull(mounted, "mounted");
        if (maximum < 1 || maximum > mounted.maximum()) {
            throw new IllegalArgumentException("risk mount bound exceeds its policy ceiling");
        }
        Path expected = mounted.mountRoot().resolve(mounted.filename()).normalize();
        if (!mounted.configured().equals(expected)) {
            throw new IllegalStateException("risk mount path changed after validation");
        }
        Path realRoot = mounted.mountRoot().toRealPath();
        Path real = mounted.configured().toRealPath();
        long size = Files.size(real);
        if (!real.startsWith(realRoot) || !Files.isRegularFile(real) || size < 1
                || size > maximum) {
            throw new IllegalStateException(mounted.filename()
                    + " escaped its mount or has an invalid type or size");
        }
        try {
            if (Files.getPosixFilePermissions(real).stream().anyMatch(WRITE::contains)) {
                throw new IllegalStateException(mounted.filename() + " mount must be read-only");
            }
        } catch (UnsupportedOperationException unsupported) {
            if (Files.isWritable(real)) {
                throw new IllegalStateException(mounted.filename() + " mount must be read-only",
                        unsupported);
            }
        }
        return real;
    }

    static MountedPath forTest(Path configured, Path mountRoot, String filename, long maximum) {
        Objects.requireNonNull(configured, "configured");
        Objects.requireNonNull(mountRoot, "mountRoot");
        return new MountedPath(configured.toAbsolutePath().normalize(),
                mountRoot.toAbsolutePath().normalize(), filename, maximum);
    }

    private static Map.Entry<String, Binding> entry(String key, String directory,
            String filename, long maximum) {
        return Map.entry(key, new Binding(directory, filename, maximum));
    }

    record MountedPath(Path configured, Path mountRoot, String filename, long maximum) {
        MountedPath {
            Objects.requireNonNull(configured, "configured");
            Objects.requireNonNull(mountRoot, "mountRoot");
            Objects.requireNonNull(filename, "filename");
            if (!configured.isAbsolute() || !mountRoot.isAbsolute()
                    || !filename.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
                    || maximum < 1) {
                throw new IllegalArgumentException("invalid risk mount binding");
            }
        }
    }

    private record Binding(String directory, String filename, long maximum) { }
}
