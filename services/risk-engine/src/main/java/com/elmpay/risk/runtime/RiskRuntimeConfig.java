package com.elmpay.risk.runtime;

import com.elmpay.events.StrictJson;
import com.elmpay.risk.CanonicalDigest;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Fail-closed, bounded production settings; secret values are never accepted from env. */
public record RiskRuntimeConfig(InetSocketAddress businessAddress,
        InetSocketAddress healthAddress, URI signalEndpoint, URI signalReadiness,
        URI modelEndpoint, URI modelReadiness, Duration dependencyTimeout,
        Duration nonceTtl, Duration maximumSignalAge, BigDecimal modelReviewThreshold,
        BigDecimal modelBlockThreshold, String governancePolicyDigest,
        RiskCallerPolicy callerPolicy, String adminWorkerId, Duration adminCommandLease,
        Duration adminCommandPollInterval, String adminActionPolicyDigest,
        Instant adminActionPolicyValidUntil) {
    public static RiskRuntimeConfig fromEnvironment(Map<String, String> environment) {
        if (!"production".equals(environment.get("ELMPAY_RISK_MODE"))) {
            throw new IllegalStateException("ELMPAY_RISK_MODE must be production");
        }
        for (String forbidden : List.of("ELMPAY_RISK_DATABASE_PASSWORD",
                "ELMPAY_RISK_HMAC_SECRET", "ELMPAY_RISK_HMAC_SECRET_FILE",
                "ELMPAY_RISK_PRIVATE_KEY",
                "ELMPAY_RISK_CLIENT_PRIVATE_KEY")) {
            if (environment.containsKey(forbidden)) {
                throw new IllegalStateException(forbidden + " is forbidden; use a read-only mount");
            }
        }
        InetSocketAddress business = address(environment, "ELMPAY_RISK_BIND_HOST",
                "ELMPAY_RISK_PORT", 8443);
        InetSocketAddress health = address(environment, "ELMPAY_RISK_HEALTH_BIND_HOST",
                "ELMPAY_RISK_HEALTH_PORT", 9081);
        if (business.getPort() == health.getPort()
                && business.getHostString().equals(health.getHostString())) {
            throw new IllegalStateException("business and health listeners must be isolated");
        }
        URI signal = endpoint(environment, "ELMPAY_RISK_SIGNAL_ENDPOINT", "/v1/risk/signals");
        URI signalHealth = endpoint(environment, "ELMPAY_RISK_SIGNAL_READINESS_ENDPOINT",
                "/health/ready");
        URI model = endpoint(environment, "ELMPAY_RISK_MODEL_ENDPOINT", "/v1/risk/model-score");
        URI modelHealth = endpoint(environment, "ELMPAY_RISK_MODEL_READINESS_ENDPOINT",
                "/health/ready");
        sameOrigin(signal, signalHealth, "signal");
        sameOrigin(model, modelHealth, "model");
        Duration timeout = dependencyTimeout(environment);
        Duration nonce = Duration.ofSeconds(number(environment,
                "ELMPAY_RISK_NONCE_TTL_SECONDS", 30, 1, 120));
        Duration maximumAge = Duration.ofSeconds(number(environment,
                "ELMPAY_RISK_MAXIMUM_SIGNAL_AGE_SECONDS", 30, 1, 300));
        BigDecimal review = decimal(environment, "ELMPAY_RISK_MODEL_REVIEW_THRESHOLD");
        BigDecimal block = decimal(environment, "ELMPAY_RISK_MODEL_BLOCK_THRESHOLD");
        byte[] governance = readOnly(environment, "ELMPAY_RISK_GOVERNANCE_POLICY_FILE",
                256 * 1024);
        String policyDigest;
        GovernanceBinding governanceBinding;
        try {
            governanceBinding = governance(governance);
            policyDigest = CanonicalDigest.sha256(List.of("risk-governance-policy-v1",
                    strictUtf8(governance, "risk governance policy")));
        } finally {
            java.util.Arrays.fill(governance, (byte) 0);
        }
        byte[] encodedCallers = readOnly(environment, "ELMPAY_RISK_CALLER_POLICY_FILE",
                256 * 1024);
        RiskCallerPolicy callerPolicy;
        try {
            callerPolicy = RiskCallerPolicy.fromBytes(encodedCallers);
        } finally {
            java.util.Arrays.fill(encodedCallers, (byte) 0);
        }
        String workerId = required(environment, "ELMPAY_RISK_ADMIN_WORKER_ID");
        if (!workerId.matches("[A-Za-z0-9._:-]{8,128}")) {
            throw new IllegalStateException("ELMPAY_RISK_ADMIN_WORKER_ID is invalid");
        }
        Duration commandLease = Duration.ofSeconds(number(environment,
                "ELMPAY_RISK_ADMIN_COMMAND_LEASE_SECONDS", 30, 5, 60));
        Duration commandPoll = Duration.ofMillis(number(environment,
                "ELMPAY_RISK_ADMIN_COMMAND_POLL_MILLISECONDS", 250, 25, 5_000));
        return new RiskRuntimeConfig(business, health, signal, signalHealth, model, modelHealth,
                timeout, nonce, maximumAge, review, block, policyDigest, callerPolicy, workerId,
                commandLease, commandPoll, governanceBinding.adminActionPolicyDigest(),
                governanceBinding.validUntil());
    }

    static byte[] readOnly(Map<String, String> environment, String key, int maximum) {
        try {
            return RiskMountedFiles.read(environment, key, maximum);
        } catch (java.io.IOException failure) {
            throw new IllegalStateException(key + " cannot be read", failure);
        }
    }

    static Duration dependencyTimeout(Map<String, String> environment) {
        return Duration.ofMillis(number(environment,
                "ELMPAY_RISK_DEPENDENCY_TIMEOUT_MILLISECONDS", 100, 100, 100));
    }

    private static InetSocketAddress address(Map<String, String> environment, String hostKey,
            String portKey, int fallback) {
        String host = environment.getOrDefault(hostKey, "0.0.0.0");
        if (!Set.of("0.0.0.0", "127.0.0.1", "::").contains(host)) {
            throw new IllegalStateException(hostKey + " must be an explicit local bind address");
        }
        return new InetSocketAddress(host, Math.toIntExact(number(environment, portKey, fallback,
                1, 65_535)));
    }

    private static URI endpoint(Map<String, String> environment, String key, String path) {
        URI value = StrictHttpsTransport.exactHttps(URI.create(required(environment, key)));
        if (!path.equals(value.getRawPath())) throw new IllegalStateException(key + " path is invalid");
        return value;
    }

    private static void sameOrigin(URI left, URI right, String name) {
        int leftPort = left.getPort() < 0 ? 443 : left.getPort();
        int rightPort = right.getPort() < 0 ? 443 : right.getPort();
        if (!left.getHost().equalsIgnoreCase(right.getHost()) || leftPort != rightPort) {
            throw new IllegalStateException(name + " endpoints must share one exact origin");
        }
    }

    private static long number(Map<String, String> environment, String key, long fallback,
            long minimum, long maximum) {
        String raw = environment.get(key);
        long value;
        try { value = raw == null ? fallback : Long.parseLong(raw); }
        catch (NumberFormatException invalid) { throw new IllegalStateException(key + " invalid", invalid); }
        if (value < minimum || value > maximum) throw new IllegalStateException(key + " out of range");
        return value;
    }

    private static BigDecimal decimal(Map<String, String> environment, String key) {
        String raw = required(environment, key);
        if (!raw.matches("(?:0|1)(?:\\.[0-9]{1,18})?")) {
            throw new IllegalStateException(key + " must be a finite decimal string");
        }
        return new BigDecimal(raw);
    }

    private static GovernanceBinding governance(byte[] encoded) {
        Map<String, Object> value = StrictJson.object(strictUtf8(encoded,
                "risk governance policy"));
        if (!value.keySet().equals(Set.of("schemaVersion", "adminActionPolicyDigest",
                "validUntil")) || !Long.valueOf(1).equals(value.get("schemaVersion"))
                || !(value.get("adminActionPolicyDigest") instanceof String digest)
                || !digest.matches("[0-9a-f]{64}")
                || !(value.get("validUntil") instanceof String rawExpiry)) {
            throw new IllegalStateException("risk governance policy schema is invalid");
        }
        Instant expiry;
        try {
            expiry = Instant.parse(rawExpiry);
        } catch (RuntimeException invalid) {
            throw new IllegalStateException("risk governance policy expiry is invalid", invalid);
        }
        return new GovernanceBinding(digest, expiry);
    }

    private static String required(Map<String, String> environment, String key) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) throw new IllegalStateException(key + " is required");
        return value;
    }

    private static String strictUtf8(byte[] value, String label) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(value)).toString();
        } catch (java.nio.charset.CharacterCodingException invalid) {
            throw new IllegalStateException(label + " is not canonical UTF-8", invalid);
        }
    }

    private record GovernanceBinding(String adminActionPolicyDigest, Instant validUntil) { }
}
