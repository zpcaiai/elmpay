package com.elmpay.risk.runtime;

import com.elmpay.events.StrictJson;
import com.elmpay.risk.CanonicalDigest;
import com.elmpay.risk.ModelScorer;
import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskDecision;
import com.elmpay.risk.RiskEngine;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.RiskOperation;
import com.elmpay.risk.RiskRequest;
import com.elmpay.risk.RiskRule;
import com.elmpay.risk.RuleSet;
import com.elmpay.risk.SignalSnapshot;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;

/** Durable nonce, idempotency, decision and transactional-outbox boundary. */
public final class JdbcRiskDecisionService implements RiskDecisionService {
    public static final class RejectedRequest extends RuntimeException {
        private static final long serialVersionUID = 1L;

        private final String code;
        RejectedRequest(String code) { super(code); this.code = code; }
        public String code() { return code; }
    }

    private static final String UNAVAILABLE_SIGNAL_VERSION = "unavailable";
    private static final String UNAVAILABLE_MODEL_VERSION = "unavailable";
    private final DataSource dataSource;
    private final SignalProvider signals;
    private final ModelProvider models;
    private final RiskEngine engine;
    private final Clock clock;
    private final Duration nonceTtl;
    private final SecureRandom random;

    public JdbcRiskDecisionService(DataSource dataSource, SignalProvider signals,
            ModelProvider models, RiskEngine engine, Clock clock, Duration nonceTtl) {
        this(dataSource, signals, models, engine, clock, nonceTtl, new SecureRandom());
    }

    JdbcRiskDecisionService(DataSource dataSource, SignalProvider signals,
            ModelProvider models, RiskEngine engine, Clock clock, Duration nonceTtl,
            SecureRandom random) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.signals = Objects.requireNonNull(signals, "signals");
        this.models = Objects.requireNonNull(models, "models");
        this.engine = Objects.requireNonNull(engine, "engine");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.nonceTtl = Objects.requireNonNull(nonceTtl, "nonceTtl");
        this.random = Objects.requireNonNull(random, "random");
        if (nonceTtl.isZero() || nonceTtl.isNegative()
                || nonceTtl.compareTo(Duration.ofMinutes(2)) > 0) {
            throw new IllegalArgumentException("nonce TTL must be within 1ms..2m");
        }
    }

    @Override
    public NonceChallenge issueNonce(NonceBinding binding, String callerSpiffeId) {
        validateBinding(binding);
        String caller = caller(callerSpiffeId);
        byte[] entropy = new byte[32];
        random.nextBytes(entropy);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(entropy);
        java.util.Arrays.fill(entropy, (byte) 0);
        String nonceDigest = CanonicalDigest.sha256(List.of("risk-nonce-v1", nonce));
        Instant issuedAt = clock.instant();
        Instant expiresAt = issuedAt.plus(nonceTtl);
        inTransaction(binding.tenantId(), connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO risk_runtime_nonce
                      (nonce_id, tenant_id, project_id, request_id, request_digest,
                       nonce_digest, caller_spiffe_digest, issued_at, expires_at)
                    VALUES (?::uuid, ?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?)
                    """)) {
                statement.setString(1, UUID.randomUUID().toString());
                statement.setString(2, binding.tenantId());
                statement.setString(3, binding.projectId());
                statement.setString(4, binding.requestId());
                statement.setString(5, binding.requestDigest());
                statement.setString(6, nonceDigest);
                statement.setString(7, callerDigest(caller));
                statement.setTimestamp(8, Timestamp.from(issuedAt));
                statement.setTimestamp(9, Timestamp.from(expiresAt));
                statement.executeUpdate();
            }
            return null;
        });
        return new NonceChallenge(nonce, expiresAt);
    }

    @Override
    public RiskDecision decide(RiskEvaluationRequest external, String nonce,
            String callerSpiffeId) {
        Objects.requireNonNull(external, "request");
        if (nonce == null || !nonce.matches("[A-Za-z0-9_-]{43}")) {
            throw new RejectedRequest("NONCE_INVALID");
        }
        String caller = caller(callerSpiffeId);
        RiskRequest request = RiskRequest.from(external);
        String nonceDigest = CanonicalDigest.sha256(List.of("risk-nonce-v1", nonce));
        preflightNonce(request, nonceDigest, callerDigest(caller));

        SignalSnapshot snapshot;
        boolean signalAvailable = true;
        try {
            snapshot = Objects.requireNonNull(signals.fetch(request), "signal snapshot");
        } catch (RuntimeException unavailable) {
            signalAvailable = false;
            Instant now = clock.instant();
            snapshot = new SignalSnapshot(request.tenantId(), request.projectId(),
                    request.requestId(), UNAVAILABLE_SIGNAL_VERSION, now, now.plusSeconds(1),
                    Map.of());
        }
        ModelScorer.ModelScore model;
        if (signalAvailable) {
            try {
                model = Objects.requireNonNull(models.score(request, snapshot), "model score");
            } catch (RuntimeException unavailable) {
                model = unavailableModel("MODEL_DEPENDENCY_UNAVAILABLE");
            }
        } else {
            model = unavailableModel("SIGNAL_DEPENDENCY_UNAVAILABLE");
        }
        SignalSnapshot persistedSnapshot = snapshot;
        ModelScorer.ModelScore persistedModel = model;
        boolean persistedSignalAvailable = signalAvailable;
        return inTransaction(request.tenantId(), connection -> {
            consumeNonce(connection, request, nonceDigest, callerDigest(caller));
            RiskDecision replay = findDecision(connection, request);
            if (replay != null) return replay;
            RuleSet rules;
            try {
                rules = loadActiveRules(connection, request);
            } catch (RuntimeException invalidRules) {
                rules = null;
            }
            RiskDecision decision = rules == null
                    ? unavailableDecision(request, persistedSnapshot, persistedModel,
                            "RULESET_UNAVAILABLE")
                    : engine.decide(request, persistedSnapshot, rules,
                            (ignoredRequest, ignoredSignals) -> persistedModel);
            persistSnapshot(connection, request, persistedSnapshot, persistedSignalAvailable);
            persistModel(connection, request, persistedSnapshot, persistedModel);
            insertDecision(connection, decision);
            appendOutbox(connection, decision);
            return decision;
        });
    }

    @Override
    public boolean ready() {
        try (Connection connection = dataSource.getConnection();
                PreparedStatement statement = connection.prepareStatement("""
                        SELECT to_regclass('risk_runtime_decision') IS NOT NULL
                           AND to_regclass('risk_runtime_nonce') IS NOT NULL
                           AND to_regclass('outbox_event') IS NOT NULL
                           AND EXISTS (SELECT 1 FROM risk_runtime_capability_health
                                        WHERE capability = 'risk_decision'
                                          AND valid_until > clock_timestamp())
                        """)) {
            statement.setQueryTimeout(2);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && result.getBoolean(1) && signals.ready() && models.ready();
            }
        } catch (SQLException | RuntimeException unavailable) {
            return false;
        }
    }

    private void preflightNonce(RiskRequest request, String nonceDigest, String callerDigest) {
        inTransaction(request.tenantId(), connection -> {
            try (PreparedStatement statement = connection.prepareStatement("""
                    SELECT 1 FROM risk_runtime_nonce
                     WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND request_id = ?
                       AND request_digest = ? AND nonce_digest = ? AND caller_spiffe_digest = ?
                       AND consumed_at IS NULL AND expires_at > ?
                    """)) {
                bindNonce(statement, request, nonceDigest, callerDigest);
                statement.setTimestamp(7, Timestamp.from(clock.instant()));
                try (ResultSet result = statement.executeQuery()) {
                    if (!result.next()) throw new RejectedRequest("NONCE_INVALID_OR_EXPIRED");
                }
            }
            return null;
        });
    }

    private void consumeNonce(Connection connection, RiskRequest request, String nonceDigest,
            String callerDigest) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE risk_runtime_nonce SET consumed_at = ?
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND request_id = ?
                   AND request_digest = ? AND nonce_digest = ? AND caller_spiffe_digest = ?
                   AND consumed_at IS NULL AND expires_at > ?
                """)) {
            Instant now = clock.instant();
            statement.setTimestamp(1, Timestamp.from(now));
            statement.setString(2, request.tenantId());
            statement.setString(3, request.projectId());
            statement.setString(4, request.requestId());
            statement.setString(5, request.requestDigest());
            statement.setString(6, nonceDigest);
            statement.setString(7, callerDigest);
            statement.setTimestamp(8, Timestamp.from(now));
            if (statement.executeUpdate() != 1) throw new RejectedRequest("NONCE_REPLAYED_OR_EXPIRED");
        }
    }

    private static void bindNonce(PreparedStatement statement, RiskRequest request,
            String nonceDigest, String callerDigest) throws SQLException {
        statement.setString(1, request.tenantId());
        statement.setString(2, request.projectId());
        statement.setString(3, request.requestId());
        statement.setString(4, request.requestDigest());
        statement.setString(5, nonceDigest);
        statement.setString(6, callerDigest);
    }

    private RiskDecision findDecision(Connection connection, RiskRequest request)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT * FROM risk_runtime_decision
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND request_id = ?
                 FOR SHARE
                """)) {
            statement.setString(1, request.tenantId());
            statement.setString(2, request.projectId());
            statement.setString(3, request.requestId());
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) return null;
                if (!request.requestDigest().equals(row.getString("request_digest"))) {
                    throw new RejectedRequest("IDEMPOTENCY_DIGEST_CONFLICT");
                }
                return decodeDecision(row);
            }
        }
    }

    private RuleSet loadActiveRules(Connection connection, RiskRequest request)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT rule_set_version, activated_at, rules_json::text, content_digest
                  FROM risk_runtime_rule_set
                 WHERE tenant_id = ?::uuid AND project_id = ?::uuid AND state = 'ACTIVE'
                   AND activated_at <= ? AND expires_at > ?
                 ORDER BY activated_at DESC LIMIT 1 FOR SHARE
                """)) {
            statement.setString(1, request.tenantId());
            statement.setString(2, request.projectId());
            Timestamp now = Timestamp.from(clock.instant());
            statement.setTimestamp(3, now);
            statement.setTimestamp(4, now);
            try (ResultSet row = statement.executeQuery()) {
                if (!row.next()) return null;
                return new RuleSet(request.tenantId(), request.projectId(),
                        row.getString("rule_set_version"),
                        row.getTimestamp("activated_at").toInstant(),
                        decodeRules(row.getString("rules_json")), row.getString("content_digest"));
            }
        }
    }

    private static List<RiskRule> decodeRules(String json) {
        Object parsed = StrictJson.parse(json);
        if (!(parsed instanceof List<?> values) || values.isEmpty() || values.size() > 256) {
            throw new IllegalArgumentException("stored risk rules schema is invalid");
        }
        List<RiskRule> rules = new ArrayList<>();
        Set<String> fields = Set.of("id", "version", "priority", "signal", "operator",
                "threshold", "action", "reasonCode");
        for (Object raw : values) {
            if (!(raw instanceof Map<?, ?> map) || !fields.equals(map.keySet())) {
                throw new IllegalArgumentException("stored risk rule schema is invalid");
            }
            rules.add(new RiskRule(string(map, "id"), string(map, "version"),
                    Math.toIntExact(integer(map, "priority")), string(map, "signal"),
                    RiskRule.Operator.valueOf(string(map, "operator")),
                    new BigDecimal(string(map, "threshold")),
                    RiskAction.valueOf(string(map, "action")), string(map, "reasonCode")));
        }
        return List.copyOf(rules);
    }

    private void persistSnapshot(Connection connection, RiskRequest request,
            SignalSnapshot snapshot, boolean available) throws SQLException {
        Map<String, String> values = snapshot.values().entrySet().stream().collect(
                java.util.stream.Collectors.toMap(Map.Entry::getKey,
                        entry -> entry.getValue().toPlainString()));
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO risk_runtime_signal_snapshot
                  (tenant_id, project_id, request_id, request_digest, signal_version,
                   content_digest, collected_at, expires_at, values_json, source_status)
                VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?::jsonb, ?)
                """)) {
            statement.setString(1, request.tenantId());
            statement.setString(2, request.projectId());
            statement.setString(3, request.requestId());
            statement.setString(4, request.requestDigest());
            statement.setString(5, snapshot.version());
            statement.setString(6, snapshot.contentDigest());
            statement.setTimestamp(7, Timestamp.from(snapshot.collectedAt()));
            statement.setTimestamp(8, Timestamp.from(snapshot.expiresAt()));
            statement.setString(9, StrictJson.canonical(values));
            statement.setString(10, available ? "AVAILABLE" : "UNAVAILABLE");
            statement.executeUpdate();
        }
    }

    private void persistModel(Connection connection, RiskRequest request,
            SignalSnapshot signals, ModelScorer.ModelScore model) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO risk_runtime_model_result
                  (tenant_id, project_id, request_id, request_digest, signal_digest,
                   model_version, content_digest, score_decimal, explanation_code, source_status,
                   evaluated_at)
                VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setString(1, request.tenantId());
            statement.setString(2, request.projectId());
            statement.setString(3, request.requestId());
            statement.setString(4, request.requestDigest());
            statement.setString(5, signals.contentDigest());
            statement.setString(6, model.version());
            statement.setString(7, model.contentDigest());
            statement.setString(8, model.score().toPlainString());
            statement.setString(9, model.explanationCode());
            statement.setString(10, model.available() ? "AVAILABLE" : "UNAVAILABLE");
            statement.setTimestamp(11, Timestamp.from(clock.instant()));
            statement.executeUpdate();
        }
    }

    private static void insertDecision(Connection connection, RiskDecision value)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO risk_runtime_decision
                  (tenant_id, project_id, request_id, request_digest, decision_id, operation,
                   subject_digest, action, reason_codes, rule_set_version, rule_set_digest,
                   signal_version, signal_digest, model_version, model_digest, degraded, decided_at)
                VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            int index = 1;
            statement.setString(index++, value.tenantId());
            statement.setString(index++, value.projectId());
            statement.setString(index++, value.requestId());
            statement.setString(index++, value.requestDigest());
            statement.setString(index++, value.decisionId());
            statement.setString(index++, value.operation().name());
            statement.setString(index++, value.subjectDigest());
            statement.setString(index++, value.action().name());
            statement.setString(index++, StrictJson.canonical(value.reasonCodes()));
            statement.setString(index++, value.ruleSetVersion());
            statement.setString(index++, value.ruleSetDigest());
            statement.setString(index++, value.signalVersion());
            statement.setString(index++, value.signalDigest());
            statement.setString(index++, value.modelVersion());
            statement.setString(index++, value.modelDigest());
            statement.setBoolean(index++, value.degraded());
            statement.setTimestamp(index, Timestamp.from(value.decidedAt()));
            statement.executeUpdate();
        }
    }

    private static RiskDecision decodeDecision(ResultSet row) throws SQLException {
        Object parsed = StrictJson.parse(row.getString("reason_codes"));
        if (!(parsed instanceof List<?> values)
                || values.stream().anyMatch(value -> !(value instanceof String))) {
            throw new SQLException("stored risk decision reasons are invalid");
        }
        List<String> reasons = values.stream().map(String.class::cast).toList();
        return new RiskDecision(row.getString("decision_id"), row.getString("tenant_id"),
                row.getString("project_id"), row.getString("request_id"),
                row.getString("request_digest"), RiskOperation.valueOf(row.getString("operation")),
                row.getString("subject_digest"), RiskAction.valueOf(row.getString("action")),
                reasons, row.getString("rule_set_version"), row.getString("rule_set_digest"),
                row.getString("signal_version"), row.getString("signal_digest"),
                row.getString("model_version"), row.getString("model_digest"),
                row.getBoolean("degraded"), row.getTimestamp("decided_at").toInstant());
    }

    private static void appendOutbox(Connection connection, RiskDecision decision)
            throws SQLException {
        UUID aggregateId = UUID.nameUUIDFromBytes(decision.decisionId()
                .getBytes(StandardCharsets.US_ASCII));
        long revision;
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO event_aggregate_revision
                  (tenant_id, aggregate_type, aggregate_id, current_revision, updated_at)
                VALUES (?::uuid, 'risk_decision', ?::uuid, 1, clock_timestamp())
                ON CONFLICT (tenant_id, aggregate_type, aggregate_id) DO UPDATE
                   SET current_revision = event_aggregate_revision.current_revision + 1,
                       updated_at = clock_timestamp()
                RETURNING current_revision
                """)) {
            statement.setString(1, decision.tenantId());
            statement.setString(2, aggregateId.toString());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) throw new SQLException("risk outbox revision was not allocated");
                revision = result.getLong(1);
            }
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("decision_id", decision.decisionId());
        payload.put("tenant_id", decision.tenantId());
        payload.put("project_id", decision.projectId());
        payload.put("request_id", decision.requestId());
        payload.put("request_digest", decision.requestDigest());
        payload.put("operation", decision.operation().name());
        payload.put("action", decision.action().name());
        payload.put("reason_codes", decision.reasonCodes());
        payload.put("rule_set_digest", decision.ruleSetDigest());
        payload.put("signal_digest", decision.signalDigest());
        payload.put("model_digest", decision.modelDigest());
        payload.put("degraded", decision.degraded());
        payload.put("decided_at", decision.decidedAt().toString());
        payload.put("aggregate_revision", revision);
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO outbox_event
                  (id, tenant_id, project_id, aggregate_type, aggregate_id, event_type,
                   event_version, aggregate_revision, payload, correlation_id, occurred_at,
                   recorded_at, trace_id, created_at)
                VALUES (?::uuid, ?::uuid, ?::uuid, 'risk_decision', ?::uuid,
                        'risk.decision.v1', 1, ?, ?::jsonb, ?, ?, clock_timestamp(), ?,
                        clock_timestamp())
                """)) {
            statement.setString(1, UUID.randomUUID().toString());
            statement.setString(2, decision.tenantId());
            statement.setString(3, decision.projectId());
            statement.setString(4, aggregateId.toString());
            statement.setLong(5, revision);
            statement.setString(6, StrictJson.canonical(payload));
            statement.setString(7, decision.requestId());
            statement.setTimestamp(8, Timestamp.from(decision.decidedAt()));
            statement.setString(9, decision.requestId());
            statement.executeUpdate();
        }
    }

    private RiskDecision unavailableDecision(RiskRequest request, SignalSnapshot signals,
            ModelScorer.ModelScore model, String reason) {
        String rulesDigest = CanonicalDigest.sha256(List.of("rules-unavailable"));
        String decisionId = CanonicalDigest.sha256(List.of(request.tenantId(), request.projectId(),
                request.requestId(), request.requestDigest(), rulesDigest, signals.contentDigest(),
                model.contentDigest(), RiskAction.REVIEW.name(), reason));
        return new RiskDecision(decisionId, request.tenantId(), request.projectId(),
                request.requestId(), request.requestDigest(), request.operation(),
                request.subjectDigest(), RiskAction.REVIEW, List.of(reason), "unavailable",
                rulesDigest, signals.version(), signals.contentDigest(), model.version(),
                model.contentDigest(), true, clock.instant());
    }

    private static ModelScorer.ModelScore unavailableModel(String reason) {
        return ModelScorer.ModelScore.unavailable(UNAVAILABLE_MODEL_VERSION,
                CanonicalDigest.sha256(List.of("model-unavailable", reason)), reason);
    }

    private <T> T inTransaction(String tenantId, SqlWork<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            connection.setAutoCommit(false);
            try {
                setTenant(connection, tenantId);
                T result = work.apply(connection);
                connection.commit();
                return result;
            } catch (SQLException | RuntimeException failure) {
                try { connection.rollback(); } catch (SQLException rollback) { failure.addSuppressed(rollback); }
                throw failure;
            } finally {
                try { connection.setAutoCommit(true); } catch (SQLException ignored) { }
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("risk database operation failed", failure);
        }
    }

    private static void setTenant(Connection connection, String tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId);
            statement.execute();
        }
    }

    private static void validateBinding(NonceBinding binding) {
        Objects.requireNonNull(binding, "binding");
        try {
            if (!UUID.fromString(binding.tenantId()).toString().equals(binding.tenantId())
                    || !UUID.fromString(binding.projectId()).toString().equals(binding.projectId())
                    || binding.requestId() == null || !binding.requestId().matches(
                            "[A-Za-z0-9][A-Za-z0-9._:-]{7,127}")
                    || binding.requestDigest() == null
                    || !binding.requestDigest().matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("invalid nonce binding");
            }
        } catch (IllegalArgumentException failure) {
            throw new RejectedRequest("NONCE_BINDING_INVALID");
        }
    }

    private static String caller(String value) {
        if (value == null || value.length() > 512 || !RiskCallerPolicy.canonicalSpiffe(value)) {
            throw new RejectedRequest("CALLER_IDENTITY_INVALID");
        }
        return value;
    }

    private static String callerDigest(String caller) {
        return CanonicalDigest.sha256(List.of("risk-caller-v1", caller));
    }

    private static String string(Map<?, ?> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalArgumentException("stored rule field is invalid: " + key);
        }
        return text;
    }

    private static long integer(Map<?, ?> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof Long number)) throw new IllegalArgumentException("rule integer invalid");
        return number;
    }

    @FunctionalInterface
    private interface SqlWork<T> { T apply(Connection connection) throws SQLException; }
}
