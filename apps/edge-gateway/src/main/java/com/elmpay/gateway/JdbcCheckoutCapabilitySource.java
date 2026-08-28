package com.elmpay.gateway;

import com.elmpay.payment.checkout.CapabilityResolver;
import com.elmpay.payment.checkout.CheckoutCapabilitySource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL B62 capability resolver with tenant RLS and fail-closed health freshness. */
public final class JdbcCheckoutCapabilitySource implements CheckoutCapabilitySource {
    private static final Duration MAX_HEALTH_AGE = Duration.ofSeconds(90);
    private static final String SQL = """
            SELECT pa.id AS provider_account_id, pa.status, pc.method, pc.currencies,
                   pc.regions, pc.device_classes, rr.enabled, rr.priority,
                   rr.min_amount_minor, rr.max_amount_minor, ph.available, ph.observed_at
              FROM provider_account pa
              JOIN provider_capability pc
                ON pc.tenant_id=pa.tenant_id AND pc.provider_account_id=pa.id
              JOIN routing_rule rr
                ON rr.tenant_id=pa.tenant_id AND rr.project_id=pa.project_id
               AND rr.provider_account_id=pa.id
              LEFT JOIN provider_method_health ph
                ON ph.tenant_id=pa.tenant_id AND ph.project_id=pa.project_id
               AND ph.provider_account_id=pa.id AND ph.method=pc.method
             WHERE pa.tenant_id=? AND pa.project_id=? AND pa.merchant_id=?
               AND pc.method=ANY(?)
            """;

    private final DataSource dataSource;
    private final CapabilityResolver resolver = new CapabilityResolver();

    public JdbcCheckoutCapabilitySource(DataSource dataSource) {
        this.dataSource = java.util.Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public List<CapabilityResolver.Decision> resolve(Request request) {
        try (Connection connection = dataSource.getConnection()) {
            connection.setReadOnly(true);
            connection.setAutoCommit(false);
            try {
                setTenant(connection, request.tenantId());
                List<RouteDecision> routes = query(connection, request);
                connection.commit();
                return aggregate(request.signedMethods(), routes);
            } catch (SQLException | RuntimeException failure) {
                rollback(connection, failure);
                throw failure;
            }
        } catch (SQLException failure) {
            throw new IllegalStateException("checkout capability read model is unavailable",
                    failure);
        }
    }

    private List<RouteDecision> query(Connection connection, Request request) throws SQLException {
        List<RouteDecision> result = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement(SQL)) {
            statement.setObject(1, request.tenantId());
            statement.setObject(2, request.projectId());
            statement.setObject(3, request.merchantId());
            statement.setArray(4, connection.createArrayOf("text",
                    request.signedMethods().toArray(String[]::new)));
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    String method = rows.getString("method");
                    CapabilityResolver.Capability capability = new CapabilityResolver.Capability(
                            method, strings(rows, "regions"), strings(rows, "currencies"),
                            strings(rows, "device_classes"),
                            "active".equals(rows.getString("status"))
                                    && rows.getBoolean("enabled")
                                    && request.amountMinor() >= rows.getLong("min_amount_minor")
                                    && request.amountMinor() <= rows.getLong("max_amount_minor"),
                            rows.getInt("priority"));
                    java.sql.Timestamp observed = rows.getTimestamp("observed_at");
                    Map<String, CapabilityResolver.Health> health = observed == null ? Map.of()
                            : Map.of(method, new CapabilityResolver.Health(
                                    rows.getBoolean("available"), observed.toInstant()));
                    CapabilityResolver.Context context = new CapabilityResolver.Context(
                            request.region(), request.currency(), request.deviceClass(),
                            request.now(), MAX_HEALTH_AGE);
                    CapabilityResolver.Decision decision = resolver.resolve(List.of(capability),
                            health, context).getFirst();
                    result.add(new RouteDecision(method, rows.getInt("priority"), decision));
                }
            }
        }
        return result;
    }

    private static List<CapabilityResolver.Decision> aggregate(Set<String> methods,
            List<RouteDecision> routes) {
        Map<String, List<RouteDecision>> byMethod = new LinkedHashMap<>();
        methods.stream().sorted().forEach(method -> byMethod.put(method, new ArrayList<>()));
        routes.forEach(route -> byMethod.computeIfAbsent(route.method(), ignored ->
                new ArrayList<>()).add(route));
        List<RankedDecision> ranked = new ArrayList<>();
        byMethod.forEach((method, candidates) -> {
            RouteDecision winner = candidates.stream().filter(route -> route.decision().eligible())
                    .min(Comparator.comparingInt(RouteDecision::priority)).orElse(null);
            if (winner != null) {
                ranked.add(new RankedDecision(winner.priority(),
                        new CapabilityResolver.Decision(method, true, List.of())));
                return;
            }
            LinkedHashSet<String> reasons = new LinkedHashSet<>();
            candidates.stream().sorted(Comparator.comparingInt(RouteDecision::priority))
                    .forEach(route -> reasons.addAll(route.decision().reasons()));
            if (reasons.isEmpty()) {
                reasons.add("NO_CONFIGURED_ROUTE");
            }
            int priority = candidates.stream().mapToInt(RouteDecision::priority).min()
                    .orElse(Integer.MAX_VALUE);
            ranked.add(new RankedDecision(priority, new CapabilityResolver.Decision(method,
                    false, List.copyOf(reasons))));
        });
        return ranked.stream().sorted(Comparator
                        .comparing((RankedDecision value) -> !value.decision().eligible())
                        .thenComparingInt(RankedDecision::priority)
                        .thenComparing(value -> value.decision().method()))
                .map(RankedDecision::decision).toList();
    }

    private static Set<String> strings(ResultSet result, String column) throws SQLException {
        return Set.copyOf(java.util.Arrays.asList((String[]) result.getArray(column).getArray()));
    }

    private static void setTenant(Connection connection, UUID tenantId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT set_config('app.tenant_id', ?, true)")) {
            statement.setString(1, tenantId.toString());
            statement.execute();
        }
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private record RouteDecision(String method, int priority,
            CapabilityResolver.Decision decision) {}

    private record RankedDecision(int priority, CapabilityResolver.Decision decision) {}
}
