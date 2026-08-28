package com.elmpay.gateway;

import com.elmpay.payment.commerce.CommerceService;
import com.elmpay.payment.commerce.JdbcCommerceService;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;
import javax.sql.DataSource;

/** Production commerce runtime; local mode stays explicitly unavailable rather than in-memory. */
public final class CommerceRuntimeFactory {
    private CommerceRuntimeFactory() {}

    public static Optional<CommerceService> create(Map<String, String> environment) {
        if (!"postgres".equals(environment.get("ELMPAY_RUNTIME_MODE"))) {
            return Optional.empty();
        }
        DataSource dataSource = new DriverManagerDataSource(
                required(environment, "ELMPAY_DATABASE_URL"),
                required(environment, "ELMPAY_DATABASE_USER"),
                required(environment, "ELMPAY_DATABASE_PASSWORD"));
        return Optional.of(new JdbcCommerceService(dataSource, Clock.systemUTC()));
    }

    private static String required(Map<String, String> environment, String name) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for the commerce runtime");
        }
        return value;
    }
}
