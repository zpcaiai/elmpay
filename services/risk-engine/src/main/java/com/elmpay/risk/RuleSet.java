package com.elmpay.risk;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/** Immutable and content-addressed collection of deterministic rules. */
public record RuleSet(
        String tenantId,
        String version,
        Instant activatedAt,
        List<RiskRule> rules,
        String digest) {

    public RuleSet(String tenantId, String version, Instant activatedAt, List<RiskRule> rules) {
        this(tenantId, version, activatedAt, normalized(rules),
                digest(tenantId, version, activatedAt, rules));
    }

    public RuleSet {
        requireText(tenantId, "tenantId");
        requireText(version, "version");
        Objects.requireNonNull(activatedAt, "activatedAt");
        rules = normalized(rules);
        String calculated = digest(tenantId, version, activatedAt, rules);
        if (!calculated.equals(digest)) {
            throw new IllegalArgumentException("rule-set digest does not match content");
        }
    }

    private static List<RiskRule> normalized(List<RiskRule> input) {
        Objects.requireNonNull(input, "rules");
        if (input.isEmpty()) {
            throw new IllegalArgumentException("a rule set must contain at least one rule");
        }
        var ids = new HashSet<String>();
        for (RiskRule rule : input) {
            Objects.requireNonNull(rule, "rule");
            if (!ids.add(rule.id())) {
                throw new IllegalArgumentException("duplicate rule id: " + rule.id());
            }
        }
        return input.stream()
                .sorted(Comparator.comparingInt(RiskRule::priority).reversed()
                        .thenComparing(RiskRule::id))
                .toList();
    }

    private static String digest(
            String tenantId, String version, Instant activatedAt, List<RiskRule> input) {
        requireText(tenantId, "tenantId");
        requireText(version, "version");
        Objects.requireNonNull(activatedAt, "activatedAt");
        List<RiskRule> normalized = normalized(input);
        var canonical = new ArrayList<String>();
        canonical.add(tenantId);
        canonical.add(version);
        canonical.add(activatedAt.toString());
        for (RiskRule rule : normalized) {
            canonical.add(rule.id());
            canonical.add(rule.version());
            canonical.add(Integer.toString(rule.priority()));
            canonical.add(rule.signal());
            canonical.add(rule.operator().name());
            canonical.add(Double.toHexString(rule.threshold()));
            canonical.add(rule.action().name());
            canonical.add(rule.reasonCode());
        }
        return CanonicalDigest.sha256(canonical);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
