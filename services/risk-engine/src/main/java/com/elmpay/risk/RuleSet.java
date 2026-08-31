package com.elmpay.risk;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/** Immutable tenant/project-scoped and content-addressed deterministic rule set. */
public record RuleSet(String tenantId, String projectId, String version, Instant activatedAt,
        List<RiskRule> rules, String digest) {
    public RuleSet(String tenantId, String projectId, String version, Instant activatedAt,
            List<RiskRule> rules) {
        this(tenantId, projectId, version, activatedAt, normalized(rules),
                digest(tenantId, projectId, version, activatedAt, rules));
    }

    public RuleSet {
        requireText(tenantId, "tenantId");
        requireText(projectId, "projectId");
        requireText(version, "version");
        Objects.requireNonNull(activatedAt, "activatedAt");
        rules = normalized(rules);
        if (!digest(tenantId, projectId, version, activatedAt, rules).equals(digest)) {
            throw new IllegalArgumentException("rule-set digest does not match content");
        }
    }

    private static List<RiskRule> normalized(List<RiskRule> input) {
        Objects.requireNonNull(input, "rules");
        if (input.isEmpty() || input.size() > 256) {
            throw new IllegalArgumentException("a rule set must contain 1..256 rules");
        }
        var ids = new HashSet<String>();
        for (RiskRule rule : input) {
            Objects.requireNonNull(rule, "rule");
            if (!ids.add(rule.id())) {
                throw new IllegalArgumentException("duplicate rule id: " + rule.id());
            }
        }
        return input.stream().sorted(Comparator.comparingInt(RiskRule::priority).reversed()
                .thenComparing(RiskRule::id)).toList();
    }

    private static String digest(String tenantId, String projectId, String version,
            Instant activatedAt, List<RiskRule> input) {
        requireText(tenantId, "tenantId");
        requireText(projectId, "projectId");
        requireText(version, "version");
        Objects.requireNonNull(activatedAt, "activatedAt");
        var canonical = new ArrayList<String>();
        canonical.add(tenantId);
        canonical.add(projectId);
        canonical.add(version);
        canonical.add(activatedAt.toString());
        for (RiskRule rule : normalized(input)) {
            canonical.add(rule.id());
            canonical.add(rule.version());
            canonical.add(Integer.toString(rule.priority()));
            canonical.add(rule.signal());
            canonical.add(rule.operator().name());
            canonical.add(rule.threshold().toPlainString());
            canonical.add(rule.action().name());
            canonical.add(rule.reasonCode());
        }
        return CanonicalDigest.sha256(canonical);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 160) {
            throw new IllegalArgumentException(field + " is invalid");
        }
    }
}
