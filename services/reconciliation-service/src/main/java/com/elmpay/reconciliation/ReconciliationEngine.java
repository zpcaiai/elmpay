package com.elmpay.reconciliation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Deterministic four-source matching without taking ownership of business orders. */
public final class ReconciliationEngine {
    public enum Source { BUSINESS, PLATFORM, PROVIDER, BANK }
    public enum Outcome { MATCHED, MISSING_SOURCE, AMOUNT_MISMATCH, DUPLICATE_SOURCE }
    public record Fact(Source source, String tenantId, String externalReference, String eventType,
                       long amountMinor, String currency, Instant occurredAt, String sourceDigest) {}
    public record Match(String key, Outcome outcome, Map<Source, Long> totals, Set<Source> missing,
                        Map<Source, Integer> counts) {}
    public record Run(String id, String tenantId, Instant cutoff, List<Match> matches,
                      long matched, long exceptions) {}

    public Run reconcile(String tenantId, Instant cutoff, List<Fact> facts) {
        Map<String, List<Fact>> groups = new HashMap<>();
        for (Fact fact : facts) {
            if (!fact.tenantId().equals(tenantId)) throw new SecurityException("cross-tenant reconciliation fact");
            if (fact.occurredAt().isAfter(cutoff)) continue;
            String key = fact.externalReference() + "\u0000" + fact.eventType() + "\u0000" + fact.currency();
            groups.computeIfAbsent(key, ignored -> new ArrayList<>()).add(fact);
        }
        List<Match> matches = groups.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(entry -> match(entry.getKey(), entry.getValue())).toList();
        long matched = matches.stream().filter(value -> value.outcome() == Outcome.MATCHED).count();
        return new Run(UUID.randomUUID().toString(), tenantId, cutoff, matches, matched, matches.size() - matched);
    }

    private static Match match(String key, List<Fact> facts) {
        Map<Source, Long> totals = new EnumMap<>(Source.class); Map<Source, Integer> counts = new EnumMap<>(Source.class);
        for (Fact fact : facts) {
            totals.merge(fact.source(), fact.amountMinor(), Math::addExact); counts.merge(fact.source(), 1, Math::addExact);
        }
        Set<Source> missing = java.util.Arrays.stream(Source.values()).filter(source -> !totals.containsKey(source))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        Outcome outcome;
        if (!missing.isEmpty()) outcome = Outcome.MISSING_SOURCE;
        else if (counts.values().stream().anyMatch(count -> count != 1)) outcome = Outcome.DUPLICATE_SOURCE;
        else if (totals.values().stream().distinct().count() != 1) outcome = Outcome.AMOUNT_MISMATCH;
        else outcome = Outcome.MATCHED;
        return new Match(key, outcome, Map.copyOf(totals), missing, Map.copyOf(counts));
    }
}
