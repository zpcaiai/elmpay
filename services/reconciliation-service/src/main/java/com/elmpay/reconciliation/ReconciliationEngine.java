package com.elmpay.reconciliation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Deterministic four-source matching without taking ownership of business orders. */
public final class ReconciliationEngine {
    public enum Source { BUSINESS, PLATFORM, PROVIDER, BANK }
    public enum Outcome { MATCHED, MISSING_SOURCE, AMOUNT_MISMATCH, DUPLICATE_SOURCE }
    public record Fact(Source source, String tenantId, String externalReference, String eventType,
                       long amountMinor, String currency, Instant occurredAt, String sourceDigest) {
        public Fact {
            java.util.Objects.requireNonNull(source, "source");
            UUID.fromString(tenantId);
            java.util.Objects.requireNonNull(occurredAt, "occurredAt");
            if (externalReference == null || !externalReference.matches("[0-9a-f]{64}")
                    || sourceDigest == null || !sourceDigest.matches("[0-9a-f]{64}")
                    || !Set.of("CAPTURE", "REFUND").contains(eventType)
                    || amountMinor <= 0 || currency == null
                    || !currency.matches("[A-Z]{3}")) {
                throw new IllegalArgumentException("invalid canonical reconciliation fact");
            }
        }
    }
    public record Match(String key, Outcome outcome, Map<Source, Long> totals, Set<Source> missing,
                        Map<Source, Integer> counts) {}
    public record Run(String id, String tenantId, Instant cutoff, List<Match> matches,
                      long matched, long exceptions) {}

    public Run reconcile(String tenantId, Instant cutoff, List<Fact> facts) {
        UUID.fromString(tenantId);
        java.util.Objects.requireNonNull(cutoff, "cutoff");
        facts = List.copyOf(facts);
        if (facts.size() > 1_000_000) {
            throw new IllegalArgumentException("reconciliation fact set exceeds the hard limit");
        }
        Map<String, List<Fact>> groups = new HashMap<>();
        for (Fact fact : facts) {
            if (!fact.tenantId().equals(tenantId)) throw new SecurityException("cross-tenant reconciliation fact");
            if (fact.occurredAt().isAfter(cutoff)) {
                throw new IllegalArgumentException(
                        "reconciliation fact occurs after the immutable cutoff");
            }
            String key = fact.externalReference() + ":" + fact.eventType() + ":"
                    + fact.currency();
            groups.computeIfAbsent(key, ignored -> new ArrayList<>()).add(fact);
        }
        List<Match> matches = groups.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(entry -> match(entry.getKey(), entry.getValue())).toList();
        long matched = matches.stream().filter(value -> value.outcome() == Outcome.MATCHED).count();
        return new Run(UUID.randomUUID().toString(), tenantId, cutoff, matches, matched, matches.size() - matched);
    }

    private static Match match(String key, List<Fact> facts) {
        Map<Source, Long> totals = new EnumMap<>(Source.class);
        Map<Source, Integer> counts = new EnumMap<>(Source.class);
        Map<Source, Set<String>> sourceRecords = new EnumMap<>(Source.class);
        boolean duplicate = false;
        for (Fact fact : facts) {
            totals.merge(fact.source(), fact.amountMinor(), Math::addExact);
            counts.merge(fact.source(), 1, Math::addExact);
            if (!sourceRecords.computeIfAbsent(fact.source(), ignored -> new HashSet<>())
                    .add(fact.sourceDigest())) {
                duplicate = true;
            }
        }
        Set<Source> missing = java.util.Arrays.stream(Source.values()).filter(source -> !totals.containsKey(source))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        Outcome outcome;
        if (!missing.isEmpty()) outcome = Outcome.MISSING_SOURCE;
        else if (duplicate) outcome = Outcome.DUPLICATE_SOURCE;
        else if (totals.values().stream().distinct().count() != 1) outcome = Outcome.AMOUNT_MISMATCH;
        else outcome = Outcome.MATCHED;
        return new Match(key, outcome, Map.copyOf(totals), missing, Map.copyOf(counts));
    }
}
