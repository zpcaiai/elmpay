package com.elmpay.reconciliation;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Reproducible financial projections with a digest-bound signed export manifest. */
public final class FinancialReportService {
    public enum Type { CAPTURE, FEE, REFUND, CHARGEBACK, SETTLEMENT, EXCEPTION }
    public record Fact(String id, String tenantId, Type type, long amountMinor, String currency, Instant effectiveAt) {}
    public record Totals(long gmvMinor, long feeMinor, long refundMinor, long chargebackMinor,
                         long settlementMinor, long exceptionMinor, long netRevenueMinor) {}
    public record Report(String tenantId, Instant from, Instant to, Map<String, Totals> byCurrency,
                         String sourceDigest, String signingKeyVersion,
                         String manifestSignature) {}

    private final ExportManifestSigner signer;
    public FinancialReportService(ExportManifestSigner signer) {
        this.signer = java.util.Objects.requireNonNull(signer, "signer");
        if (!signer.ready()) {
            throw new IllegalStateException("financial export signer is not ready");
        }
    }

    public Report generate(String tenantId, Instant from, Instant to, List<Fact> sourceFacts) {
        List<Fact> facts = sourceFacts.stream().filter(f -> {
            if (!f.tenantId().equals(tenantId)) throw new SecurityException("cross-tenant report fact");
            return !f.effectiveAt().isBefore(from) && f.effectiveAt().isBefore(to);
        }).sorted(Comparator.comparing(Fact::id)).toList();
        Map<String, long[]> accumulators = new TreeMap<>();
        for (Fact fact : facts) {
            long[] values = accumulators.computeIfAbsent(fact.currency(), ignored -> new long[6]);
            int index = switch (fact.type()) { case CAPTURE -> 0; case FEE -> 1; case REFUND -> 2;
                case CHARGEBACK -> 3; case SETTLEMENT -> 4; case EXCEPTION -> 5; };
            values[index] = Math.addExact(values[index], fact.amountMinor());
        }
        Map<String, Totals> totals = new TreeMap<>();
        accumulators.forEach((currency, v) -> {
            long net = Math.addExact(Math.subtractExact(Math.subtractExact(
                    Math.subtractExact(v[0], v[1]), v[2]), v[3]), v[5]);
            totals.put(currency, new Totals(v[0], v[1], v[2], v[3], v[4], v[5], net));
        });
        String digest = digestFacts(facts);
        String manifest = canonicalManifest(tenantId, from, to, totals, digest);
        ExportManifestSigner.Signature signature = signer.sign(
                manifest.getBytes(StandardCharsets.UTF_8));
        return new Report(tenantId, from, to, Map.copyOf(totals), digest,
                signature.keyVersion(), signature.value());
    }

    public boolean verify(Report report) {
        String canonical = canonicalManifest(report.tenantId(), report.from(), report.to(),
                report.byCurrency(), report.sourceDigest());
        return signer.verify(report.signingKeyVersion(),
                canonical.getBytes(StandardCharsets.UTF_8), report.manifestSignature());
    }

    private static String canonicalManifest(String tenant, Instant from, Instant to, Map<String, Totals> totals, String digest) {
        StringBuilder result = new StringBuilder("elmpay-financial-report-v1");
        append(result, tenant); append(result, from.toString()); append(result, to.toString()); append(result, digest);
        new TreeMap<>(totals).forEach((currency, value) -> { append(result, currency); append(result, Long.toString(value.gmvMinor()));
            append(result, Long.toString(value.feeMinor())); append(result, Long.toString(value.refundMinor()));
            append(result, Long.toString(value.chargebackMinor())); append(result, Long.toString(value.settlementMinor()));
            append(result, Long.toString(value.exceptionMinor())); append(result, Long.toString(value.netRevenueMinor())); });
        return result.toString();
    }
    private static String digestFacts(List<Fact> facts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (Fact fact : facts) { digest.update(canonicalFact(fact).getBytes(StandardCharsets.UTF_8)); }
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
        } catch (GeneralSecurityException unavailable) { throw new IllegalStateException(unavailable); }
    }
    private static String canonicalFact(Fact fact) {
        StringBuilder result = new StringBuilder(); append(result, fact.id()); append(result, fact.tenantId());
        append(result, fact.type().name()); append(result, Long.toString(fact.amountMinor())); append(result, fact.currency());
        append(result, fact.effectiveAt().toString()); return result.toString();
    }
    private static void append(StringBuilder target, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8); target.append(bytes.length).append(':').append(value);
    }
}
