package com.elmpay.payment.refund;

import com.elmpay.provider.VerifiedProviderEvidence;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/** Verified-provider-event driven dispute lifecycle with immutable evidence revisions. */
public final class DisputeService {
    public enum Status { OPEN, EVIDENCE_SUBMITTED, WON, LOST, ACCEPTED, APPEALED }
    public enum ProviderResult { WON, LOST, ACCEPTED, UNKNOWN }
    public record ProviderEvent(String tenantId, String provider, String providerEventId,
                                String providerDisputeId, String paymentId, long amountMinor,
                                String currency, Instant responseDeadline,
                                String providerResultDigest,
                                VerifiedProviderEvidence providerEvidence) {}
    public record Evidence(int revision, String sha256, String mediaType, String submittedBy, Instant submittedAt) {}
    public record Dispute(String tenantId, String provider, String providerDisputeId,
                          String paymentId, long amountMinor, String currency, Instant deadline,
                          Status status, List<Evidence> evidence) {}

    private static final String EVENT_EVIDENCE_TYPE = "PROVIDER_DISPUTE_EVENT";
    private static final String RESULT_EVIDENCE_TYPE = "PROVIDER_DISPUTE_RESULT";

    private final Clock clock;
    private final Map<String, Dispute> disputes = new ConcurrentHashMap<>();
    private final Map<String, String> inbox = new ConcurrentHashMap<>();

    public DisputeService(Clock clock) { this.clock = Objects.requireNonNull(clock, "clock"); }

    public synchronized Dispute ingest(ProviderEvent event) {
        Objects.requireNonNull(event, "event");
        require(event.tenantId()); require(event.provider()); require(event.providerEventId());
        require(event.providerDisputeId()); require(event.paymentId()); require(event.currency());
        Objects.requireNonNull(event.responseDeadline(), "responseDeadline");
        if (event.amountMinor() <= 0) throw new IllegalArgumentException("dispute amount must be positive");
        String providerDigest = providerDigest(event.providerResultDigest());
        Map<String, String> expectedEvidence = evidenceFields(event.tenantId(), event.provider(),
                event.providerEventId(), "received", providerDigest,
                "providerDisputeId", event.providerDisputeId(),
                "paymentId", event.paymentId(),
                "amountMinor", Long.toString(event.amountMinor()),
                "currency", event.currency(),
                "responseDeadline", event.responseDeadline().toString());
        requireEvidence(event.providerEvidence(), EVENT_EVIDENCE_TYPE, expectedEvidence);
        String eventKey = key(event.tenantId(), event.providerEventId());
        String priorDigest = inbox.get(eventKey);
        if (priorDigest != null) {
            if (!priorDigest.equals(providerDigest)) {
                throw new IllegalStateException("provider event identity conflict");
            }
            return get(event.tenantId(), event.providerDisputeId());
        }
        String disputeKey = key(event.tenantId(), event.providerDisputeId());
        Dispute result = disputes.compute(disputeKey, (ignored, existing) -> {
            if (existing == null) return new Dispute(event.tenantId(), event.provider(),
                    event.providerDisputeId(), event.paymentId(), event.amountMinor(),
                    event.currency(), event.responseDeadline(), Status.OPEN, List.of());
            if (!existing.paymentId().equals(event.paymentId()) || existing.amountMinor() != event.amountMinor()
                    || !existing.currency().equals(event.currency())
                    || !existing.provider().equals(event.provider()))
                throw new IllegalStateException("provider dispute identity conflict");
            return existing;
        });
        inbox.put(eventKey, providerDigest);
        return result;
    }

    public Dispute submitEvidence(String tenantId, String disputeId, String sha256, String mediaType, String actor) {
        return update(tenantId, disputeId, current -> {
            if (!clock.instant().isBefore(current.deadline())) throw new IllegalStateException("evidence deadline passed");
            if (sha256 == null || !sha256.matches("[0-9a-fA-F]{64}")) throw new IllegalArgumentException("evidence digest must be SHA-256 hex");
            List<Evidence> evidence = new ArrayList<>(current.evidence());
            evidence.add(new Evidence(evidence.size() + 1, sha256.toLowerCase(java.util.Locale.ROOT), mediaType, actor, clock.instant()));
            return copy(current, Status.EVIDENCE_SUBMITTED, evidence);
        });
    }

    public Dispute resolve(String tenantId, String disputeId, ProviderResult result,
                           String providerResultDigest,
                           VerifiedProviderEvidence providerEvidence) {
        Objects.requireNonNull(result, "result");
        String digest = providerDigest(providerResultDigest);
        return update(tenantId, disputeId, current -> {
            requireEvidence(providerEvidence, RESULT_EVIDENCE_TYPE,
                    evidenceFields(tenantId, current.provider(), disputeId,
                            wire(result), digest));
            if (result == ProviderResult.UNKNOWN) return current;
            Status terminal = switch (result) {
                case WON -> Status.WON;
                case LOST -> Status.LOST;
                case ACCEPTED -> Status.ACCEPTED;
                case UNKNOWN -> throw new IllegalStateException("unreachable provider result");
            };
            return copy(current, terminal, current.evidence());
        });
    }

    public Dispute appeal(String tenantId, String disputeId, String actor) {
        require(actor);
        return update(tenantId, disputeId, current -> {
            if (current.status() != Status.LOST) throw new IllegalStateException("only lost disputes may be appealed");
            return copy(current, Status.APPEALED, current.evidence());
        });
    }

    public Dispute get(String tenantId, String disputeId) {
        Dispute value = disputes.get(key(tenantId, disputeId));
        if (value == null) throw new SecurityException("dispute not found");
        return value;
    }

    private Dispute update(String tenantId, String disputeId, java.util.function.UnaryOperator<Dispute> operation) {
        String key = key(tenantId, disputeId);
        Dispute result = disputes.computeIfPresent(key, (ignored, current) -> operation.apply(current));
        if (result == null) throw new SecurityException("dispute not found");
        return result;
    }
    private static Dispute copy(Dispute value, Status status, List<Evidence> evidence) {
        return new Dispute(value.tenantId(), value.provider(), value.providerDisputeId(),
                value.paymentId(), value.amountMinor(), value.currency(), value.deadline(),
                status, List.copyOf(evidence));
    }
    private static Map<String, String> evidenceFields(String tenantId, String provider,
            String entityId, String result, String providerResultDigest, String... additional) {
        LinkedHashMap<String, String> fields = new LinkedHashMap<>();
        fields.put("tenantId", tenantId);
        fields.put("provider", provider);
        fields.put("entityId", entityId);
        fields.put("result", result);
        fields.put("providerResultDigest", providerResultDigest);
        if (additional.length % 2 != 0) throw new IllegalArgumentException("invalid evidence fields");
        for (int index = 0; index < additional.length; index += 2) {
            if (fields.putIfAbsent(additional[index], additional[index + 1]) != null)
                throw new IllegalArgumentException("duplicate evidence field");
        }
        return Map.copyOf(fields);
    }
    private static void requireEvidence(VerifiedProviderEvidence evidence, String evidenceType,
            Map<String, String> expectedFields) {
        if (evidence == null || !evidenceType.equals(evidence.evidenceType())
                || evidence.fields().size() != expectedFields.size())
            throw new SecurityException("verified provider evidence is required");
        for (Map.Entry<String, String> expected : expectedFields.entrySet()) {
            if (!expected.getValue().equals(evidence.fields().get(expected.getKey())))
                throw new SecurityException("provider evidence binding mismatch");
        }
    }
    private static String providerDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("provider result digest must be lowercase SHA-256 hex");
        return value;
    }
    private static String wire(ProviderResult value) {
        return value.name().toLowerCase(java.util.Locale.ROOT);
    }
    private static String key(String tenant, String id) { require(tenant); require(id); return tenant + "\u0000" + id; }
    private static void require(String value) { if (value == null || value.isBlank()) throw new IllegalArgumentException("required value missing"); }
}
