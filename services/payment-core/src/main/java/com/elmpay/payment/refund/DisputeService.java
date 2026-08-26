package com.elmpay.payment.refund;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/** Verified-provider-event driven dispute lifecycle with immutable evidence revisions. */
public final class DisputeService {
    public enum Status { OPEN, EVIDENCE_SUBMITTED, WON, LOST, ACCEPTED, APPEALED }
    public record ProviderEvent(String tenantId, String providerEventId, String providerDisputeId,
                                String paymentId, long amountMinor, String currency,
                                Instant responseDeadline, boolean signatureVerified) {}
    public record Evidence(int revision, String sha256, String mediaType, String submittedBy, Instant submittedAt) {}
    public record Dispute(String tenantId, String providerDisputeId, String paymentId, long amountMinor,
                          String currency, Instant deadline, Status status, List<Evidence> evidence) {}

    private final Clock clock;
    private final Map<String, Dispute> disputes = new ConcurrentHashMap<>();
    private final Map<String, Boolean> inbox = new ConcurrentHashMap<>();

    public DisputeService(Clock clock) { this.clock = Objects.requireNonNull(clock, "clock"); }

    public synchronized Dispute ingest(ProviderEvent event) {
        if (!event.signatureVerified()) throw new SecurityException("provider event must be verified before persistence");
        require(event.tenantId()); require(event.providerEventId()); require(event.providerDisputeId()); require(event.paymentId());
        if (event.amountMinor() <= 0) throw new IllegalArgumentException("dispute amount must be positive");
        String eventKey = key(event.tenantId(), event.providerEventId());
        if (inbox.containsKey(eventKey)) return get(event.tenantId(), event.providerDisputeId());
        String disputeKey = key(event.tenantId(), event.providerDisputeId());
        Dispute result = disputes.compute(disputeKey, (ignored, existing) -> {
            if (existing == null) return new Dispute(event.tenantId(), event.providerDisputeId(), event.paymentId(),
                    event.amountMinor(), event.currency(), event.responseDeadline(), Status.OPEN, List.of());
            if (!existing.paymentId().equals(event.paymentId()) || existing.amountMinor() != event.amountMinor()
                    || !existing.currency().equals(event.currency())) throw new IllegalStateException("provider dispute identity conflict");
            return existing;
        });
        inbox.put(eventKey, true);
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

    public Dispute resolve(String tenantId, String disputeId, Status result, boolean verifiedProviderResult) {
        if (!verifiedProviderResult) throw new SecurityException("unverified dispute result");
        if (result != Status.WON && result != Status.LOST && result != Status.ACCEPTED) throw new IllegalArgumentException("invalid terminal result");
        return update(tenantId, disputeId, current -> copy(current, result, current.evidence()));
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
        return new Dispute(value.tenantId(), value.providerDisputeId(), value.paymentId(), value.amountMinor(),
                value.currency(), value.deadline(), status, List.copyOf(evidence));
    }
    private static String key(String tenant, String id) { require(tenant); require(id); return tenant + "\u0000" + id; }
    private static void require(String value) { if (value == null || value.isBlank()) throw new IllegalArgumentException("required value missing"); }
}
