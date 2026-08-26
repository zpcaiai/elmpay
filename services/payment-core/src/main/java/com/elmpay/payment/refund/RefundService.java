package com.elmpay.payment.refund;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Concurrent-safe refund orchestration with amount reservation, idempotency,
 * four-eyes approval and explicit UNKNOWN provider outcomes.
 */
public final class RefundService {
    public enum Status { PENDING_APPROVAL, SUBMITTING, UNKNOWN, SUCCEEDED, FAILED, CANCELED }
    public enum RiskDecision { AUTO_APPROVE, MANUAL_REVIEW, DENY }
    public enum ProviderOutcome { SUCCEEDED, FAILED, UNKNOWN }

    public record Capture(String tenantId, String paymentId, long capturedMinor, String currency) {
        public Capture {
            required(tenantId, "tenantId"); required(paymentId, "paymentId"); required(currency, "currency");
            if (capturedMinor <= 0) throw new IllegalArgumentException("captured amount must be positive");
        }
    }
    public record Request(String idempotencyKey, long amountMinor, String requester, String reason) {
        public Request {
            required(idempotencyKey, "idempotencyKey"); required(requester, "requester"); required(reason, "reason");
            if (amountMinor <= 0) throw new IllegalArgumentException("refund amount must be positive");
        }
    }
    public record Refund(String id, String tenantId, String paymentId, String idempotencyKey,
                         long amountMinor, String currency, String requester, String approver,
                         Status status, String providerReference, String reason, Instant updatedAt) {}
    public record ProviderResult(ProviderOutcome outcome, String providerReference) {}
    public record AuditEvent(String refundId, String actor, String action, String reason, Instant at) {}

    @FunctionalInterface public interface RiskPolicy { RiskDecision decide(Capture capture, Request request); }
    public interface Provider {
        ProviderResult submit(Refund refund);
        ProviderResult query(Refund refund);
    }

    private static final class PaymentAggregate {
        private final Capture capture;
        private long reservedOrSucceeded;
        private PaymentAggregate(Capture capture) { this.capture = capture; }
        private synchronized void reserve(long amount) {
            if (amount > capture.capturedMinor() - reservedOrSucceeded) {
                throw new IllegalStateException("refund exceeds remaining refundable amount");
            }
            reservedOrSucceeded = Math.addExact(reservedOrSucceeded, amount);
        }
        private synchronized void release(long amount) { reservedOrSucceeded = Math.subtractExact(reservedOrSucceeded, amount); }
        private synchronized long remaining() { return capture.capturedMinor() - reservedOrSucceeded; }
    }

    private final Clock clock;
    private final RiskPolicy riskPolicy;
    private final Provider provider;
    private final Map<String, PaymentAggregate> payments = new ConcurrentHashMap<>();
    private final Map<String, Refund> refunds = new ConcurrentHashMap<>();
    private final Map<String, String> idempotency = new ConcurrentHashMap<>();
    private final List<AuditEvent> audit = java.util.Collections.synchronizedList(new ArrayList<>());

    public RefundService(Clock clock, RiskPolicy riskPolicy, Provider provider) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.riskPolicy = Objects.requireNonNull(riskPolicy, "riskPolicy");
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    public void registerCapture(Capture capture) {
        String key = paymentKey(capture.tenantId(), capture.paymentId());
        Capture existing = Optional.ofNullable(payments.putIfAbsent(key, new PaymentAggregate(capture)))
                .map(value -> value.capture).orElse(null);
        if (existing != null && !existing.equals(capture)) throw new IllegalStateException("capture identity conflict");
    }

    public synchronized Refund request(String tenantId, String paymentId, Request request) {
        PaymentAggregate aggregate = requirePayment(tenantId, paymentId);
        String idemKey = paymentKey(tenantId, paymentId) + ":" + request.idempotencyKey();
        String existingId = idempotency.get(idemKey);
        if (existingId != null) return requireSameRequest(refunds.get(existingId), request);

        RiskDecision decision = riskPolicy.decide(aggregate.capture, request);
        if (decision == RiskDecision.DENY) {
            audit.add(new AuditEvent("denied", request.requester(), "REFUND_DENIED", request.reason(), clock.instant()));
            throw new SecurityException("refund denied by risk policy");
        }
        aggregate.reserve(request.amountMinor());
        String id = UUID.randomUUID().toString();
        Status initial = decision == RiskDecision.MANUAL_REVIEW ? Status.PENDING_APPROVAL : Status.SUBMITTING;
        Refund created = new Refund(id, tenantId, paymentId, request.idempotencyKey(), request.amountMinor(),
                aggregate.capture.currency(), request.requester(), null, initial, null, request.reason(), clock.instant());
        String raced = idempotency.putIfAbsent(idemKey, id);
        if (raced != null) {
            aggregate.release(request.amountMinor());
            return requireSameRequest(refunds.get(raced), request);
        }
        refunds.put(id, created);
        audit.add(new AuditEvent(id, request.requester(), "REFUND_REQUESTED", request.reason(), clock.instant()));
        return initial == Status.SUBMITTING ? submit(created) : created;
    }

    public synchronized Refund approve(String tenantId, String refundId, String approver, String reason) {
        required(approver, "approver"); required(reason, "reason");
        Refund current = get(tenantId, refundId);
        if (current.status() != Status.PENDING_APPROVAL) throw new IllegalStateException("refund is not awaiting approval");
        if (MessageEquality.equal(current.requester(), approver)) throw new SecurityException("requester cannot approve refund");
        Refund approved = replace(current, Status.SUBMITTING, approver, current.providerReference());
        refunds.put(refundId, approved);
        audit.add(new AuditEvent(refundId, approver, "REFUND_APPROVED", reason, clock.instant()));
        return submit(approved);
    }

    public synchronized Refund cancel(String tenantId, String refundId, String actor, String reason) {
        Refund current = get(tenantId, refundId);
        if (current.status() != Status.PENDING_APPROVAL) throw new IllegalStateException("only unsubmitted refunds can be canceled");
        requirePayment(tenantId, current.paymentId()).release(current.amountMinor());
        Refund canceled = replace(current, Status.CANCELED, current.approver(), current.providerReference());
        refunds.put(refundId, canceled);
        audit.add(new AuditEvent(refundId, actor, "REFUND_CANCELED", reason, clock.instant()));
        return canceled;
    }

    public synchronized Refund recoverUnknown(String tenantId, String refundId, String actor) {
        Refund current = get(tenantId, refundId);
        if (current.status() != Status.UNKNOWN) throw new IllegalStateException("refund outcome is not unknown");
        Refund recovered = applyProviderResult(current, provider.query(current));
        refunds.put(refundId, recovered);
        audit.add(new AuditEvent(refundId, actor, "REFUND_QUERIED", recovered.status().name(), clock.instant()));
        return recovered;
    }

    public Refund get(String tenantId, String refundId) {
        Refund value = refunds.get(refundId);
        if (value == null || !MessageEquality.equal(value.tenantId(), tenantId)) throw new SecurityException("refund not found");
        return value;
    }
    public long remainingRefundable(String tenantId, String paymentId) { return requirePayment(tenantId, paymentId).remaining(); }
    public List<AuditEvent> auditEvents() { synchronized (audit) { return List.copyOf(audit); } }

    private synchronized Refund submit(Refund current) {
        ProviderResult result;
        try { result = provider.submit(current); }
        catch (RuntimeException timeoutOrTransport) { result = new ProviderResult(ProviderOutcome.UNKNOWN, null); }
        Refund updated = applyProviderResult(current, result);
        refunds.put(current.id(), updated);
        audit.add(new AuditEvent(current.id(), "system", "PROVIDER_REFUND_RESULT", updated.status().name(), clock.instant()));
        return updated;
    }

    private Refund applyProviderResult(Refund current, ProviderResult result) {
        Status next = switch (result.outcome()) {
            case SUCCEEDED -> Status.SUCCEEDED;
            case UNKNOWN -> Status.UNKNOWN;
            case FAILED -> Status.FAILED;
        };
        if (next == Status.FAILED && current.status() != Status.FAILED) {
            requirePayment(current.tenantId(), current.paymentId()).release(current.amountMinor());
        }
        return replace(current, next, current.approver(), result.providerReference());
    }

    private Refund replace(Refund value, Status status, String approver, String providerReference) {
        return new Refund(value.id(), value.tenantId(), value.paymentId(), value.idempotencyKey(), value.amountMinor(),
                value.currency(), value.requester(), approver, status, providerReference, value.reason(), clock.instant());
    }
    private PaymentAggregate requirePayment(String tenantId, String paymentId) {
        PaymentAggregate value = payments.get(paymentKey(tenantId, paymentId));
        if (value == null) throw new IllegalArgumentException("captured payment not found");
        return value;
    }
    private static Refund requireSameRequest(Refund refund, Request request) {
        if (refund.amountMinor() != request.amountMinor() || !MessageEquality.equal(refund.reason(), request.reason())
                || !MessageEquality.equal(refund.requester(), request.requester())) {
            throw new IllegalStateException("idempotency key reused with different refund request");
        }
        return refund;
    }
    private static String paymentKey(String tenantId, String paymentId) { return tenantId + "\u0000" + paymentId; }
    private static void required(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
    }
    private static final class MessageEquality {
        private MessageEquality() {}
        static boolean equal(String left, String right) {
            return java.security.MessageDigest.isEqual(String.valueOf(left).getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    String.valueOf(right).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }
}
