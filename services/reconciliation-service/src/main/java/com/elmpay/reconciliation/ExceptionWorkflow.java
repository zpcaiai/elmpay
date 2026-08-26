package com.elmpay.reconciliation;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Auditable exception tickets; financial adjustments require a distinct approver. */
public final class ExceptionWorkflow {
    public enum Status { OPEN, CLAIMED, ADJUSTMENT_PROPOSED, RESOLVED, REJECTED }
    public record Audit(String actor, String action, String reason, Instant at) {}
    public record Ticket(String id, String tenantId, String matchKey, Status status, String owner,
                         String proposer, String approver, long adjustmentMinor, String currency,
                         List<Audit> history, long version) {}
    private final Clock clock;
    private final Map<String, Ticket> tickets = new ConcurrentHashMap<>();
    public ExceptionWorkflow(Clock clock) { this.clock = java.util.Objects.requireNonNull(clock); }

    public Ticket open(String tenantId, String matchKey, String reason) {
        String id = UUID.randomUUID().toString();
        Ticket value = new Ticket(id, tenantId, matchKey, Status.OPEN, null, null, null, 0L, null,
                List.of(new Audit("system", "OPENED", reason, clock.instant())), 1L);
        tickets.put(key(tenantId, id), value); return value;
    }
    public Ticket claim(String tenantId, String ticketId, String actor) {
        return update(tenantId, ticketId, current -> {
            if (current.status() != Status.OPEN) throw new IllegalStateException("ticket already claimed");
            return copy(current, Status.CLAIMED, actor, null, null, 0, null, actor, "CLAIMED", "case ownership accepted");
        });
    }
    public Ticket proposeAdjustment(String tenantId, String ticketId, String actor, long amountMinor, String currency, String reason) {
        if (amountMinor == 0) throw new IllegalArgumentException("zero adjustment is meaningless");
        return update(tenantId, ticketId, current -> {
            if (current.status() != Status.CLAIMED || !actor.equals(current.owner())) throw new SecurityException("only case owner may propose adjustment");
            return copy(current, Status.ADJUSTMENT_PROPOSED, current.owner(), actor, null, amountMinor, currency,
                    actor, "ADJUSTMENT_PROPOSED", reason);
        });
    }
    public Ticket approve(String tenantId, String ticketId, String approver, String ledgerTransactionId, String reason) {
        final String normalizedLedgerTransactionId;
        try {
            normalizedLedgerTransactionId = UUID.fromString(ledgerTransactionId).toString();
        } catch (NullPointerException | IllegalArgumentException invalid) {
            throw new IllegalArgumentException("immutable ledger adjustment UUID required", invalid);
        }
        return update(tenantId, ticketId, current -> {
            if (current.status() != Status.ADJUSTMENT_PROPOSED) throw new IllegalStateException("no adjustment awaiting approval");
            if (approver.equals(current.proposer())) throw new SecurityException("proposer cannot approve adjustment");
            return copy(current, Status.RESOLVED, current.owner(), current.proposer(), approver,
                    current.adjustmentMinor(), current.currency(), approver,
                    "APPROVED:" + normalizedLedgerTransactionId, reason);
        });
    }
    public Ticket reject(String tenantId, String ticketId, String reviewer, String reason) {
        return update(tenantId, ticketId, current -> {
            if (current.status() != Status.ADJUSTMENT_PROPOSED) throw new IllegalStateException("only proposed adjustments may be rejected");
            return copy(current, Status.REJECTED, current.owner(), current.proposer(), reviewer,
                    current.adjustmentMinor(), current.currency(), reviewer, "REJECTED", reason);
        });
    }
    public Ticket get(String tenantId, String id) {
        Ticket value = tickets.get(key(tenantId, id)); if (value == null) throw new SecurityException("ticket not found"); return value;
    }
    private Ticket update(String tenant, String id, java.util.function.UnaryOperator<Ticket> op) {
        Ticket value = tickets.computeIfPresent(key(tenant, id), (ignored, old) -> op.apply(old));
        if (value == null) throw new SecurityException("ticket not found"); return value;
    }
    private Ticket copy(Ticket v, Status status, String owner, String proposer, String approver, long amount,
                        String currency, String actor, String action, String reason) {
        List<Audit> history = new ArrayList<>(v.history()); history.add(new Audit(actor, action, reason, clock.instant()));
        return new Ticket(v.id(), v.tenantId(), v.matchKey(), status, owner, proposer, approver, amount, currency,
                List.copyOf(history), v.version() + 1);
    }
    private static String key(String tenant, String id) { return tenant + "\u0000" + id; }
}
