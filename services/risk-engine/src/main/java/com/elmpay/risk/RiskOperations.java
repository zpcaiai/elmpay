package com.elmpay.risk;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Tenant-scoped case and list mutations protected by four-eyes approval. */
public final class RiskOperations {
    public enum Kind {
        LIST_ADD,
        LIST_REMOVE,
        CASE_CLOSE
    }

    public enum Status {
        PENDING,
        APPROVED,
        REJECTED,
        EXPIRED
    }

    public record ApprovalRequest(
            String id,
            String tenantId,
            Kind kind,
            String subject,
            String reason,
            String proposedBy,
            String decidedBy,
            Status status,
            int version,
            Instant createdAt,
            Instant expiresAt,
            Instant decidedAt) { }

    public record AuditEntry(
            long sequence,
            String requestId,
            String event,
            String actor,
            Instant occurredAt,
            String previousHash,
            String hash) { }

    private final Clock clock;
    private final Map<String, ApprovalRequest> approvals = new HashMap<>();
    private final Map<String, Set<String>> lists = new HashMap<>();
    private final Map<String, Set<String>> closedCases = new HashMap<>();
    private final List<AuditEntry> audit = new ArrayList<>();

    public RiskOperations(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public synchronized ApprovalRequest propose(
            String tenantId,
            Kind kind,
            String subject,
            String reason,
            String actor,
            Instant expiresAt) {
        requireText(tenantId, "tenantId");
        Objects.requireNonNull(kind, "kind");
        requireText(subject, "subject");
        requireText(reason, "reason");
        requireText(actor, "actor");
        Instant now = clock.instant();
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (!expiresAt.isAfter(now)) {
            throw new IllegalArgumentException("approval expiry must be in the future");
        }
        String id = UUID.randomUUID().toString();
        ApprovalRequest request = new ApprovalRequest(
                id, tenantId, kind, subject, reason, actor, null,
                Status.PENDING, 1, now, expiresAt, null);
        approvals.put(id, request);
        appendAudit(request, "PROPOSED", actor, now);
        return request;
    }

    public synchronized ApprovalRequest approve(
            String tenantId, String requestId, String actor, int expectedVersion) {
        ApprovalRequest current = current(tenantId, requestId);
        requireText(actor, "actor");
        Instant now = clock.instant();
        current = expireIfNeeded(current, now);
        requirePendingAndVersion(current, expectedVersion);
        if (current.proposedBy().equals(actor)) {
            throw new SecurityException("the proposer cannot approve their own change");
        }
        apply(current);
        ApprovalRequest approved = transition(current, actor, Status.APPROVED, now);
        approvals.put(requestId, approved);
        appendAudit(approved, "APPROVED", actor, now);
        return approved;
    }

    public synchronized ApprovalRequest reject(
            String tenantId, String requestId, String actor, int expectedVersion) {
        ApprovalRequest current = current(tenantId, requestId);
        requireText(actor, "actor");
        Instant now = clock.instant();
        current = expireIfNeeded(current, now);
        requirePendingAndVersion(current, expectedVersion);
        if (current.proposedBy().equals(actor)) {
            throw new SecurityException("the proposer cannot decide their own change");
        }
        ApprovalRequest rejected = transition(current, actor, Status.REJECTED, now);
        approvals.put(requestId, rejected);
        appendAudit(rejected, "REJECTED", actor, now);
        return rejected;
    }

    public synchronized ApprovalRequest get(String tenantId, String requestId) {
        return expireIfNeeded(current(tenantId, requestId), clock.instant());
    }

    public synchronized boolean isListed(String tenantId, String subject) {
        requireText(tenantId, "tenantId");
        requireText(subject, "subject");
        return lists.getOrDefault(tenantId, Set.of()).contains(subject);
    }

    public synchronized boolean isCaseClosed(String tenantId, String caseId) {
        requireText(tenantId, "tenantId");
        requireText(caseId, "caseId");
        return closedCases.getOrDefault(tenantId, Set.of()).contains(caseId);
    }

    public synchronized List<AuditEntry> auditLog() {
        return List.copyOf(audit);
    }

    private ApprovalRequest current(String tenantId, String requestId) {
        requireText(tenantId, "tenantId");
        requireText(requestId, "requestId");
        ApprovalRequest current = approvals.get(requestId);
        if (current == null) {
            throw new IllegalArgumentException("unknown approval request");
        }
        if (!current.tenantId().equals(tenantId)) {
            throw new SecurityException("cross-tenant approval access is forbidden");
        }
        return current;
    }

    private ApprovalRequest expireIfNeeded(ApprovalRequest current, Instant now) {
        if (current.status() == Status.PENDING && !current.expiresAt().isAfter(now)) {
            ApprovalRequest expired = transition(current, "system", Status.EXPIRED, now);
            approvals.put(current.id(), expired);
            appendAudit(expired, "EXPIRED", "system", now);
            return expired;
        }
        return current;
    }

    private static void requirePendingAndVersion(ApprovalRequest current, int expectedVersion) {
        if (current.version() != expectedVersion) {
            throw new IllegalStateException("optimistic version conflict");
        }
        if (current.status() != Status.PENDING) {
            throw new IllegalStateException("approval is not pending: " + current.status());
        }
    }

    private void apply(ApprovalRequest request) {
        Set<String> tenantList = lists.computeIfAbsent(request.tenantId(), ignored -> new HashSet<>());
        switch (request.kind()) {
            case LIST_ADD -> tenantList.add(request.subject());
            case LIST_REMOVE -> tenantList.remove(request.subject());
            case CASE_CLOSE -> closedCases
                    .computeIfAbsent(request.tenantId(), ignored -> new HashSet<>())
                    .add(request.subject());
        }
    }

    private static ApprovalRequest transition(
            ApprovalRequest current, String actor, Status status, Instant now) {
        return new ApprovalRequest(
                current.id(), current.tenantId(), current.kind(), current.subject(),
                current.reason(), current.proposedBy(), actor, status,
                Math.addExact(current.version(), 1), current.createdAt(), current.expiresAt(), now);
    }

    private void appendAudit(ApprovalRequest request, String event, String actor, Instant now) {
        long sequence = audit.size() + 1L;
        String previous = audit.isEmpty() ? "GENESIS" : audit.get(audit.size() - 1).hash();
        String hash = CanonicalDigest.sha256(List.of(
                Long.toString(sequence), request.id(), request.tenantId(), request.kind().name(),
                request.subject(), request.reason(), request.proposedBy(), request.status().name(),
                Integer.toString(request.version()), event, actor, now.toString(), previous));
        audit.add(new AuditEntry(sequence, request.id(), event, actor, now, previous, hash));
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
