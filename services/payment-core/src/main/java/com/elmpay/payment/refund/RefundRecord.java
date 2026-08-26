package com.elmpay.payment.refund;

import com.elmpay.money.Money;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Durable refund aggregate. Only provider references and normalized digests are retained;
 * reusable payment tokens, PAN and raw provider payloads are outside this model.
 */
public record RefundRecord(UUID id, UUID tenantId, UUID projectId, UUID paymentIntentId,
        UUID providerAccountId, String provider, String providerPaymentId, Money amount,
        RefundReason reason, RefundStatus status, RefundRiskDecision riskDecision,
        String riskContextDigest, String requestIdempotencyKey, String requestDigest,
        String requesterId, String approverId, String approvalReason, String approvalTicketId,
        String providerRefundId, String providerOutcomeDigest, String failureCode,
        String correlationId, Instant createdAt, Instant updatedAt, long version) {
    public RefundRecord {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(projectId, "projectId");
        Objects.requireNonNull(paymentIntentId, "paymentIntentId");
        Objects.requireNonNull(providerAccountId, "providerAccountId");
        requireText(provider, "provider");
        requireText(providerPaymentId, "providerPaymentId");
        Objects.requireNonNull(amount, "amount");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(riskDecision, "riskDecision");
        requireDigest(riskContextDigest, "riskContextDigest");
        requireText(requestIdempotencyKey, "requestIdempotencyKey");
        requireDigest(requestDigest, "requestDigest");
        requireText(requesterId, "requesterId");
        requireText(correlationId, "correlationId");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (amount.amountMinor() <= 0 || version < 0 || updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("invalid refund amount or version timeline");
        }
        if (approverId != null && constantTimeEquals(requesterId, approverId)) {
            throw new IllegalArgumentException("refund requester cannot approve the same refund");
        }
        if ((approverId == null) != (approvalReason == null)
                || (approverId == null) != (approvalTicketId == null)) {
            throw new IllegalArgumentException("approval actor, reason and ticket are atomic");
        }
        if (riskDecision == RefundRiskDecision.REQUIRE_APPROVAL
                && status != RefundStatus.APPROVAL_PENDING && approverId == null
                && status != RefundStatus.FAILED && status != RefundStatus.CANCELED) {
            throw new IllegalArgumentException("policy-required refund lacks independent approval");
        }
        if (status == RefundStatus.SUCCEEDED) {
            requireText(providerRefundId, "providerRefundId");
            requireDigest(providerOutcomeDigest, "providerOutcomeDigest");
        }
        if (status == RefundStatus.UNKNOWN) {
            requireDigest(providerOutcomeDigest, "providerOutcomeDigest");
        } else if (status == RefundStatus.PROCESSING && providerOutcomeDigest != null) {
            requireDigest(providerOutcomeDigest, "providerOutcomeDigest");
        }
        if (status == RefundStatus.FAILED && (failureCode == null || failureCode.isBlank())) {
            throw new IllegalArgumentException("failed refund requires a normalized failure code");
        }
    }

    public static RefundRecord create(UUID id, RefundRequestCommand command,
            UUID projectId, UUID providerAccountId, String provider, String providerPaymentId,
            Money amount, RefundRiskDecision riskDecision, String requestDigest,
            String riskContextDigest, Instant now) {
        RefundStatus initial = switch (riskDecision) {
            case AUTO_APPROVE -> RefundStatus.PROCESSING;
            case REQUIRE_APPROVAL -> RefundStatus.APPROVAL_PENDING;
            case DENY -> RefundStatus.FAILED;
        };
        String failure = riskDecision == RefundRiskDecision.DENY ? "REFUND_RISK_DENIED" : null;
        return new RefundRecord(id, command.tenantId(), projectId, command.paymentIntentId(),
                providerAccountId, provider, providerPaymentId, amount, command.reason(), initial,
                riskDecision, riskContextDigest, command.idempotencyKey(), requestDigest,
                command.requesterId(), null, null, null, null, null, failure,
                command.correlationId(), now, now, 0);
    }

    public RefundRecord approve(RefundApprovalCommand command, Instant now) {
        if (status != RefundStatus.APPROVAL_PENDING || riskDecision != RefundRiskDecision.REQUIRE_APPROVAL) {
            throw new IllegalStateException("refund is not awaiting policy approval");
        }
        if (constantTimeEquals(requesterId, command.approverId())) {
            throw new SecurityException("refund requester cannot approve the same refund");
        }
        return new RefundRecord(id, tenantId, projectId, paymentIntentId, providerAccountId,
                provider, providerPaymentId, amount, reason, RefundStatus.PROCESSING,
                riskDecision, riskContextDigest, requestIdempotencyKey, requestDigest, requesterId,
                command.approverId(), command.reason(), command.ticketId(), providerRefundId,
                providerOutcomeDigest, null, command.correlationId(), createdAt, now, version + 1);
    }

    public RefundRecord providerResult(RefundStatus next, String nextProviderRefundId,
            String outcomeDigest, String normalizedFailureCode, String nextCorrelationId,
            Instant now) {
        if (status != RefundStatus.PROCESSING && status != RefundStatus.UNKNOWN) {
            throw new IllegalStateException("refund is not awaiting a provider outcome");
        }
        if (next != RefundStatus.SUCCEEDED && next != RefundStatus.FAILED
                && next != RefundStatus.UNKNOWN) {
            throw new IllegalArgumentException("invalid provider refund resolution");
        }
        return new RefundRecord(id, tenantId, projectId, paymentIntentId, providerAccountId,
                provider, providerPaymentId, amount, reason, next, riskDecision,
                riskContextDigest, requestIdempotencyKey, requestDigest, requesterId, approverId,
                approvalReason, approvalTicketId, nextProviderRefundId, outcomeDigest,
                normalizedFailureCode, nextCorrelationId, createdAt, now, version + 1);
    }

    public boolean sameRequestDigest(String expectedDigest) {
        return constantTimeEquals(requestDigest, expectedDigest);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }

    private static void requireDigest(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be a SHA-256 hex digest");
        }
    }

    private static boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) {
            return left == right;
        }
        return java.security.MessageDigest.isEqual(
                left.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                right.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
