package com.elmpay.payment.refund;

import com.elmpay.idempotency.RequestFingerprint;
import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.ProviderAccount;
import com.elmpay.money.Money;
import com.elmpay.payment.AttemptOperation;
import com.elmpay.payment.AttemptState;
import com.elmpay.payment.PaymentAttempt;
import com.elmpay.payment.PaymentCoreException;
import com.elmpay.payment.PaymentIntent;
import com.elmpay.payment.PaymentRepository;
import com.elmpay.payment.ProviderAdapterRegistry;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderRefund;
import com.elmpay.provider.ProviderRequestContext;
import com.elmpay.provider.RefundCommand;
import com.elmpay.security.CanonicalPayload;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Durable B64/B65 refund orchestration. Every money movement is reserved before dispatch,
 * provider uncertainty remains explicit, and only exact server-side results can succeed.
 */
public final class RefundApplicationService {
    private static final String APPROVE_OPERATION = "REFUND_APPROVE";
    private static final String QUERY_OPERATION = "REFUND_QUERY";

    private final RefundRepository refunds;
    private final PaymentRepository payments;
    private final MerchantConfigurationRepository merchantConfiguration;
    private final ProviderAdapterRegistry adapters;
    private final RefundRiskPolicy riskPolicy;
    private final RefundChannelPolicy channelPolicy;
    private final Clock clock;
    private final Duration recoveryDelay;

    public RefundApplicationService(RefundRepository refunds, PaymentRepository payments,
            MerchantConfigurationRepository merchantConfiguration,
            ProviderAdapterRegistry adapters, RefundRiskPolicy riskPolicy,
            RefundChannelPolicy channelPolicy, Clock clock, Duration recoveryDelay) {
        this.refunds = Objects.requireNonNull(refunds, "refunds");
        this.payments = Objects.requireNonNull(payments, "payments");
        this.merchantConfiguration = Objects.requireNonNull(
                merchantConfiguration, "merchantConfiguration");
        this.adapters = Objects.requireNonNull(adapters, "adapters");
        this.riskPolicy = Objects.requireNonNull(riskPolicy, "riskPolicy");
        this.channelPolicy = Objects.requireNonNull(channelPolicy, "channelPolicy");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.recoveryDelay = Objects.requireNonNull(recoveryDelay, "recoveryDelay");
        if (recoveryDelay.isNegative()) {
            throw new IllegalArgumentException("recoveryDelay cannot be negative");
        }
    }

    public RefundRecord request(RefundRequestCommand command) {
        Objects.requireNonNull(command, "command");
        RequestFingerprint.validateKey(command.idempotencyKey());
        PaymentIntent intent = requireIntent(command.tenantId(), command.paymentIntentId());
        if (intent.capturedAmountMinor() <= 0) {
            throw new PaymentCoreException("REFUND_NOT_ALLOWED",
                    "payment intent has no captured amount to refund");
        }
        Money amount = Money.of(command.amountMinor(), intent.amount().currency().code());
        String requestDigest = requestDigest(command, intent, amount);
        RefundRecord replay = refunds.findByRequestKey(command.tenantId(),
                command.idempotencyKey()).orElse(null);
        if (replay != null) {
            requireSameRequest(replay, requestDigest);
            return requireNotDenied(replay);
        }

        PaymentAttempt source = sourceAttempt(intent);
        ProviderAccount account = requireAccount(intent, source.providerAccountId());
        if (!account.status().permitsRefunds()) {
            throw new PaymentCoreException("PROVIDER_ACCOUNT_REFUND_DISABLED",
                    "provider account is not permitted to issue refunds");
        }
        channelPolicy.validate(account, intent, command.amountMinor(), command.reason());
        Instant now = clock.instant();
        RefundRiskDecision decision = Objects.requireNonNull(riskPolicy.decide(
                new RefundRiskPolicy.Context(intent, command, now)),
                "refund risk decision is missing");
        String riskContextDigest = CanonicalPayload.sha256Hex(Map.ofEntries(
                Map.entry("tenant_id", intent.tenantId().toString()),
                Map.entry("project_id", intent.projectId().toString()),
                Map.entry("merchant_id", intent.merchantId().toString()),
                Map.entry("payment_intent_id", intent.id().toString()),
                Map.entry("amount_minor", amount.amountMinor()),
                Map.entry("currency", amount.currency().code()),
                Map.entry("reason", command.reason().wireValue()),
                Map.entry("requester_id", command.requesterId()),
                Map.entry("device_context_digest", command.deviceContextDigest()),
                Map.entry("decision", decision.name())));
        RefundRecord proposed = RefundRecord.create(UUID.randomUUID(), command,
                intent.projectId(), account.id(), account.provider(),
                source.providerTransactionId(), amount, decision, requestDigest,
                riskContextDigest, now);
        String eventType = decision == RefundRiskDecision.DENY
                ? "refund.request.denied.v1" : "refund.requested.v1";
        RefundRepository.WriteResult result = refunds.createAndReserve(proposed,
                intent.capturedAmountMinor(), intent.refundedAmountMinor(), eventType);
        RefundRecord created = requireNotDenied(result.refund());
        if (result.replay() || created.status() == RefundStatus.APPROVAL_PENDING) {
            return created;
        }
        return submit(created);
    }

    public RefundRecord approve(RefundApprovalCommand command) {
        Objects.requireNonNull(command, "command");
        RequestFingerprint.validateKey(command.idempotencyKey());
        String digest = CanonicalPayload.sha256Hex(Map.ofEntries(
                Map.entry("operation", APPROVE_OPERATION),
                Map.entry("refund_id", command.refundId().toString()),
                Map.entry("approver_id", command.approverId()),
                Map.entry("reason", command.reason()),
                Map.entry("ticket_id", command.ticketId())));
        RefundActionReceipt replay = refunds.findActionReceipt(command.tenantId(),
                command.refundId(), command.idempotencyKey()).orElse(null);
        if (replay != null) {
            requireSameAction(replay, APPROVE_OPERATION, digest);
            return requireRefund(command.tenantId(), command.refundId());
        }
        RefundRecord current = requireRefund(command.tenantId(), command.refundId());
        RefundRecord approved;
        try {
            approved = current.approve(command, clock.instant());
        } catch (SecurityException exception) {
            throw new PaymentCoreException("REFUND_FOUR_EYES_REQUIRED",
                    "refund requester cannot approve the same refund", exception);
        } catch (IllegalStateException exception) {
            throw new PaymentCoreException("REFUND_APPROVAL_NOT_ALLOWED",
                    exception.getMessage(), exception);
        }
        RefundActionReceipt receipt = new RefundActionReceipt(command.tenantId(),
                command.refundId(), APPROVE_OPERATION, command.idempotencyKey(), digest,
                command.approverId(), command.reason(), command.ticketId(), approved.version(),
                clock.instant());
        RefundRepository.WriteResult result = refunds.transitionWithReceipt(current, approved,
                receipt, "refund.approved.v1");
        return result.replay() ? result.refund() : submit(result.refund());
    }

    public RefundRecord recover(RefundRecoveryCommand command) {
        Objects.requireNonNull(command, "command");
        RequestFingerprint.validateKey(command.idempotencyKey());
        String digest = CanonicalPayload.sha256Hex(Map.ofEntries(
                Map.entry("operation", QUERY_OPERATION),
                Map.entry("refund_id", command.refundId().toString()),
                Map.entry("actor_id", command.actorId()),
                Map.entry("ticket_id", command.ticketId())));
        RefundActionReceipt replay = refunds.findActionReceipt(command.tenantId(),
                command.refundId(), command.idempotencyKey()).orElse(null);
        if (replay != null) {
            requireSameAction(replay, QUERY_OPERATION, digest);
            return requireRefund(command.tenantId(), command.refundId());
        }
        RefundRecord current = requireRefund(command.tenantId(), command.refundId());
        if (current.status() != RefundStatus.UNKNOWN
                && current.status() != RefundStatus.PROCESSING) {
            throw new PaymentCoreException("REFUND_QUERY_NOT_ALLOWED",
                    "only processing or unknown refunds can be provider-queried");
        }
        if (clock.instant().isBefore(current.updatedAt().plus(recoveryDelay))) {
            throw new PaymentCoreException("REFUND_QUERY_TOO_EARLY",
                    "refund has not exceeded the configured provider recovery delay");
        }
        RefundActionReceipt receipt = new RefundActionReceipt(command.tenantId(),
                command.refundId(), QUERY_OPERATION, command.idempotencyKey(), digest,
                command.actorId(), "provider outcome recovery", command.ticketId(),
                current.version(), clock.instant());
        RefundRepository.WriteResult claim = refunds.claimAction(current, receipt,
                "refund.recovery.requested.v1");
        if (claim.replay()) {
            return claim.refund();
        }
        RefundRecord claimed = claim.refund();
        ProviderAccount account = requireAccount(claimed);
        ProviderAdapter adapter = adapters.require(account.provider());
        if (!adapter.configured()) {
            return recordQueryFailure(claimed,
                    new ProviderException("PROVIDER_NOT_CONFIGURED",
                            "provider adapter is not configured", false, false),
                    command.correlationId());
        }
        String providerRefundId = claimed.providerRefundId() == null
                ? claimed.id().toString() : claimed.providerRefundId();
        try {
            ProviderRefund result = adapter.queryRefund(context(account,
                    command.idempotencyKey(), command.correlationId()), providerRefundId,
                    claimed.id().toString());
            return recordProviderResult(claimed, result, command.correlationId());
        } catch (ProviderException exception) {
            return recordQueryFailure(claimed, exception, command.correlationId());
        } catch (RuntimeException exception) {
            return recordUnexpectedFailure(claimed, command.correlationId());
        }
    }

    public RefundRecord get(UUID tenantId, UUID refundId) {
        return requireRefund(tenantId, refundId);
    }

    public long remainingRefundable(UUID tenantId, UUID paymentIntentId) {
        PaymentIntent intent = requireIntent(tenantId, paymentIntentId);
        return refunds.remainingRefundable(tenantId, paymentIntentId,
                intent.capturedAmountMinor(), intent.refundedAmountMinor());
    }

    private RefundRecord submit(RefundRecord refund) {
        ProviderAccount account = requireAccount(refund);
        ProviderAdapter adapter = adapters.require(account.provider());
        if (!adapter.configured()) {
            return recordProviderFailure(refund,
                    new ProviderException("PROVIDER_NOT_CONFIGURED",
                            "provider adapter is not configured", false, false),
                    refund.correlationId());
        }
        try {
            ProviderRefund result = adapter.refund(new RefundCommand(
                    context(account, refund.requestIdempotencyKey(), refund.correlationId()),
                    refund.id(), refund.providerPaymentId(), refund.amount(),
                    refund.reason().wireValue()));
            return recordProviderResult(refund, result, refund.correlationId());
        } catch (ProviderException exception) {
            return recordProviderFailure(refund, exception, refund.correlationId());
        } catch (RuntimeException exception) {
            return recordUnexpectedFailure(refund, refund.correlationId());
        }
    }

    private RefundRecord recordProviderResult(RefundRecord current, ProviderRefund result,
            String correlationId) {
        Resolution resolution = normalize(current, Objects.requireNonNull(result,
                "provider refund result"));
        RefundRecord proposed = current.providerResult(resolution.status(),
                resolution.providerRefundId(), resolution.outcomeDigest(),
                resolution.failureCode(), correlationId, clock.instant());
        return resolveConcurrent(current, proposed, eventType(proposed.status()));
    }

    private RefundRecord recordProviderFailure(RefundRecord current, ProviderException failure,
            String correlationId) {
        Map<String, Object> evidence = Map.of(
                "code", failure.code(),
                "retryable", failure.retryable(),
                "outcome_unknown", failure.outcomeUnknown());
        RefundStatus status = failure.outcomeUnknown()
                ? RefundStatus.UNKNOWN : RefundStatus.FAILED;
        RefundRecord proposed = current.providerResult(status, current.providerRefundId(),
                CanonicalPayload.sha256Hex(evidence), failure.code(), correlationId,
                clock.instant());
        return resolveConcurrent(current, proposed, eventType(status));
    }

    /** A failed query never proves the original refund failed, so reservation is retained. */
    private RefundRecord recordQueryFailure(RefundRecord current, ProviderException failure,
            String correlationId) {
        Map<String, Object> evidence = Map.of(
                "code", failure.code(),
                "query_retryable", failure.retryable(),
                "query_outcome_unknown", failure.outcomeUnknown(),
                "original_outcome_still_unknown", true);
        RefundRecord proposed = current.providerResult(RefundStatus.UNKNOWN,
                current.providerRefundId(), CanonicalPayload.sha256Hex(evidence),
                "REFUND_QUERY_" + failure.code(), correlationId, clock.instant());
        return resolveConcurrent(current, proposed, "refund.unknown.v1");
    }

    private RefundRecord recordUnexpectedFailure(RefundRecord current, String correlationId) {
        RefundRecord proposed = current.providerResult(RefundStatus.UNKNOWN,
                current.providerRefundId(), CanonicalPayload.sha256Hex(Map.of(
                        "code", "UNCLASSIFIED_PROVIDER_TRANSPORT",
                        "outcome_unknown", true)), "UNCLASSIFIED_PROVIDER_TRANSPORT",
                correlationId, clock.instant());
        return resolveConcurrent(current, proposed, "refund.unknown.v1");
    }

    private RefundRecord resolveConcurrent(RefundRecord current, RefundRecord proposed,
            String eventType) {
        try {
            return refunds.recordProviderOutcome(current, proposed, eventType);
        } catch (PaymentCoreException exception) {
            if (!"CONCURRENT_MODIFICATION".equals(exception.code())) {
                throw exception;
            }
            RefundRecord stored = requireRefund(current.tenantId(), current.id());
            if (stored.status().finalState() || stored.status() == RefundStatus.UNKNOWN) {
                return stored;
            }
            throw exception;
        }
    }

    private Resolution normalize(RefundRecord current, ProviderRefund result) {
        String providerRefundId = blankToNull(result.providerRefundId());
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("outcome", result.outcome().name());
        evidence.put("final", result.finalOutcome());
        evidence.put("provider_refund_id", providerRefundId == null ? "" : providerRefundId);
        evidence.put("refunded_minor", result.refunded() == null
                ? -1 : result.refunded().amountMinor());
        evidence.put("currency", result.refunded() == null
                ? "" : result.refunded().currency().code());
        String digest = CanonicalPayload.sha256Hex(evidence);

        if (result.outcome() == ProviderOutcome.SUCCEEDED) {
            if (!result.finalOutcome()) {
                return new Resolution(RefundStatus.UNKNOWN, chooseReference(current,
                        providerRefundId), digest, "PROVIDER_SUCCESS_NOT_FINAL");
            }
            if (providerRefundId == null) {
                return new Resolution(RefundStatus.UNKNOWN, current.providerRefundId(), digest,
                        "PROVIDER_REFUND_REFERENCE_MISSING");
            }
            if (current.providerRefundId() != null
                    && !current.providerRefundId().equals(current.id().toString())
                    && !current.providerRefundId().equals(providerRefundId)) {
                return new Resolution(RefundStatus.UNKNOWN, current.providerRefundId(), digest,
                        "PROVIDER_REFUND_REFERENCE_MISMATCH");
            }
            if (result.refunded() == null) {
                return new Resolution(RefundStatus.UNKNOWN, providerRefundId, digest,
                        "PROVIDER_REFUND_AMOUNT_MISSING");
            }
            if (!result.refunded().currency().code().equals(current.amount().currency().code())) {
                return new Resolution(RefundStatus.UNKNOWN, providerRefundId, digest,
                        "PROVIDER_REFUND_CURRENCY_MISMATCH");
            }
            if (result.refunded().amountMinor() != current.amount().amountMinor()) {
                return new Resolution(RefundStatus.UNKNOWN, providerRefundId, digest,
                        "PROVIDER_REFUND_AMOUNT_MISMATCH");
            }
            return new Resolution(RefundStatus.SUCCEEDED, providerRefundId, digest, null);
        }
        if ((result.outcome() == ProviderOutcome.FAILED
                || result.outcome() == ProviderOutcome.DECLINED
                || result.outcome() == ProviderOutcome.CANCELED) && result.finalOutcome()) {
            return new Resolution(RefundStatus.FAILED,
                    chooseReference(current, providerRefundId), digest,
                    "PROVIDER_REFUND_" + result.outcome().name());
        }
        return new Resolution(RefundStatus.UNKNOWN, chooseReference(current, providerRefundId),
                digest, "PROVIDER_REFUND_OUTCOME_UNKNOWN");
    }

    private PaymentAttempt sourceAttempt(PaymentIntent intent) {
        List<PaymentAttempt> attempts = payments.attempts(intent.tenantId(), intent.id());
        for (int index = attempts.size() - 1; index >= 0; index--) {
            PaymentAttempt attempt = attempts.get(index);
            if ((attempt.operation() == AttemptOperation.PAYMENT
                    || attempt.operation() == AttemptOperation.CAPTURE)
                    && attempt.state() == AttemptState.SUCCEEDED
                    && attempt.providerTransactionId() != null
                    && !attempt.providerTransactionId().isBlank()) {
                return attempt;
            }
        }
        throw new PaymentCoreException("PROVIDER_TRANSACTION_MISSING",
                "captured payment has no attributable successful provider transaction");
    }

    private ProviderAccount requireAccount(RefundRecord refund) {
        return merchantConfiguration.findAccount(refund.tenantId(), refund.projectId(),
                refund.providerAccountId()).filter(account -> account.provider().equals(refund.provider()))
                .orElseThrow(() -> new PaymentCoreException("PROVIDER_ACCOUNT_NOT_FOUND",
                        "refund provider account is outside this tenant or project"));
    }

    private ProviderAccount requireAccount(PaymentIntent intent, UUID providerAccountId) {
        return merchantConfiguration.findAccount(intent.tenantId(), intent.projectId(),
                providerAccountId).orElseThrow(() -> new PaymentCoreException(
                        "PROVIDER_ACCOUNT_NOT_FOUND",
                        "provider account is outside this tenant or project"));
    }

    private PaymentIntent requireIntent(UUID tenantId, UUID intentId) {
        return payments.find(tenantId, intentId).orElseThrow(() -> new PaymentCoreException(
                "RESOURCE_NOT_FOUND", "payment intent does not exist in this tenant"));
    }

    private RefundRecord requireRefund(UUID tenantId, UUID refundId) {
        return refunds.find(tenantId, refundId).orElseThrow(() -> new PaymentCoreException(
                "RESOURCE_NOT_FOUND", "refund does not exist in this tenant"));
    }

    private static ProviderRequestContext context(ProviderAccount account, String key,
            String correlationId) {
        return new ProviderRequestContext(account.tenantId(), account.projectId(), account.id(),
                key, correlationId, account.credentialVersion());
    }

    private static String requestDigest(RefundRequestCommand command, PaymentIntent intent,
            Money amount) {
        return CanonicalPayload.sha256Hex(Map.ofEntries(
                Map.entry("operation", "REFUND_CREATE"),
                Map.entry("tenant_id", command.tenantId().toString()),
                Map.entry("project_id", intent.projectId().toString()),
                Map.entry("payment_intent_id", command.paymentIntentId().toString()),
                Map.entry("amount_minor", amount.amountMinor()),
                Map.entry("currency", amount.currency().code()),
                Map.entry("reason", command.reason().wireValue()),
                Map.entry("requester_id", command.requesterId()),
                Map.entry("device_context_digest", command.deviceContextDigest())));
    }

    private static void requireSameRequest(RefundRecord replay, String digest) {
        if (!replay.sameRequestDigest(digest)) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "refund request key was reused with a different canonical payload");
        }
    }

    private static void requireSameAction(RefundActionReceipt receipt, String operation,
            String digest) {
        if (!receipt.matches(operation, digest)) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "refund action key was reused with a different operation or payload");
        }
    }

    private static RefundRecord requireNotDenied(RefundRecord refund) {
        if (refund.status() == RefundStatus.FAILED
                && "REFUND_RISK_DENIED".equals(refund.failureCode())) {
            throw new PaymentCoreException("REFUND_RISK_DENIED",
                    "refund was denied by server-side risk policy");
        }
        return refund;
    }

    private static String eventType(RefundStatus status) {
        return switch (status) {
            case SUCCEEDED -> "refund.succeeded.v1";
            case FAILED -> "refund.failed.v1";
            case UNKNOWN -> "refund.unknown.v1";
            default -> "refund.processing.v1";
        };
    }

    private static String chooseReference(RefundRecord current, String candidate) {
        return current.providerRefundId() == null ? candidate : current.providerRefundId();
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private record Resolution(RefundStatus status, String providerRefundId,
            String outcomeDigest, String failureCode) {
    }
}
