package com.elmpay.payment.commerce;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** Durable B66-B71 boundary used by HTTP and fenced workers. */
public interface CommerceService {
    enum SubscriptionState { TRIALING, ACTIVE, PAST_DUE, PAUSED, CANCELED }
    enum DisputeState { OPEN, EVIDENCE_SUBMITTED, WON, LOST, ACCEPTED, APPEALED }
    enum DunningState { SCHEDULED, WAITING_PROVIDER_QUERY, RECOVERED, EXHAUSTED, PAUSED }
    enum RenewalOutcome { SUCCEEDED, FAILED, UNKNOWN }

    record Context(UUID tenantId, UUID projectId, String actorId) {
        public Context {
            if (tenantId == null || projectId == null || actorId == null || actorId.isBlank()) {
                throw new IllegalArgumentException("tenant, project and actor are required");
            }
        }
    }

    record PlanCommand(String code, long amountMinor, String currency,
            long billingPeriodSeconds, long trialPeriodSeconds, boolean metered, long version) {}

    record Plan(UUID id, UUID tenantId, UUID projectId, String code, long amountMinor,
            String currency, long billingPeriodSeconds, long trialPeriodSeconds,
            boolean metered, long version) {}

    record MandateCommand(String customerReference, String provider,
            String providerMandateReference, String paymentMethodReference, String purpose,
            long maximumAmountMinor, String currency, String consentDigest) {}

    record Mandate(UUID id, UUID tenantId, UUID projectId, String customerReference,
            String provider, String providerMandateReference, String paymentMethodReference,
            String purpose, long maximumAmountMinor, String currency, String consentDigest,
            String state, Instant consentedAt, Instant revokedAt, long version) {}

    record SubscriptionCommand(String customerReference, UUID planId, UUID mandateId) {}

    record Subscription(UUID id, UUID tenantId, UUID projectId, String customerReference,
            UUID planId, UUID mandateId, SubscriptionState state, Instant periodStart,
            Instant periodEnd, long usageQuantity, Instant cancelAt, long version) {}

    record Adjustment(UUID id, UUID subscriptionId, String operation, UUID oldPlanId,
            UUID newPlanId, long oldUnusedCreditMinor, long newRemainingChargeMinor,
            long netDebitMinor, String currency, long remainingSeconds, long periodSeconds,
            Instant createdAt) {}

    record DisputeEvent(String provider, String providerEventId, String providerDisputeId,
            UUID paymentIntentId, long amountMinor, String currency, Instant responseDeadline,
            String payloadDigest, boolean signatureVerified) {}

    record Dispute(UUID id, UUID tenantId, UUID projectId, String provider,
            String providerDisputeId, UUID paymentIntentId, long amountMinor, String currency,
            Instant responseDeadline, DisputeState state, String financialEffectState,
            long version) {}

    record BillingCycle(UUID id, UUID tenantId, UUID projectId, UUID subscriptionId,
            Instant periodStart, Instant periodEnd, long amountMinor, String currency,
            String state) {}

    record DunningCase(UUID id, UUID tenantId, UUID projectId, UUID subscriptionId,
            UUID billingCycleId, DunningState state, int attempts, int maximumAttempts,
            Instant nextAttemptAt, Instant graceEndsAt, long version) {}

    Plan createPlan(Context context, PlanCommand command, String idempotencyKey,
            String correlationId);

    Mandate createMandate(Context context, MandateCommand command, String idempotencyKey,
            String correlationId);

    Mandate revokeMandate(Context context, UUID mandateId, String reason,
            String idempotencyKey, String correlationId);

    Subscription createSubscription(Context context, SubscriptionCommand command,
            String idempotencyKey, String correlationId);

    Subscription recordUsage(Context context, UUID subscriptionId, long quantity,
            String idempotencyKey, String correlationId);

    Adjustment changePlan(Context context, UUID subscriptionId, UUID newPlanId, String reason,
            String idempotencyKey, String correlationId);

    Adjustment scheduleCancellation(Context context, UUID subscriptionId, Instant cancelAt,
            String reason, String idempotencyKey, String correlationId);

    Subscription getSubscription(Context context, UUID subscriptionId);

    Dispute ingestDispute(Context context, DisputeEvent event, String correlationId);

    Dispute submitEvidence(Context context, UUID disputeId, String objectDigest,
            String mediaType, String objectReference, String idempotencyKey,
            String correlationId);

    Dispute resolveDispute(Context context, UUID disputeId, DisputeState result,
            String providerResultDigest, boolean verifiedProviderResult,
            String idempotencyKey, String correlationId);

    Dispute getDispute(Context context, UUID disputeId);

    Optional<BillingCycle> enqueueDueRenewal(UUID tenantId, Instant now,
            String workerId);

    Subscription recordRenewalOutcome(Context context, UUID billingCycleId,
            RenewalOutcome outcome, String providerResultDigest, boolean verifiedProviderResult,
            String idempotencyKey, String correlationId);

    Optional<DunningCase> enqueueDueDunning(UUID tenantId, Instant now,
            String workerId);

    DunningCase recordDunningOutcome(Context context, UUID dunningCaseId,
            RenewalOutcome outcome, String providerResultDigest, boolean verifiedProviderResult,
            String idempotencyKey, String correlationId);
}
