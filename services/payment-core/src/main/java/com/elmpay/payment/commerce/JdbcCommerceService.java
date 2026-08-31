package com.elmpay.payment.commerce;

import com.elmpay.payment.billing.ProrationCalculator;
import com.elmpay.payment.events.SemanticOutboxAppender;
import com.elmpay.provider.ProviderEvidenceReceipt;
import com.elmpay.provider.ProviderEvidenceVerifier;
import com.elmpay.provider.VerifiedProviderEvidence;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;

/** PostgreSQL implementation with tenant RLS, durable receipts and transactional outbox. */
public final class JdbcCommerceService implements CommerceService {
    private static final Set<String> PROVIDERS = Set.of(
            "wechat", "alipay", "stripe", "paypal", "apple_pay");
    private static final Set<String> TERMINAL_DISPUTES = Set.of("won", "lost", "accepted");
    private static final int MAXIMUM_DUNNING_ATTEMPTS = 4;
    private static final Duration DUNNING_GRACE = Duration.ofDays(14);
    private static final Duration[] DUNNING_DELAYS = {
        Duration.ofHours(12), Duration.ofDays(1), Duration.ofDays(3), Duration.ofDays(7)
    };

    private final DataSource dataSource;
    private final Clock clock;
    private final ProviderEvidenceVerifier evidenceVerifier;
    private final ProrationCalculator proration = new ProrationCalculator();

    public JdbcCommerceService(DataSource dataSource, Clock clock) {
        this(dataSource, clock, null);
    }

    public JdbcCommerceService(DataSource dataSource, Clock clock,
            ProviderEvidenceVerifier evidenceVerifier) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.evidenceVerifier = evidenceVerifier;
    }

    @Override
    public Plan createPlan(Context context, PlanCommand command, String idempotencyKey,
            String correlationId) {
        Objects.requireNonNull(command, "command");
        String code = text(command.code(), "plan code");
        String currency = currency(command.currency());
        if (command.amountMinor() < 0 || command.billingPeriodSeconds() <= 0
                || command.trialPeriodSeconds() < 0 || command.version() <= 0) {
            throw invalid("invalid plan amount or period");
        }
        UUID id = UUID.randomUUID();
        String digest = digest("plan", code, Long.toString(command.amountMinor()), currency,
                Long.toString(command.billingPeriodSeconds()),
                Long.toString(command.trialPeriodSeconds()), Boolean.toString(command.metered()),
                Long.toString(command.version()));
        return transaction(context.tenantId(), connection -> {
            Reservation reservation = reserve(connection, context, "plan.create",
                    idempotencyKey, digest, id, correlationId);
            if (reservation.replay()) {
                return plan(connection, context, reservation.resourceId());
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO billing_plan
                      (id,tenant_id,project_id,code,amount_minor,currency,
                       billing_period_seconds,trial_period_seconds,metered,active,version,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,true,?,?)
                    """)) {
                statement.setObject(1, id);
                statement.setObject(2, context.tenantId());
                statement.setObject(3, context.projectId());
                statement.setString(4, code);
                statement.setLong(5, command.amountMinor());
                statement.setString(6, currency);
                statement.setLong(7, command.billingPeriodSeconds());
                statement.setLong(8, command.trialPeriodSeconds());
                statement.setBoolean(9, command.metered());
                statement.setLong(10, command.version());
                statement.setTimestamp(11, timestamp(clock.instant()));
                statement.executeUpdate();
            }
            outbox(connection, context, "billing_plan", id, "billing.plan.created.v1",
                    correlationId, "{\"plan_id\":\"" + id + "\"}");
            return plan(connection, context, id);
        });
    }

    @Override
    public Mandate createMandate(Context context, MandateCommand command, String idempotencyKey,
            String correlationId) {
        Objects.requireNonNull(command, "command");
        String customer = text(command.customerReference(), "customer reference");
        String provider = provider(command.provider());
        String providerReference = opaque(command.providerMandateReference(),
                "provider mandate reference");
        String paymentReference = paymentReference(command.paymentMethodReference());
        String purpose = text(command.purpose(), "mandate purpose");
        String normalizedCurrency = currency(command.currency());
        String consentDigest = sha256(command.consentDigest(), "consent digest");
        if (command.maximumAmountMinor() <= 0) {
            throw invalid("mandate maximum must be positive");
        }
        UUID id = UUID.randomUUID();
        String requestDigest = digest("mandate", customer, provider, providerReference,
                paymentReference, purpose, Long.toString(command.maximumAmountMinor()),
                normalizedCurrency, consentDigest);
        return transaction(context.tenantId(), connection -> {
            Reservation reservation = reserve(connection, context, "mandate.create",
                    idempotencyKey, requestDigest, id, correlationId);
            if (reservation.replay()) {
                return mandate(connection, context, reservation.resourceId());
            }
            Instant now = clock.instant();
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO billing_mandate
                      (id,tenant_id,project_id,customer_reference,provider,
                       provider_mandate_reference,payment_method_reference,purpose,
                       maximum_amount_minor,currency,consent_digest,state,consented_at,version)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,'active',?,1)
                    """)) {
                statement.setObject(1, id);
                statement.setObject(2, context.tenantId());
                statement.setObject(3, context.projectId());
                statement.setString(4, customer);
                statement.setString(5, provider);
                statement.setString(6, providerReference);
                statement.setString(7, paymentReference);
                statement.setString(8, purpose);
                statement.setLong(9, command.maximumAmountMinor());
                statement.setString(10, normalizedCurrency);
                statement.setString(11, consentDigest);
                statement.setTimestamp(12, timestamp(now));
                statement.executeUpdate();
            }
            outbox(connection, context, "billing_mandate", id, "billing.mandate.created.v1",
                    correlationId, "{\"mandate_id\":\"" + id + "\"}");
            return mandate(connection, context, id);
        });
    }

    @Override
    public Mandate revokeMandate(Context context, UUID mandateId, String reason,
            String idempotencyKey, String correlationId) {
        Objects.requireNonNull(mandateId, "mandateId");
        String safeReason = text(reason, "revocation reason");
        String requestDigest = digest("mandate.revoke", mandateId.toString(), safeReason);
        return transaction(context.tenantId(), connection -> {
            Reservation reservation = reserve(connection, context, "mandate.revoke",
                    idempotencyKey, requestDigest, mandateId, correlationId);
            if (!reservation.replay()) {
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE billing_mandate
                           SET state='revoked', revoked_at=?, version=version+1
                         WHERE id=? AND tenant_id=? AND project_id=? AND state='active'
                        """)) {
                    statement.setTimestamp(1, timestamp(clock.instant()));
                    statement.setObject(2, mandateId);
                    statement.setObject(3, context.tenantId());
                    statement.setObject(4, context.projectId());
                    int updated = statement.executeUpdate();
                    if (updated == 0 && !"revoked".equals(
                            mandate(connection, context, mandateId).state())) {
                        throw notFound("mandate");
                    }
                }
                outbox(connection, context, "billing_mandate", mandateId,
                        "billing.mandate.revoked.v1", correlationId,
                        "{\"mandate_id\":\"" + mandateId + "\"}");
            }
            return mandate(connection, context, mandateId);
        });
    }

    @Override
    public Subscription createSubscription(Context context, SubscriptionCommand command,
            String idempotencyKey, String correlationId) {
        Objects.requireNonNull(command, "command");
        String customer = text(command.customerReference(), "customer reference");
        Objects.requireNonNull(command.planId(), "planId");
        Objects.requireNonNull(command.mandateId(), "mandateId");
        UUID id = UUID.randomUUID();
        String requestDigest = digest("subscription", customer, command.planId().toString(),
                command.mandateId().toString());
        return transaction(context.tenantId(), connection -> {
            Reservation reservation = reserve(connection, context, "subscription.create",
                    idempotencyKey, requestDigest, id, correlationId);
            if (reservation.replay()) {
                return subscription(connection, context, reservation.resourceId(), false);
            }
            Plan plan = plan(connection, context, command.planId());
            Mandate mandate = mandate(connection, context, command.mandateId());
            if (!"active".equals(mandate.state()) || !customer.equals(mandate.customerReference())
                    || !plan.currency().equals(mandate.currency())
                    || plan.amountMinor() > mandate.maximumAmountMinor()) {
                throw new CommerceRuntimeException("MANDATE_SCOPE_MISMATCH",
                        "subscription is outside the active mandate scope");
            }
            Instant start = clock.instant();
            long firstPeriod = plan.trialPeriodSeconds() > 0
                    ? plan.trialPeriodSeconds() : plan.billingPeriodSeconds();
            SubscriptionState state = plan.trialPeriodSeconds() > 0
                    ? SubscriptionState.TRIALING : SubscriptionState.ACTIVE;
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO billing_subscription
                      (id,tenant_id,project_id,customer_reference,plan_id,mandate_id,state,
                       period_start,period_end,usage_quantity,version,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?, ?,?,0,1,?,?)
                    """)) {
                statement.setObject(1, id);
                statement.setObject(2, context.tenantId());
                statement.setObject(3, context.projectId());
                statement.setString(4, customer);
                statement.setObject(5, plan.id());
                statement.setObject(6, mandate.id());
                statement.setString(7, wire(state));
                statement.setTimestamp(8, timestamp(start));
                statement.setTimestamp(9, timestamp(start.plusSeconds(firstPeriod)));
                statement.setTimestamp(10, timestamp(start));
                statement.setTimestamp(11, timestamp(start));
                statement.executeUpdate();
            }
            outbox(connection, context, "billing_subscription", id,
                    "billing.subscription.created.v1", correlationId,
                    "{\"subscription_id\":\"" + id + "\"}");
            return subscription(connection, context, id, false);
        });
    }

    @Override
    public Subscription recordUsage(Context context, UUID subscriptionId, long quantity,
            String idempotencyKey, String correlationId) {
        Objects.requireNonNull(subscriptionId, "subscriptionId");
        if (quantity <= 0) {
            throw invalid("usage quantity must be positive");
        }
        String requestDigest = digest("usage", subscriptionId.toString(), Long.toString(quantity));
        return transaction(context.tenantId(), connection -> {
            Subscription current = subscription(connection, context, subscriptionId, true);
            Plan plan = plan(connection, context, current.planId());
            if (!plan.metered() || current.state() == SubscriptionState.CANCELED) {
                throw new CommerceRuntimeException("USAGE_NOT_ALLOWED",
                        "usage requires an active metered subscription");
            }
            Savepoint savepoint = connection.setSavepoint("usage_inbox_insert");
            boolean inserted;
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO subscription_usage_inbox
                      (tenant_id,project_id,subscription_id,idempotency_key,request_digest,
                       quantity,received_at) VALUES (?,?,?,?,?,?,?)
                    """)) {
                statement.setObject(1, context.tenantId());
                statement.setObject(2, context.projectId());
                statement.setObject(3, subscriptionId);
                statement.setString(4, idempotency(idempotencyKey));
                statement.setString(5, requestDigest);
                statement.setLong(6, quantity);
                statement.setTimestamp(7, timestamp(clock.instant()));
                statement.executeUpdate();
                connection.releaseSavepoint(savepoint);
                inserted = true;
            } catch (SQLException duplicate) {
                rollbackUnique(connection, savepoint, duplicate);
                try (PreparedStatement query = connection.prepareStatement("""
                        SELECT request_digest FROM subscription_usage_inbox
                         WHERE tenant_id=? AND subscription_id=? AND idempotency_key=?
                        """)) {
                    query.setObject(1, context.tenantId());
                    query.setObject(2, subscriptionId);
                    query.setString(3, idempotency(idempotencyKey));
                    try (ResultSet result = query.executeQuery()) {
                        if (!result.next() || !constantEquals(requestDigest, result.getString(1))) {
                            throw new CommerceRuntimeException("IDEMPOTENCY_CONFLICT",
                                    "usage idempotency key was reused with different input");
                        }
                    }
                }
                inserted = false;
            }
            if (inserted) {
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE billing_subscription
                           SET usage_quantity=usage_quantity+?, version=version+1, updated_at=?
                         WHERE id=? AND tenant_id=? AND project_id=? AND version=?
                        """)) {
                    statement.setLong(1, quantity);
                    statement.setTimestamp(2, timestamp(clock.instant()));
                    statement.setObject(3, subscriptionId);
                    statement.setObject(4, context.tenantId());
                    statement.setObject(5, context.projectId());
                    statement.setLong(6, current.version());
                    requireUpdated(statement.executeUpdate(), "stale subscription version");
                }
                outbox(connection, context, "billing_subscription", subscriptionId,
                        "billing.subscription.usage_recorded.v1", correlationId,
                        "{\"subscription_id\":\"" + subscriptionId
                                + "\",\"quantity\":" + quantity + "}");
            }
            return subscription(connection, context, subscriptionId, false);
        });
    }

    @Override
    public Adjustment changePlan(Context context, UUID subscriptionId, UUID newPlanId,
            String reason, String idempotencyKey, String correlationId) {
        Objects.requireNonNull(subscriptionId, "subscriptionId");
        Objects.requireNonNull(newPlanId, "newPlanId");
        String safeReason = text(reason, "plan change reason");
        return adjust(context, subscriptionId, newPlanId, null, "plan_change", safeReason,
                idempotencyKey, correlationId);
    }

    @Override
    public Adjustment scheduleCancellation(Context context, UUID subscriptionId,
            Instant cancelAt, String reason, String idempotencyKey, String correlationId) {
        Objects.requireNonNull(subscriptionId, "subscriptionId");
        Objects.requireNonNull(cancelAt, "cancelAt");
        String safeReason = text(reason, "cancellation reason");
        return adjust(context, subscriptionId, null, cancelAt, "cancellation", safeReason,
                idempotencyKey, correlationId);
    }

    private Adjustment adjust(Context context, UUID subscriptionId, UUID newPlanId,
            Instant cancelAt, String operation, String reason, String idempotencyKey,
            String correlationId) {
        UUID adjustmentId = UUID.randomUUID();
        String requestDigest = digest(operation, subscriptionId.toString(),
                newPlanId == null ? "" : newPlanId.toString(),
                cancelAt == null ? "" : cancelAt.toString(), reason);
        return transaction(context.tenantId(), connection -> {
            Reservation reservation = reserve(connection, context, "subscription." + operation,
                    idempotencyKey, requestDigest, adjustmentId, correlationId);
            if (reservation.replay()) {
                return adjustment(connection, context, reservation.resourceId());
            }
            Subscription current = subscription(connection, context, subscriptionId, true);
            if (current.state() == SubscriptionState.CANCELED) {
                throw new CommerceRuntimeException("SUBSCRIPTION_FINAL",
                        "canceled subscription cannot be adjusted");
            }
            Plan oldPlan = plan(connection, context, current.planId());
            Plan newPlan = newPlanId == null ? null : plan(connection, context, newPlanId);
            if (newPlan != null && !oldPlan.currency().equals(newPlan.currency())) {
                throw invalid("cross-currency plan changes are not supported");
            }
            Instant now = clock.instant();
            Instant effectiveAt = cancelAt == null ? now : cancelAt;
            if (effectiveAt.isBefore(now) || effectiveAt.isAfter(current.periodEnd())) {
                throw invalid("adjustment effective time must be inside the current period");
            }
            long periodSeconds = Duration.between(current.periodStart(), current.periodEnd()).getSeconds();
            long remainingSeconds = Duration.between(effectiveAt, current.periodEnd()).getSeconds();
            long newAmount = newPlan == null ? 0L : newPlan.amountMinor();
            ProrationCalculator.Adjustment calculated = proration.calculate(oldPlan.amountMinor(),
                    newAmount, remainingSeconds, periodSeconds);
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO billing_adjustment
                      (id,tenant_id,project_id,subscription_id,operation,old_plan_id,new_plan_id,
                       old_unused_credit_minor,new_remaining_charge_minor,net_debit_minor,currency,
                       remaining_seconds,period_seconds,reason,actor_id,created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """)) {
                statement.setObject(1, adjustmentId);
                statement.setObject(2, context.tenantId());
                statement.setObject(3, context.projectId());
                statement.setObject(4, subscriptionId);
                statement.setString(5, operation);
                statement.setObject(6, oldPlan.id());
                statement.setObject(7, newPlan == null ? null : newPlan.id());
                statement.setLong(8, calculated.oldUnusedCreditMinor());
                statement.setLong(9, calculated.newRemainingChargeMinor());
                statement.setLong(10, calculated.netDebitMinor());
                statement.setString(11, oldPlan.currency());
                statement.setLong(12, remainingSeconds);
                statement.setLong(13, periodSeconds);
                statement.setString(14, reason);
                statement.setString(15, context.actorId());
                statement.setTimestamp(16, timestamp(now));
                statement.executeUpdate();
            }
            String sql = newPlan == null
                    ? "UPDATE billing_subscription SET cancel_at=?,version=version+1,updated_at=? WHERE id=? AND tenant_id=? AND project_id=? AND version=?"
                    : "UPDATE billing_subscription SET plan_id=?,version=version+1,updated_at=? WHERE id=? AND tenant_id=? AND project_id=? AND version=?";
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setObject(1, newPlan == null ? timestamp(cancelAt) : newPlan.id());
                statement.setTimestamp(2, timestamp(now));
                statement.setObject(3, subscriptionId);
                statement.setObject(4, context.tenantId());
                statement.setObject(5, context.projectId());
                statement.setLong(6, current.version());
                requireUpdated(statement.executeUpdate(), "stale subscription version");
            }
            outbox(connection, context, "billing_adjustment", adjustmentId,
                    "billing.subscription.adjusted.v1", correlationId,
                    "{\"adjustment_id\":\"" + adjustmentId
                            + "\",\"subscription_id\":\"" + subscriptionId + "\"}");
            return adjustment(connection, context, adjustmentId);
        });
    }

    @Override
    public Subscription getSubscription(Context context, UUID subscriptionId) {
        return transaction(context.tenantId(), connection ->
                subscription(connection, context, subscriptionId, false));
    }

    @Override
    public Dispute ingestDispute(Context context, DisputeEvent event, String correlationId) {
        Objects.requireNonNull(event, "event");
        String normalizedProvider = provider(event.provider());
        String providerEventId = opaque(event.providerEventId(), "provider event id");
        String providerDisputeId = opaque(event.providerDisputeId(), "provider dispute id");
        Objects.requireNonNull(event.paymentIntentId(), "paymentIntentId");
        if (event.amountMinor() <= 0 || event.responseDeadline() == null) {
            throw invalid("invalid dispute amount or deadline");
        }
        String normalizedCurrency = currency(event.currency());
        String payloadDigest = sha256(event.payloadDigest(), "payload digest");
        VerifiedProviderEvidence verification = verifyEvidence(event.evidence(),
                "PROVIDER_DISPUTE_EVENT", evidenceFields(context, normalizedProvider,
                        providerEventId,
                        "providerEventId", providerEventId,
                        "providerDisputeId", providerDisputeId,
                        "paymentIntentId", event.paymentIntentId().toString(),
                        "amountMinor", Long.toString(event.amountMinor()),
                        "currency", normalizedCurrency,
                        "responseDeadline", event.responseDeadline().toString(),
                        "payloadDigest", payloadDigest));
        return transaction(context.tenantId(), connection -> {
            UUID disputeId = UUID.randomUUID();
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO provider_dispute
                      (id,tenant_id,project_id,provider,provider_dispute_id,payment_intent_id,
                       amount_minor,currency,response_deadline,state,financial_effect_state,
                       version,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,'open','pending',1,?,?)
                    ON CONFLICT (tenant_id,project_id,provider,provider_dispute_id) DO NOTHING
                    """)) {
                Instant now = clock.instant();
                statement.setObject(1, disputeId);
                statement.setObject(2, context.tenantId());
                statement.setObject(3, context.projectId());
                statement.setString(4, normalizedProvider);
                statement.setString(5, providerDisputeId);
                statement.setObject(6, event.paymentIntentId());
                statement.setLong(7, event.amountMinor());
                statement.setString(8, normalizedCurrency);
                statement.setTimestamp(9, timestamp(event.responseDeadline()));
                statement.setTimestamp(10, timestamp(now));
                statement.setTimestamp(11, timestamp(now));
                statement.executeUpdate();
            }
            Dispute dispute = disputeByProvider(connection, context, normalizedProvider,
                    providerDisputeId);
            if (!dispute.paymentIntentId().equals(event.paymentIntentId())
                    || dispute.amountMinor() != event.amountMinor()
                    || !dispute.currency().equals(normalizedCurrency)) {
                throw new CommerceRuntimeException("DISPUTE_IDENTITY_CONFLICT",
                        "provider dispute identity was reused with different financial facts");
            }
            boolean inserted;
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO dispute_event_inbox
                      (tenant_id,project_id,provider,provider_event_id,provider_dispute_id,
                       payload_digest,verification_receipt_digest,dispute_id,received_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    ON CONFLICT (tenant_id,provider,provider_event_id) DO NOTHING
                    """)) {
                statement.setObject(1, context.tenantId());
                statement.setObject(2, context.projectId());
                statement.setString(3, normalizedProvider);
                statement.setString(4, providerEventId);
                statement.setString(5, providerDisputeId);
                statement.setString(6, payloadDigest);
                statement.setString(7, verification.receiptDigest());
                statement.setObject(8, dispute.id());
                statement.setTimestamp(9, timestamp(clock.instant()));
                inserted = statement.executeUpdate() == 1;
            }
            verifyDisputeInbox(connection, context.tenantId(), normalizedProvider,
                    providerEventId, payloadDigest, verification.receiptDigest(), dispute.id());
            if (inserted) {
                outbox(connection, context, "provider_dispute", dispute.id(),
                        "dispute.opened.v1", correlationId,
                        "{\"dispute_id\":\"" + dispute.id() + "\"}");
            }
            return dispute;
        });
    }

    @Override
    public Dispute submitEvidence(Context context, UUID disputeId, String objectDigest,
            String mediaType, String objectReference, String idempotencyKey,
            String correlationId) {
        Objects.requireNonNull(disputeId, "disputeId");
        String digest = sha256(objectDigest, "evidence digest");
        String type = text(mediaType, "evidence media type");
        String reference = objectReference(objectReference);
        String requestDigest = digest("evidence", disputeId.toString(), digest, type, reference);
        UUID evidenceId = UUID.randomUUID();
        return transaction(context.tenantId(), connection -> {
            Reservation reservation = reserve(connection, context, "dispute.evidence",
                    idempotencyKey, requestDigest, evidenceId, correlationId);
            if (reservation.replay()) {
                return dispute(connection, context, disputeId, false);
            }
            Dispute current = dispute(connection, context, disputeId, true);
            if (!clock.instant().isBefore(current.responseDeadline())
                    || TERMINAL_DISPUTES.contains(wire(current.state()))) {
                throw new CommerceRuntimeException("DISPUTE_EVIDENCE_CLOSED",
                        "dispute evidence window is closed");
            }
            int revision;
            try (PreparedStatement query = connection.prepareStatement("""
                    SELECT COALESCE(MAX(revision),0)+1 FROM dispute_evidence
                     WHERE tenant_id=? AND dispute_id=?
                    """)) {
                query.setObject(1, context.tenantId());
                query.setObject(2, disputeId);
                try (ResultSet result = query.executeQuery()) {
                    result.next();
                    revision = result.getInt(1);
                }
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    INSERT INTO dispute_evidence
                      (id,tenant_id,project_id,dispute_id,revision,object_digest,media_type,
                       object_reference,submitted_by,submitted_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """)) {
                statement.setObject(1, evidenceId);
                statement.setObject(2, context.tenantId());
                statement.setObject(3, context.projectId());
                statement.setObject(4, disputeId);
                statement.setInt(5, revision);
                statement.setString(6, digest);
                statement.setString(7, type);
                statement.setString(8, reference);
                statement.setString(9, context.actorId());
                statement.setTimestamp(10, timestamp(clock.instant()));
                statement.executeUpdate();
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE provider_dispute
                       SET state='evidence_submitted',version=version+1,updated_at=?
                     WHERE id=? AND tenant_id=? AND project_id=? AND version=?
                    """)) {
                statement.setTimestamp(1, timestamp(clock.instant()));
                statement.setObject(2, disputeId);
                statement.setObject(3, context.tenantId());
                statement.setObject(4, context.projectId());
                statement.setLong(5, current.version());
                requireUpdated(statement.executeUpdate(), "stale dispute version");
            }
            outbox(connection, context, "provider_dispute", disputeId,
                    "dispute.evidence_submitted.v1", correlationId,
                    "{\"dispute_id\":\"" + disputeId + "\",\"revision\":" + revision + "}");
            return dispute(connection, context, disputeId, false);
        });
    }

    @Override
    public Dispute resolveDispute(Context context, UUID disputeId, DisputeState result,
            String providerResultDigest, ProviderEvidenceReceipt evidence,
            String idempotencyKey, String correlationId) {
        Objects.requireNonNull(disputeId, "disputeId");
        Objects.requireNonNull(result, "result");
        if (!TERMINAL_DISPUTES.contains(wire(result))) {
            throw new CommerceRuntimeException("UNVERIFIED_PROVIDER_RESULT",
                    "a verified terminal provider result is required");
        }
        String resultDigest = sha256(providerResultDigest, "provider result digest");
        return transaction(context.tenantId(), connection -> {
            Dispute current = dispute(connection, context, disputeId, true);
            VerifiedProviderEvidence verification = verifyEvidence(evidence,
                    "PROVIDER_DISPUTE_RESULT", evidenceFields(context, current.provider(),
                            disputeId.toString(),
                            "disputeId", disputeId.toString(),
                            "result", wire(result), "providerResultDigest", resultDigest));
            String requestDigest = digest("dispute.resolve", disputeId.toString(), result.name(),
                    resultDigest, verification.receiptDigest());
            Reservation reservation = reserve(connection, context, "dispute.resolve",
                    idempotencyKey, requestDigest, disputeId, correlationId);
            if (!reservation.replay()) {
                if (TERMINAL_DISPUTES.contains(wire(current.state()))) {
                    throw new CommerceRuntimeException("DISPUTE_FINAL",
                            "terminal dispute cannot transition again");
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE provider_dispute
                           SET state=?,version=version+1,updated_at=?
                         WHERE id=? AND tenant_id=? AND project_id=? AND version=?
                        """)) {
                    statement.setString(1, wire(result));
                    statement.setTimestamp(2, timestamp(clock.instant()));
                    statement.setObject(3, disputeId);
                    statement.setObject(4, context.tenantId());
                    statement.setObject(5, context.projectId());
                    statement.setLong(6, current.version());
                    requireUpdated(statement.executeUpdate(), "stale dispute version");
                }
                outbox(connection, context, "provider_dispute", disputeId,
                        "dispute.resolved.v1", correlationId,
                        "{\"dispute_id\":\"" + disputeId + "\",\"result\":\""
                                + wire(result) + "\",\"result_digest\":\""
                                + resultDigest + "\",\"verification_receipt_digest\":\""
                                + verification.receiptDigest() + "\"}");
            }
            return dispute(connection, context, disputeId, false);
        });
    }

    @Override
    public Dispute getDispute(Context context, UUID disputeId) {
        return transaction(context.tenantId(), connection ->
                dispute(connection, context, disputeId, false));
    }

    @Override
    public Optional<BillingCycle> enqueueDueRenewal(UUID tenantId, Instant now,
            String workerId) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(now, "now");
        text(workerId, "worker id");
        return transaction(tenantId, connection -> {
            try (PreparedStatement query = connection.prepareStatement("""
                    SELECT s.id,s.project_id,s.period_start,s.period_end,s.usage_quantity,
                           p.amount_minor,p.currency,p.metered
                      FROM billing_subscription s
                      JOIN billing_plan p ON p.id=s.plan_id AND p.tenant_id=s.tenant_id
                     WHERE s.tenant_id=? AND s.state IN ('trialing','active')
                       AND s.period_end<=?
                       AND NOT EXISTS (SELECT 1 FROM subscription_billing_cycle c
                         WHERE c.tenant_id=s.tenant_id AND c.subscription_id=s.id
                           AND c.period_start=s.period_start)
                     ORDER BY s.period_end,s.id FOR UPDATE OF s SKIP LOCKED LIMIT 1
                    """)) {
                query.setObject(1, tenantId);
                query.setTimestamp(2, timestamp(now));
                try (ResultSet result = query.executeQuery()) {
                    if (!result.next()) {
                        return Optional.empty();
                    }
                    UUID cycleId = UUID.randomUUID();
                    UUID subscriptionId = result.getObject("id", UUID.class);
                    UUID projectId = result.getObject("project_id", UUID.class);
                    long amount = result.getLong("amount_minor");
                    if (result.getBoolean("metered")) {
                        amount = Math.multiplyExact(amount, result.getLong("usage_quantity"));
                    }
                    try (PreparedStatement insert = connection.prepareStatement("""
                            INSERT INTO subscription_billing_cycle
                              (id,tenant_id,project_id,subscription_id,period_start,period_end,
                               amount_minor,currency,state,created_at,updated_at)
                            VALUES (?,?,?,?,?,?,?,?,'queued',?,?)
                            """)) {
                        insert.setObject(1, cycleId);
                        insert.setObject(2, tenantId);
                        insert.setObject(3, projectId);
                        insert.setObject(4, subscriptionId);
                        insert.setTimestamp(5, result.getTimestamp("period_start"));
                        insert.setTimestamp(6, result.getTimestamp("period_end"));
                        insert.setLong(7, amount);
                        insert.setString(8, result.getString("currency"));
                        insert.setTimestamp(9, timestamp(now));
                        insert.setTimestamp(10, timestamp(now));
                        insert.executeUpdate();
                    }
                    Context worker = new Context(tenantId, projectId, workerId);
                    outbox(connection, worker, "subscription_billing_cycle", cycleId,
                            "billing.subscription.renewal_due.v1", "worker:" + cycleId,
                            "{\"billing_cycle_id\":\"" + cycleId
                                    + "\",\"subscription_id\":\"" + subscriptionId + "\"}");
                    return Optional.of(new BillingCycle(cycleId, tenantId, projectId,
                            subscriptionId, result.getTimestamp("period_start").toInstant(),
                            result.getTimestamp("period_end").toInstant(), amount,
                            result.getString("currency"), "queued"));
                }
            }
        });
    }

    @Override
    public Subscription recordRenewalOutcome(Context context, UUID billingCycleId,
            RenewalOutcome outcome, String providerResultDigest, ProviderEvidenceReceipt evidence,
            String idempotencyKey, String correlationId) {
        Objects.requireNonNull(billingCycleId, "billingCycleId");
        Objects.requireNonNull(outcome, "outcome");
        // Reject an unverified provider result before opening a transaction or
        // touching the database.  This keeps the fail-closed boundary useful
        // even when the configured data source is unavailable.
        if (evidenceVerifier == null || evidence == null) {
            throw new CommerceRuntimeException("UNVERIFIED_PROVIDER_RESULT",
                    "cryptographically verified provider evidence is required");
        }
        String resultDigest = sha256(providerResultDigest, "provider result digest");
        return transaction(context.tenantId(), connection -> {
            CycleRow cycle = cycle(connection, context, billingCycleId, true);
            Subscription subscription = subscription(connection, context,
                    cycle.subscriptionId(), true);
            Mandate mandate = mandate(connection, context, subscription.mandateId());
            VerifiedProviderEvidence verification = verifyEvidence(evidence,
                    "PROVIDER_RENEWAL_RESULT", evidenceFields(context, mandate.provider(),
                            billingCycleId.toString(),
                            "billingCycleId", billingCycleId.toString(),
                            "subscriptionId", subscription.id().toString(),
                            "result", wire(outcome), "providerResultDigest", resultDigest));
            String requestDigest = digest("renewal.result", billingCycleId.toString(),
                    outcome.name(), resultDigest, verification.receiptDigest());
            Reservation reservation = reserve(connection, context, "renewal.result",
                    idempotencyKey, requestDigest, billingCycleId, correlationId);
            if (!reservation.replay()) {
                String cycleState = wire(outcome);
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE subscription_billing_cycle
                           SET state=?,provider_result_digest=?,updated_at=?
                         WHERE id=? AND tenant_id=? AND project_id=? AND state='queued'
                        """)) {
                    statement.setString(1, cycleState);
                    statement.setString(2, resultDigest);
                    statement.setTimestamp(3, timestamp(clock.instant()));
                    statement.setObject(4, billingCycleId);
                    statement.setObject(5, context.tenantId());
                    statement.setObject(6, context.projectId());
                    requireUpdated(statement.executeUpdate(), "billing cycle is already final");
                }
                if (outcome == RenewalOutcome.SUCCEEDED) {
                    Plan plan = plan(connection, context, subscription.planId());
                    Instant start = subscription.periodEnd();
                    updateSubscriptionPeriod(connection, context, subscription, start,
                            start.plusSeconds(plan.billingPeriodSeconds()));
                } else {
                    markPastDueAndOpenDunning(connection, context, subscription, billingCycleId,
                            outcome, correlationId);
                }
                outbox(connection, context, "subscription_billing_cycle", billingCycleId,
                        "billing.subscription.renewal_result.v1", correlationId,
                        "{\"billing_cycle_id\":\"" + billingCycleId
                                + "\",\"result\":\"" + cycleState
                                + "\",\"verification_receipt_digest\":\""
                                + verification.receiptDigest() + "\"}");
            }
            return subscription(connection, context, subscription.id(), false);
        });
    }

    @Override
    public Optional<DunningCase> enqueueDueDunning(UUID tenantId, Instant now,
            String workerId) {
        Objects.requireNonNull(tenantId, "tenantId");
        Objects.requireNonNull(now, "now");
        text(workerId, "worker id");
        return transaction(tenantId, connection -> {
            try (PreparedStatement query = connection.prepareStatement("""
                    SELECT * FROM dunning_case
                     WHERE tenant_id=? AND state='scheduled' AND next_attempt_at<=?
                     ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1
                    """)) {
                query.setObject(1, tenantId);
                query.setTimestamp(2, timestamp(now));
                try (ResultSet result = query.executeQuery()) {
                    if (!result.next()) {
                        return Optional.empty();
                    }
                    DunningCase value = dunning(result);
                    int attempts = value.attempts() + 1;
                    try (PreparedStatement update = connection.prepareStatement("""
                            UPDATE dunning_case
                               SET state='waiting_provider_query',attempts=?,next_attempt_at=NULL,
                                   version=version+1,updated_at=?
                             WHERE id=? AND tenant_id=? AND version=?
                            """)) {
                        update.setInt(1, attempts);
                        update.setTimestamp(2, timestamp(now));
                        update.setObject(3, value.id());
                        update.setObject(4, tenantId);
                        update.setLong(5, value.version());
                        requireUpdated(update.executeUpdate(), "stale dunning version");
                    }
                    Context worker = new Context(tenantId, value.projectId(), workerId);
                    outbox(connection, worker, "dunning_case", value.id(),
                            "billing.dunning.retry_due.v1", "worker:" + value.id() + ":" + attempts,
                            "{\"dunning_case_id\":\"" + value.id()
                                    + "\",\"attempt\":" + attempts + "}");
                    return Optional.of(dunning(connection, worker, value.id(), false));
                }
            }
        });
    }

    @Override
    public DunningCase recordDunningOutcome(Context context, UUID dunningCaseId,
            RenewalOutcome outcome, String providerResultDigest, ProviderEvidenceReceipt evidence,
            String idempotencyKey, String correlationId) {
        Objects.requireNonNull(dunningCaseId, "dunningCaseId");
        Objects.requireNonNull(outcome, "outcome");
        String resultDigest = sha256(providerResultDigest, "provider result digest");
        return transaction(context.tenantId(), connection -> {
            DunningCase current = dunning(connection, context, dunningCaseId, true);
            Subscription currentSubscription = subscription(connection, context,
                    current.subscriptionId(), true);
            Mandate mandate = mandate(connection, context, currentSubscription.mandateId());
            VerifiedProviderEvidence verification = verifyEvidence(evidence,
                    "PROVIDER_DUNNING_RESULT", evidenceFields(context, mandate.provider(),
                            dunningCaseId.toString(),
                            "dunningCaseId", dunningCaseId.toString(),
                            "subscriptionId", current.subscriptionId().toString(),
                            "attempt", Integer.toString(current.attempts()),
                            "result", wire(outcome), "providerResultDigest", resultDigest));
            String requestDigest = digest("dunning.result", dunningCaseId.toString(),
                    outcome.name(), resultDigest, verification.receiptDigest());
            Reservation reservation = reserve(connection, context, "dunning.result",
                    idempotencyKey, requestDigest, dunningCaseId, correlationId);
            if (!reservation.replay()) {
                if (current.state() != DunningState.WAITING_PROVIDER_QUERY) {
                    throw new CommerceRuntimeException("DUNNING_STATE_CONFLICT",
                            "dunning case is not waiting for a provider result");
                }
                String nextState;
                Instant nextAttempt = null;
                if (outcome == RenewalOutcome.SUCCEEDED) {
                    nextState = "recovered";
                    Subscription subscription = subscription(connection, context,
                            current.subscriptionId(), true);
                    Plan plan = plan(connection, context, subscription.planId());
                    Instant start = subscription.periodEnd();
                    updateSubscriptionPeriod(connection, context, subscription, start,
                            start.plusSeconds(plan.billingPeriodSeconds()));
                } else if (outcome == RenewalOutcome.UNKNOWN) {
                    nextState = "waiting_provider_query";
                } else if (current.attempts() >= current.maximumAttempts()
                        || !clock.instant().isBefore(current.graceEndsAt())) {
                    nextState = "exhausted";
                    pauseSubscription(connection, context, current.subscriptionId());
                } else {
                    nextState = "scheduled";
                    nextAttempt = clock.instant().plus(DUNNING_DELAYS[Math.min(
                            current.attempts(), DUNNING_DELAYS.length - 1)]);
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE dunning_case
                           SET state=?,next_attempt_at=?,version=version+1,updated_at=?
                         WHERE id=? AND tenant_id=? AND project_id=? AND version=?
                        """)) {
                    statement.setString(1, nextState);
                    statement.setTimestamp(2, nextAttempt == null ? null : timestamp(nextAttempt));
                    statement.setTimestamp(3, timestamp(clock.instant()));
                    statement.setObject(4, dunningCaseId);
                    statement.setObject(5, context.tenantId());
                    statement.setObject(6, context.projectId());
                    statement.setLong(7, current.version());
                    requireUpdated(statement.executeUpdate(), "stale dunning version");
                }
                outbox(connection, context, "dunning_case", dunningCaseId,
                        "billing.dunning.result.v1", correlationId,
                        "{\"dunning_case_id\":\"" + dunningCaseId
                                + "\",\"result\":\"" + wire(outcome)
                                + "\",\"result_digest\":\"" + resultDigest
                                + "\",\"verification_receipt_digest\":\""
                                + verification.receiptDigest() + "\"}");
            }
            return dunning(connection, context, dunningCaseId, false);
        });
    }

    private void markPastDueAndOpenDunning(Connection connection, Context context,
            Subscription subscription, UUID billingCycleId, RenewalOutcome outcome,
            String correlationId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE billing_subscription
                   SET state='past_due',version=version+1,updated_at=?
                 WHERE id=? AND tenant_id=? AND project_id=? AND version=?
                """)) {
            statement.setTimestamp(1, timestamp(clock.instant()));
            statement.setObject(2, subscription.id());
            statement.setObject(3, context.tenantId());
            statement.setObject(4, context.projectId());
            statement.setLong(5, subscription.version());
            requireUpdated(statement.executeUpdate(), "stale subscription version");
        }
        UUID caseId = UUID.randomUUID();
        Instant now = clock.instant();
        String state = outcome == RenewalOutcome.UNKNOWN
                ? "waiting_provider_query" : "scheduled";
        Instant next = outcome == RenewalOutcome.UNKNOWN ? null : now.plus(DUNNING_DELAYS[0]);
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO dunning_case
                  (id,tenant_id,project_id,subscription_id,billing_cycle_id,state,attempts,
                   maximum_attempts,next_attempt_at,grace_ends_at,version,created_at,updated_at)
                VALUES (?,?,?,?,?,?,0,?,?,?,?,?,?)
                ON CONFLICT (tenant_id,billing_cycle_id) DO NOTHING
                """)) {
            statement.setObject(1, caseId);
            statement.setObject(2, context.tenantId());
            statement.setObject(3, context.projectId());
            statement.setObject(4, subscription.id());
            statement.setObject(5, billingCycleId);
            statement.setString(6, state);
            statement.setInt(7, MAXIMUM_DUNNING_ATTEMPTS);
            statement.setTimestamp(8, next == null ? null : timestamp(next));
            statement.setTimestamp(9, timestamp(now.plus(DUNNING_GRACE)));
            statement.setLong(10, 1L);
            statement.setTimestamp(11, timestamp(now));
            statement.setTimestamp(12, timestamp(now));
            statement.executeUpdate();
        }
        outbox(connection, context, "dunning_case", caseId, "billing.dunning.opened.v1",
                correlationId, "{\"dunning_case_id\":\"" + caseId
                        + "\",\"subscription_id\":\"" + subscription.id() + "\"}");
    }

    private void updateSubscriptionPeriod(Connection connection, Context context,
            Subscription subscription, Instant start, Instant end) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE billing_subscription
                   SET state='active',period_start=?,period_end=?,usage_quantity=0,cancel_at=NULL,
                       version=version+1,updated_at=?
                 WHERE id=? AND tenant_id=? AND project_id=? AND version=?
                """)) {
            statement.setTimestamp(1, timestamp(start));
            statement.setTimestamp(2, timestamp(end));
            statement.setTimestamp(3, timestamp(clock.instant()));
            statement.setObject(4, subscription.id());
            statement.setObject(5, context.tenantId());
            statement.setObject(6, context.projectId());
            statement.setLong(7, subscription.version());
            requireUpdated(statement.executeUpdate(), "stale subscription version");
        }
    }

    private void pauseSubscription(Connection connection, Context context, UUID subscriptionId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE billing_subscription SET state='paused',version=version+1,updated_at=?
                 WHERE id=? AND tenant_id=? AND project_id=? AND state='past_due'
                """)) {
            statement.setTimestamp(1, timestamp(clock.instant()));
            statement.setObject(2, subscriptionId);
            statement.setObject(3, context.tenantId());
            statement.setObject(4, context.projectId());
            requireUpdated(statement.executeUpdate(), "subscription cannot be paused");
        }
    }

    private Plan plan(Connection connection, Context context, UUID id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT * FROM billing_plan WHERE id=? AND tenant_id=? AND project_id=?
                """)) {
            statement.setObject(1, id);
            statement.setObject(2, context.tenantId());
            statement.setObject(3, context.projectId());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw notFound("plan");
                }
                return new Plan(result.getObject("id", UUID.class),
                        result.getObject("tenant_id", UUID.class),
                        result.getObject("project_id", UUID.class), result.getString("code"),
                        result.getLong("amount_minor"), result.getString("currency"),
                        result.getLong("billing_period_seconds"),
                        result.getLong("trial_period_seconds"), result.getBoolean("metered"),
                        result.getLong("version"));
            }
        }
    }

    private Mandate mandate(Connection connection, Context context, UUID id) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT * FROM billing_mandate WHERE id=? AND tenant_id=? AND project_id=?
                """)) {
            statement.setObject(1, id);
            statement.setObject(2, context.tenantId());
            statement.setObject(3, context.projectId());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw notFound("mandate");
                }
                Timestamp revoked = result.getTimestamp("revoked_at");
                return new Mandate(result.getObject("id", UUID.class),
                        result.getObject("tenant_id", UUID.class),
                        result.getObject("project_id", UUID.class),
                        result.getString("customer_reference"), result.getString("provider"),
                        result.getString("provider_mandate_reference"),
                        result.getString("payment_method_reference"), result.getString("purpose"),
                        result.getLong("maximum_amount_minor"), result.getString("currency"),
                        result.getString("consent_digest"), result.getString("state"),
                        result.getTimestamp("consented_at").toInstant(),
                        revoked == null ? null : revoked.toInstant(), result.getLong("version"));
            }
        }
    }

    private Subscription subscription(Connection connection, Context context, UUID id,
            boolean lock) throws SQLException {
        String sql = "SELECT * FROM billing_subscription WHERE id=? AND tenant_id=? AND project_id=?"
                + (lock ? " FOR UPDATE" : "");
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, id);
            statement.setObject(2, context.tenantId());
            statement.setObject(3, context.projectId());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw notFound("subscription");
                }
                Timestamp cancelAt = result.getTimestamp("cancel_at");
                return new Subscription(result.getObject("id", UUID.class),
                        result.getObject("tenant_id", UUID.class),
                        result.getObject("project_id", UUID.class),
                        result.getString("customer_reference"),
                        result.getObject("plan_id", UUID.class),
                        result.getObject("mandate_id", UUID.class),
                        SubscriptionState.valueOf(result.getString("state").toUpperCase(Locale.ROOT)),
                        result.getTimestamp("period_start").toInstant(),
                        result.getTimestamp("period_end").toInstant(),
                        result.getLong("usage_quantity"),
                        cancelAt == null ? null : cancelAt.toInstant(), result.getLong("version"));
            }
        }
    }

    private Adjustment adjustment(Connection connection, Context context, UUID id)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT * FROM billing_adjustment WHERE id=? AND tenant_id=? AND project_id=?
                """)) {
            statement.setObject(1, id);
            statement.setObject(2, context.tenantId());
            statement.setObject(3, context.projectId());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw notFound("adjustment");
                }
                return new Adjustment(result.getObject("id", UUID.class),
                        result.getObject("subscription_id", UUID.class),
                        result.getString("operation"), result.getObject("old_plan_id", UUID.class),
                        result.getObject("new_plan_id", UUID.class),
                        result.getLong("old_unused_credit_minor"),
                        result.getLong("new_remaining_charge_minor"),
                        result.getLong("net_debit_minor"), result.getString("currency"),
                        result.getLong("remaining_seconds"), result.getLong("period_seconds"),
                        result.getTimestamp("created_at").toInstant());
            }
        }
    }

    private Dispute dispute(Connection connection, Context context, UUID id, boolean lock)
            throws SQLException {
        String sql = "SELECT * FROM provider_dispute WHERE id=? AND tenant_id=? AND project_id=?"
                + (lock ? " FOR UPDATE" : "");
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, id);
            statement.setObject(2, context.tenantId());
            statement.setObject(3, context.projectId());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw notFound("dispute");
                }
                return dispute(result);
            }
        }
    }

    private Dispute disputeByProvider(Connection connection, Context context, String provider,
            String providerDisputeId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT * FROM provider_dispute
                 WHERE tenant_id=? AND project_id=? AND provider=? AND provider_dispute_id=?
                """)) {
            statement.setObject(1, context.tenantId());
            statement.setObject(2, context.projectId());
            statement.setString(3, provider);
            statement.setString(4, providerDisputeId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw notFound("dispute");
                }
                return dispute(result);
            }
        }
    }

    private static Dispute dispute(ResultSet result) throws SQLException {
        return new Dispute(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class), result.getString("provider"),
                result.getString("provider_dispute_id"),
                result.getObject("payment_intent_id", UUID.class),
                result.getLong("amount_minor"), result.getString("currency"),
                result.getTimestamp("response_deadline").toInstant(),
                DisputeState.valueOf(result.getString("state").toUpperCase(Locale.ROOT)),
                result.getString("financial_effect_state"), result.getLong("version"));
    }

    private CycleRow cycle(Connection connection, Context context, UUID id, boolean lock)
            throws SQLException {
        String sql = "SELECT * FROM subscription_billing_cycle WHERE id=? AND tenant_id=? AND project_id=?"
                + (lock ? " FOR UPDATE" : "");
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, id);
            statement.setObject(2, context.tenantId());
            statement.setObject(3, context.projectId());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw notFound("billing cycle");
                }
                return new CycleRow(result.getObject("id", UUID.class),
                        result.getObject("subscription_id", UUID.class),
                        result.getString("state"));
            }
        }
    }

    private DunningCase dunning(Connection connection, Context context, UUID id, boolean lock)
            throws SQLException {
        String sql = "SELECT * FROM dunning_case WHERE id=? AND tenant_id=? AND project_id=?"
                + (lock ? " FOR UPDATE" : "");
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, id);
            statement.setObject(2, context.tenantId());
            statement.setObject(3, context.projectId());
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw notFound("dunning case");
                }
                return dunning(result);
            }
        }
    }

    private static DunningCase dunning(ResultSet result) throws SQLException {
        Timestamp next = result.getTimestamp("next_attempt_at");
        return new DunningCase(result.getObject("id", UUID.class),
                result.getObject("tenant_id", UUID.class),
                result.getObject("project_id", UUID.class),
                result.getObject("subscription_id", UUID.class),
                result.getObject("billing_cycle_id", UUID.class),
                DunningState.valueOf(result.getString("state").toUpperCase(Locale.ROOT)),
                result.getInt("attempts"), result.getInt("maximum_attempts"),
                next == null ? null : next.toInstant(),
                result.getTimestamp("grace_ends_at").toInstant(), result.getLong("version"));
    }

    private void verifyDisputeInbox(Connection connection, UUID tenantId, String provider,
            String eventId, String expectedDigest, String expectedReceiptDigest,
            UUID expectedDispute) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement("""
                SELECT payload_digest,verification_receipt_digest,dispute_id
                  FROM dispute_event_inbox
                 WHERE tenant_id=? AND provider=? AND provider_event_id=?
                """)) {
            query.setObject(1, tenantId);
            query.setString(2, provider);
            query.setString(3, eventId);
            try (ResultSet result = query.executeQuery()) {
                if (!result.next() || !constantEquals(expectedDigest, result.getString(1))
                        || !constantEquals(expectedReceiptDigest, result.getString(2))
                        || !expectedDispute.equals(result.getObject(3, UUID.class))) {
                    throw new CommerceRuntimeException("PROVIDER_EVENT_CONFLICT",
                            "provider event identity was reused with different input");
                }
            }
        }
    }

    private VerifiedProviderEvidence verifyEvidence(ProviderEvidenceReceipt receipt,
            String evidenceType, Map<String, String> fields) {
        if (evidenceVerifier == null || receipt == null) {
            throw new CommerceRuntimeException("UNVERIFIED_PROVIDER_RESULT",
                    "cryptographically verified provider evidence is required");
        }
        try {
            return evidenceVerifier.verify(receipt, evidenceType, fields, clock.instant());
        } catch (IllegalArgumentException | SecurityException invalidEvidence) {
            throw new CommerceRuntimeException("UNVERIFIED_PROVIDER_RESULT",
                    "provider evidence failed verification");
        }
    }

    private static Map<String, String> evidenceFields(Context context, String provider,
            String entityId, String... additional) {
        if (additional.length % 2 != 0) {
            throw new IllegalArgumentException("provider evidence fields must be key/value pairs");
        }
        java.util.LinkedHashMap<String, String> fields = new java.util.LinkedHashMap<>();
        fields.put("tenantId", context.tenantId().toString());
        fields.put("projectId", context.projectId().toString());
        fields.put("provider", provider);
        fields.put("entityId", entityId);
        for (int index = 0; index < additional.length; index += 2) {
            if (fields.putIfAbsent(additional[index], additional[index + 1]) != null) {
                throw new IllegalArgumentException("duplicate provider evidence field");
            }
        }
        return Map.copyOf(fields);
    }

    private Reservation reserve(Connection connection, Context context, String operation,
            String key, String requestDigest, UUID resourceId, String correlationId)
            throws SQLException {
        String safeKey = idempotency(key);
        String safeCorrelation = text(correlationId, "correlation id");
        Savepoint savepoint = connection.setSavepoint("commerce_receipt_insert");
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO commerce_action_receipt
                  (tenant_id,project_id,operation,idempotency_key,request_digest,resource_id,
                   actor_id,correlation_id,created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                """)) {
            statement.setObject(1, context.tenantId());
            statement.setObject(2, context.projectId());
            statement.setString(3, operation);
            statement.setString(4, safeKey);
            statement.setString(5, requestDigest);
            statement.setObject(6, resourceId);
            statement.setString(7, context.actorId());
            statement.setString(8, safeCorrelation);
            statement.setTimestamp(9, timestamp(clock.instant()));
            statement.executeUpdate();
            connection.releaseSavepoint(savepoint);
            return new Reservation(false, resourceId);
        } catch (SQLException duplicate) {
            rollbackUnique(connection, savepoint, duplicate);
            try (PreparedStatement query = connection.prepareStatement("""
                    SELECT project_id,request_digest,resource_id
                      FROM commerce_action_receipt
                     WHERE tenant_id=? AND operation=? AND idempotency_key=?
                    """)) {
                query.setObject(1, context.tenantId());
                query.setString(2, operation);
                query.setString(3, safeKey);
                try (ResultSet result = query.executeQuery()) {
                    if (!result.next() || !context.projectId().equals(
                            result.getObject("project_id", UUID.class))
                            || !constantEquals(requestDigest, result.getString("request_digest"))) {
                        throw new CommerceRuntimeException("IDEMPOTENCY_CONFLICT",
                                "idempotency key was reused with different input");
                    }
                    return new Reservation(true, result.getObject("resource_id", UUID.class));
                }
            }
        }
    }

    private void outbox(Connection connection, Context context, String aggregateType,
            UUID aggregateId, String eventType, String correlationId, String payload)
            throws SQLException {
        SemanticOutboxAppender.append(connection, new SemanticOutboxAppender.EventDraft(
                context.tenantId(), context.projectId(), aggregateType, aggregateId, eventType,
                1, clock.instant(), text(correlationId, "correlation id"),
                com.elmpay.events.StrictJson.object(payload)));
    }

    private <T> T transaction(UUID tenantId, SqlWork<T> work) {
        try (Connection connection = dataSource.getConnection()) {
            boolean previousAutoCommit = connection.getAutoCommit();
            int previousIsolation = connection.getTransactionIsolation();
            connection.setAutoCommit(false);
            connection.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            try {
                try (PreparedStatement tenant = connection.prepareStatement(
                        "SELECT set_config('app.tenant_id', ?, true)")) {
                    tenant.setString(1, tenantId.toString());
                    tenant.execute();
                }
                T value = work.run(connection);
                connection.commit();
                return value;
            } catch (RuntimeException | SQLException failure) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackFailure) {
                    failure.addSuppressed(rollbackFailure);
                }
                if (failure instanceof CommerceRuntimeException runtime) {
                    throw runtime;
                }
                throw new CommerceRuntimeException("COMMERCE_PERSISTENCE_FAILURE",
                        "commerce operation could not be persisted", failure);
            } finally {
                try {
                    connection.setTransactionIsolation(previousIsolation);
                    connection.setAutoCommit(previousAutoCommit);
                } catch (SQLException restoreFailure) {
                    // Connection close follows immediately; do not hide a committed result.
                }
            }
        } catch (SQLException failure) {
            throw new CommerceRuntimeException("COMMERCE_DATABASE_UNAVAILABLE",
                    "commerce database is unavailable", failure);
        }
    }

    static void rollbackUnique(Connection connection, Savepoint savepoint, SQLException failure)
            throws SQLException {
        if (!"23505".equals(failure.getSQLState())) {
            throw failure;
        }
        connection.rollback(savepoint);
    }

    static String paymentReference(String value) {
        String reference = opaque(value, "payment method reference");
        if (!reference.matches("^(psp|wallet|mandate)://[A-Za-z0-9._:/-]+$")) {
            throw invalid("only an opaque PSP, wallet or mandate reference is accepted");
        }
        return reference;
    }

    static String objectReference(String value) {
        String reference = opaque(value, "object reference");
        if (!reference.matches("^(s3|gcs|azure|vault)://.+$")) {
            throw invalid("evidence must use an approved object-store reference");
        }
        return reference;
    }

    private static String opaque(String value, String label) {
        String result = text(value, label);
        String compact = result.replace(" ", "").replace("-", "");
        if (compact.matches(".*[0-9]{12,19}.*")
                || result.toLowerCase(Locale.ROOT).contains("cvv")) {
            throw new CommerceRuntimeException("CARD_DATA_FORBIDDEN",
                    "raw card data is forbidden");
        }
        return result;
    }

    private static String currency(String value) {
        String normalized = text(value, "currency").toUpperCase(Locale.ROOT);
        if (!normalized.matches("[A-Z]{3}")) {
            throw invalid("currency must be ISO-4217 alpha-3");
        }
        return normalized;
    }

    private static String provider(String value) {
        String normalized = text(value, "provider").toLowerCase(Locale.ROOT);
        if (!PROVIDERS.contains(normalized)) {
            throw invalid("unsupported provider");
        }
        return normalized;
    }

    private static String sha256(String value, String label) {
        String normalized = text(value, label).toLowerCase(Locale.ROOT);
        if (!normalized.matches("[0-9a-f]{64}")) {
            throw invalid(label + " must be SHA-256 hex");
        }
        return normalized;
    }

    private static String idempotency(String value) {
        String result = text(value, "idempotency key");
        if (result.length() > 200) {
            throw invalid("idempotency key is too long");
        }
        return result;
    }

    private static String text(String value, String label) {
        if (value == null || value.isBlank() || value.length() > 512) {
            throw invalid(label + " is required and bounded");
        }
        return value;
    }

    private static String digest(String... values) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (String value : values) {
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                digest.update(Integer.toString(bytes.length).getBytes(StandardCharsets.US_ASCII));
                digest.update((byte) ':');
                digest.update(bytes);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("JDK is missing SHA-256", unavailable);
        }
    }

    private static boolean constantEquals(String left, String right) {
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.US_ASCII),
                right.getBytes(StandardCharsets.US_ASCII));
    }

    private static String wire(Enum<?> value) {
        return value.name().toLowerCase(Locale.ROOT);
    }

    private static Timestamp timestamp(Instant value) {
        return Timestamp.from(value);
    }

    private static void requireUpdated(int updated, String message) {
        if (updated != 1) {
            throw new CommerceRuntimeException("CONCURRENT_MODIFICATION", message);
        }
    }

    private static CommerceRuntimeException invalid(String message) {
        return new CommerceRuntimeException("INVALID_COMMERCE_REQUEST", message);
    }

    private static CommerceRuntimeException notFound(String resource) {
        return new CommerceRuntimeException("RESOURCE_NOT_FOUND", resource + " does not exist");
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T run(Connection connection) throws SQLException;
    }

    private record Reservation(boolean replay, UUID resourceId) {}
    private record CycleRow(UUID id, UUID subscriptionId, String state) {}
}
