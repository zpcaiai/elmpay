package com.elmpay.payment;

import com.elmpay.idempotency.RequestFingerprint;
import com.elmpay.merchant.MerchantConfigurationRepository;
import com.elmpay.merchant.ProviderAccount;
import com.elmpay.merchant.ProviderRoute;
import com.elmpay.merchant.RoutingRequest;
import com.elmpay.merchant.RoutingException;
import com.elmpay.merchant.RoutingService;
import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderPayment;
import com.elmpay.provider.ProviderRequestContext;
import com.elmpay.risk.RiskAction;
import com.elmpay.risk.RiskEvaluationRequest;
import com.elmpay.risk.RiskGateEnforcer;
import com.elmpay.risk.RiskGateException;
import com.elmpay.risk.RiskOperation;
import com.elmpay.risk.SynchronousRiskGate;
import com.elmpay.security.CanonicalPayload;
import com.elmpay.security.SensitiveDataGuard;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Application service for B32-B36 payment intent and provider-attempt behavior. */
public final class PaymentService {
    private static final String DIRECT_CANCEL_OPERATION = "DIRECT_CANCEL";
    private final PaymentRepository repository;
    private final MerchantConfigurationRepository merchantConfiguration;
    private final RoutingService routing;
    private final ProviderAdapterRegistry adapters;
    private final SynchronousRiskGate riskGate;
    private final PaymentStateMachine stateMachine;
    private final Clock clock;
    private final Duration attemptLease;

    public PaymentService(PaymentRepository repository,
            MerchantConfigurationRepository merchantConfiguration, RoutingService routing,
            ProviderAdapterRegistry adapters, SynchronousRiskGate riskGate, Clock clock) {
        this(repository, merchantConfiguration, routing, adapters, riskGate, clock,
                Duration.ofSeconds(30));
    }

    public PaymentService(PaymentRepository repository,
            MerchantConfigurationRepository merchantConfiguration, RoutingService routing,
            ProviderAdapterRegistry adapters, SynchronousRiskGate riskGate, Clock clock,
            Duration attemptLease) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.merchantConfiguration = Objects.requireNonNull(
                merchantConfiguration, "merchantConfiguration");
        this.routing = Objects.requireNonNull(routing, "routing");
        this.adapters = Objects.requireNonNull(adapters, "adapters");
        this.riskGate = Objects.requireNonNull(riskGate, "riskGate");
        this.stateMachine = new PaymentStateMachine();
        this.clock = Objects.requireNonNull(clock, "clock");
        this.attemptLease = Objects.requireNonNull(attemptLease, "attemptLease");
        if (attemptLease.isZero() || attemptLease.isNegative()) {
            throw new IllegalArgumentException("attemptLease must be positive");
        }
    }

    public PaymentIntent create(CreateIntentCommand command) {
        RequestFingerprint.validateKey(command.idempotencyKey());
        PaymentIntent replay = repository.findByCreateKey(command.tenantId(), command.projectId(),
                command.idempotencyKey()).orElse(null);
        if (replay != null) {
            requireSameCreateRequest(replay, command);
            return replay;
        }
        PaymentIntent byOrder = repository.findByExternalReference(command.tenantId(),
                command.projectId(), command.externalReference()).orElse(null);
        if (byOrder != null) {
            requireSameCreateRequest(byOrder, command);
            return byOrder;
        }
        requireRiskApproval(new RiskEvaluationRequest(command.tenantId().toString(),
                command.projectId().toString(),
                riskRequestId(RiskOperation.PAYMENT_CREATE, command.idempotencyKey()),
                RiskOperation.PAYMENT_CREATE, command.merchantId().toString(),
                command.amount().amountMinor(), command.amount().currency().code(), clock.instant(),
                Map.of("projectId", command.projectId().toString(),
                        "merchantId", command.merchantId().toString(),
                        "region", command.region().toUpperCase(java.util.Locale.ROOT),
                        "confirmationMode", command.confirmationMode().name(),
                        "paymentMethods", command.allowedMethods().stream().sorted()
                                .collect(java.util.stream.Collectors.joining(",")))));
        return repository.create(PaymentIntent.create(command, clock));
    }

    public PaymentIntent get(UUID tenantId, UUID intentId) {
        return requireIntent(tenantId, intentId);
    }

    public List<PaymentAttempt> attempts(UUID tenantId, UUID intentId) {
        return repository.attempts(tenantId, intentId);
    }

    public PaymentIntent cancel(IntentActionCommand command) {
        RequestFingerprint.validateKey(command.idempotencyKey());
        PaymentIntent intent = requireIntent(command.tenantId(), command.intentId());
        String requestDigest = directCancelDigest(intent, command);
        requireNoProviderAttemptKey(intent, command.idempotencyKey());
        PaymentActionReceipt replay = repository.findActionReceipt(intent.tenantId(), intent.id(),
                command.idempotencyKey()).orElse(null);
        if (replay != null) {
            if (!replay.matches(DIRECT_CANCEL_OPERATION, requestDigest)) {
                throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                        "action key was reused for a different operation or canonical payload");
            }
            if (intent.state() != IntentState.CANCELED
                    || intent.version() < replay.resultIntentVersion()) {
                throw new PaymentCoreException("ACTION_RECEIPT_INCONSISTENT",
                        "cancel receipt does not match the stored payment intent");
            }
            return intent;
        }
        if (intent.state() != IntentState.CREATED && intent.state() != IntentState.REQUIRES_ACTION) {
            throw new PaymentCoreException("CANCEL_NOT_ALLOWED",
                    "only an uncaptured, unauthorized intent can be canceled directly");
        }
        PaymentIntent canceled = stateMachine.transition(intent, IntentState.CANCELED,
                AuthoritySource.MERCHANT_REQUEST, clock.instant());
        PaymentActionReceipt receipt = new PaymentActionReceipt(intent.tenantId(), intent.id(),
                DIRECT_CANCEL_OPERATION, command.idempotencyKey(), requestDigest,
                canceled.version(), clock.instant());
        return repository.updateWithActionReceipt(canceled, intent.version(), receipt,
                "payment.intent.canceled.v1", command.correlationId());
    }

    public ConfirmationResult confirm(ConfirmationCommand command) {
        RequestFingerprint.validateKey(command.idempotencyKey());
        PaymentIntent intent = requireIntent(command.tenantId(), command.intentId());
        Map<String, String> parameters = new LinkedHashMap<>(command.providerParameters());
        parameters.put("payment_method_reference", command.paymentMethod().reference().toString());
        parameters.put("payment_method_fingerprint", command.paymentMethod().fingerprint());
        SensitiveDataGuard.assertSafe(parameters);
        String requestDigest = confirmationDigest(intent, command, parameters);
        PaymentAttempt replay = findAttemptByKey(intent, command.idempotencyKey(),
                AttemptOperation.PAYMENT, requestDigest);
        if (replay != null) {
            if (replay.state() == AttemptState.INITIATED) {
                throw new PaymentCoreException("ATTEMPT_IN_PROGRESS", "provider call is in progress");
            }
            return new ConfirmationResult(intent, replay, Map.of(), true);
        }
        if (clock.instant().isAfter(intent.expiresAt())) {
            throw new PaymentCoreException("PAYMENT_INTENT_EXPIRED", "expired intent cannot be confirmed");
        }
        if (intent.state() != IntentState.CREATED && intent.state() != IntentState.REQUIRES_ACTION) {
            throw new PaymentCoreException("STATE_TRANSITION_NOT_ALLOWED",
                    "payment intent cannot be confirmed in its current state");
        }
        if (!intent.permitsMethod(command.paymentMethod().method())) {
            throw new PaymentCoreException("PAYMENT_METHOD_NOT_ALLOWED",
                    "payment method is outside the immutable intent snapshot");
        }
        requireRiskApproval(new RiskEvaluationRequest(intent.tenantId().toString(),
                intent.projectId().toString(),
                riskRequestId(RiskOperation.PAYMENT_CONFIRM, command.idempotencyKey()),
                RiskOperation.PAYMENT_CONFIRM, command.paymentMethod().fingerprint(),
                intent.amount().amountMinor(), intent.amount().currency().code(), clock.instant(),
                Map.of("intentId", intent.id().toString(),
                        "projectId", intent.projectId().toString(),
                        "merchantId", intent.merchantId().toString(),
                        "paymentMethod", command.paymentMethod().method(),
                        "region", intent.region())));

        ProviderRoute route;
        try {
            route = routing.select(new RoutingRequest(intent.tenantId(), intent.projectId(),
                    intent.merchantId(), command.paymentMethod().method(),
                    intent.amount().currency().code(), intent.region(),
                    intent.amount().amountMinor(), intent.id().toString()));
        } catch (RoutingException exception) {
            throw new PaymentCoreException(exception.code(), exception.getMessage(), exception);
        }
        PaymentAttempt attempt = beginAttempt(new AttemptDraft(intent.tenantId(),
                intent.id(), route.account().id(), route.account().provider(),
                AttemptOperation.PAYMENT, intent.version(), requestDigest,
                command.idempotencyKey(), attemptStartedAt(), newLeaseOwner("dispatch"),
                attemptLeaseExpiresAt()));
        ProviderRequestContext context = context(route.account(), command.idempotencyKey(),
                command.correlationId());
        ProviderAdapter adapter = adapters.require(route.account().provider());
        try {
            ProviderPayment providerPayment = adapter.createPayment(new CreatePaymentCommand(context,
                    intent.id(), intent.externalReference(), intent.amount(),
                    command.paymentMethod().method(), command.approvedReturnRouteId(), parameters));
            return commitProviderResult(intent, attempt, providerPayment, command.correlationId(),
                    AttemptOperation.PAYMENT, 0);
        } catch (ProviderException exception) {
            return commitProviderException(intent, attempt, exception, command.correlationId());
        }
    }

    public ConfirmationResult capture(CaptureCommand command) {
        RequestFingerprint.validateKey(command.idempotencyKey());
        PaymentIntent intent = requireIntent(command.tenantId(), command.intentId());
        String requestDigest = captureDigest(intent, command);
        PaymentAttempt replay = findAttemptByKey(intent, command.idempotencyKey(),
                AttemptOperation.CAPTURE, requestDigest);
        if (replay != null) {
            return new ConfirmationResult(intent, replay, Map.of(), true);
        }
        long cumulativeCapture;
        try {
            cumulativeCapture = Math.addExact(intent.capturedAmountMinor(), command.amountMinor());
        } catch (ArithmeticException exception) {
            throw new PaymentCoreException("CAPTURE_EXCEEDS_AUTHORIZED",
                    "cumulative capture exceeds the authorized amount", exception);
        }
        stateMachine.recordCapture(intent, cumulativeCapture,
                cumulativeCapture == intent.amount().amountMinor(),
                AuthoritySource.SERVER_SIDE_PROVIDER_RESULT, clock.instant());
        requireRiskApproval(new RiskEvaluationRequest(intent.tenantId().toString(),
                intent.projectId().toString(),
                riskRequestId(RiskOperation.PAYMENT_CAPTURE, command.idempotencyKey()),
                RiskOperation.PAYMENT_CAPTURE, intent.id().toString(), command.amountMinor(),
                intent.amount().currency().code(), clock.instant(),
                Map.of("intentId", intent.id().toString(),
                        "projectId", intent.projectId().toString(),
                        "merchantId", intent.merchantId().toString(),
                        "region", intent.region())));
        PaymentAttempt source = lastProviderTransaction(intent);
        ProviderAccount account = requireAccount(intent, source.providerAccountId());
        Money requested = Money.of(command.amountMinor(), intent.amount().currency().code());
        PaymentAttempt attempt = beginAttempt(new AttemptDraft(intent.tenantId(),
                intent.id(), account.id(), account.provider(), AttemptOperation.CAPTURE,
                intent.version(), requestDigest, command.idempotencyKey(), attemptStartedAt(),
                newLeaseOwner("dispatch"), attemptLeaseExpiresAt(), command.amountMinor(),
                intent.amount().currency().code(),
                ProviderEffectExpectationService.businessOrderDigest(
                        intent.externalReference())));
        try {
            ProviderPayment payment = adapters.require(account.provider()).capture(
                    context(account, command.idempotencyKey(), command.correlationId()),
                    source.providerTransactionId(), requested);
            return commitProviderResult(intent, attempt, payment, command.correlationId(),
                    AttemptOperation.CAPTURE, command.amountMinor());
        } catch (ProviderException exception) {
            return commitProviderException(intent, attempt, exception, command.correlationId());
        }
    }

    public ConfirmationResult voidAuthorization(IntentActionCommand command) {
        RequestFingerprint.validateKey(command.idempotencyKey());
        PaymentIntent intent = requireIntent(command.tenantId(), command.intentId());
        String requestDigest = voidDigest(intent, command);
        PaymentAttempt replay = findAttemptByKey(intent, command.idempotencyKey(),
                AttemptOperation.CANCEL, requestDigest);
        if (replay != null) {
            return new ConfirmationResult(intent, replay, Map.of(), true);
        }
        // Ask the state machine, do not re-decide here: the three exits from an active
        // authorization are its invariant (B34 CAP-I2), and a second copy of the guard is how
        // the two drift apart.
        stateMachine.voidAuthorization(intent, AuthoritySource.SERVER_SIDE_PROVIDER_RESULT,
                clock.instant());
        PaymentAttempt source = lastProviderTransaction(intent);
        ProviderAccount account = requireAccount(intent, source.providerAccountId());
        PaymentAttempt attempt = beginAttempt(new AttemptDraft(intent.tenantId(),
                intent.id(), account.id(), account.provider(), AttemptOperation.CANCEL,
                intent.version(), requestDigest, command.idempotencyKey(), attemptStartedAt(),
                newLeaseOwner("dispatch"), attemptLeaseExpiresAt()));
        try {
            ProviderPayment payment = adapters.require(account.provider()).cancel(
                    context(account, command.idempotencyKey(), command.correlationId()),
                    source.providerTransactionId(), command.reason());
            return commitProviderResult(intent, attempt, payment, command.correlationId(),
                    AttemptOperation.CANCEL, 0);
        } catch (ProviderException exception) {
            return commitProviderException(intent, attempt, exception, command.correlationId());
        }
    }

    /**
     * Release the uncaptured remainder after a partial capture.
     *
     * <p>The provider call is the same cancel the void path uses — the difference is what it
     * means locally. A void undoes a payment that never took money; a close ends one that took
     * some and will not take the rest.
     */
    public ConfirmationResult closeAuthorization(IntentActionCommand command) {
        RequestFingerprint.validateKey(command.idempotencyKey());
        PaymentIntent intent = requireIntent(command.tenantId(), command.intentId());
        String requestDigest = closeDigest(intent, command);
        PaymentAttempt replay = findAttemptByKey(intent, command.idempotencyKey(),
                AttemptOperation.CLOSE, requestDigest);
        if (replay != null) {
            return new ConfirmationResult(intent, replay, Map.of(), true);
        }
        stateMachine.closeAfterPartialCapture(intent, AuthoritySource.SERVER_SIDE_PROVIDER_RESULT,
                clock.instant());
        PaymentAttempt source = lastProviderTransaction(intent);
        ProviderAccount account = requireAccount(intent, source.providerAccountId());
        PaymentAttempt attempt = beginAttempt(new AttemptDraft(intent.tenantId(),
                intent.id(), account.id(), account.provider(), AttemptOperation.CLOSE,
                intent.version(), requestDigest, command.idempotencyKey(), attemptStartedAt(),
                newLeaseOwner("dispatch"), attemptLeaseExpiresAt()));
        try {
            ProviderPayment payment = adapters.require(account.provider()).cancel(
                    context(account, command.idempotencyKey(), command.correlationId()),
                    source.providerTransactionId(), command.reason());
            return commitClose(intent, attempt, payment, command.correlationId());
        } catch (ProviderException exception) {
            return commitProviderException(intent, attempt, exception, command.correlationId());
        }
    }

    public ConfirmationResult resolveUnknown(UUID tenantId, UUID intentId, String correlationId) {
        PaymentIntent intent = requireIntent(tenantId, intentId);
        InstantLease recoveryLease = newLease("recovery");
        PaymentAttempt source = repository.claimRecoverableAttempt(tenantId, intentId,
                recoveryLease.owner(), recoveryLease.startedAt(), recoveryLease.expiresAt())
                .orElseThrow(() -> new PaymentCoreException("NO_UNKNOWN_ATTEMPT",
                        "intent has no expired unresolved provider outcome"));
        ProviderAccount account = requireAccount(intent, source.providerAccountId());
        String key = "query:" + UUID.randomUUID();
        String requestDigest = CanonicalPayload.sha256Hex(Map.of(
                "intent_id", intent.id().toString(), "operation", "query",
                "provider_transaction_id", value(source.providerTransactionId()),
                "external_reference", intent.externalReference()));
        InstantLease queryLease = newLease("query");
        PaymentAttempt query = beginAttempt(new AttemptDraft(intent.tenantId(),
                intent.id(), account.id(), account.provider(), AttemptOperation.QUERY,
                intent.version(), requestDigest, key, queryLease.startedAt(), queryLease.owner(),
                queryLease.expiresAt()));
        try {
            ProviderPayment payment = adapters.require(account.provider()).queryPayment(
                    context(account, key, correlationId), source.providerTransactionId(),
                    intent.externalReference());
            return commitRecoveryResult(intent, source, query, payment, correlationId);
        } catch (ProviderException exception) {
            ConfirmationResult failure = commitProviderException(intent, query, exception,
                    correlationId);
            repository.releaseAttemptLease(source, clock.instant());
            return failure;
        }
    }

    private ConfirmationResult commitProviderException(PaymentIntent intent, PaymentAttempt attempt,
            ProviderException exception, String correlationId) {
        AttemptState state = exception.outcomeUnknown() ? AttemptState.UNKNOWN : AttemptState.FAILED;
        OutcomeClass outcome = exception.outcomeUnknown() ? OutcomeClass.UNKNOWN
                : exception.retryable() ? OutcomeClass.FAILED_RETRYABLE : OutcomeClass.FAILED_FINAL;
        String digest = CanonicalPayload.sha256Hex(Map.of(
                "code", exception.code(), "outcome_unknown", exception.outcomeUnknown(),
                "retryable", exception.retryable()));
        AttemptResolution resolution = new AttemptResolution(state, outcome, digest,
                "provider-exception", null, "adapter.normalized", exception.code(), clock.instant());
        PaymentAttempt resolved = attempt.resolve(resolution);
        repository.resolveAttempt(resolved, intent, intent.version(), "payment.attempt.resolved.v1",
                correlationId);
        return new ConfirmationResult(intent, resolved, Map.of(), false);
    }

    private ConfirmationResult commitProviderResult(PaymentIntent intent, PaymentAttempt attempt,
            ProviderPayment payment, String correlationId, AttemptOperation operation,
            long requestedCaptureAmount) {
        validateOrRecordInvalidResult(intent, attempt, payment, correlationId, operation,
                requestedCaptureAmount);
        AttemptResolution resolution = normalize(payment, operation);
        PaymentAttempt resolved = attempt.resolve(resolution);
        PaymentIntent next = nextIntent(intent, payment, operation, requestedCaptureAmount);
        repository.resolveAttempt(resolved, next, intent.version(), eventType(operation), correlationId);
        return new ConfirmationResult(next, resolved, payment.clientAction(), false);
    }

    private ConfirmationResult commitClose(PaymentIntent intent, PaymentAttempt attempt,
            ProviderPayment payment, String correlationId) {
        validateOrRecordInvalidResult(intent, attempt, payment, correlationId,
                AttemptOperation.CLOSE, 0);
        AttemptResolution resolution = normalize(payment, AttemptOperation.CLOSE);
        PaymentAttempt resolved = attempt.resolve(resolution);
        PaymentIntent next = intent;
        if (payment.outcome() == ProviderOutcome.CANCELED
                || payment.outcome() == ProviderOutcome.SUCCEEDED) {
            next = stateMachine.closeAfterPartialCapture(intent,
                    AuthoritySource.SERVER_SIDE_PROVIDER_RESULT, clock.instant());
        }
        repository.resolveAttempt(resolved, next, intent.version(),
                "payment.authorization.closed.v1", correlationId);
        return new ConfirmationResult(next, resolved, payment.clientAction(), false);
    }

    private ConfirmationResult commitRecoveryResult(PaymentIntent intent, PaymentAttempt source,
            PaymentAttempt query, ProviderPayment payment, String correlationId) {
        validateOrRecordRecoveryResult(intent, source, query, payment, correlationId,
                source.operation());
        AttemptResolution recoveredResolution = normalize(payment, source.operation());
        AttemptResolution sourceResolution = new AttemptResolution(recoveredResolution.state(),
                recoveredResolution.outcomeClass(), recoveredResolution.responseDigest(),
                recoveredResolution.providerRequestId(),
                payment.providerPaymentId() == null
                        ? source.providerTransactionId() : payment.providerPaymentId(),
                "adapter.query.normalized", recoveredResolution.providerCode(),
                recoveredResolution.finishedAt());
        PaymentAttempt resolvedSource = source.resolve(sourceResolution);
        PaymentAttempt resolvedQuery = query.resolve(recoveredResolution);
        PaymentIntent next = nextRecoveredIntent(intent, payment, source.operation());
        repository.resolveRecovery(resolvedSource, resolvedQuery, next, intent.version(),
                "payment.query.recovered.v1", correlationId);
        return new ConfirmationResult(next, resolvedQuery, payment.clientAction(), false);
    }

    private void validateOrRecordRecoveryResult(PaymentIntent intent, PaymentAttempt source,
            PaymentAttempt query, ProviderPayment payment, String correlationId,
            AttemptOperation sourceOperation) {
        try {
            validateRecoveryAmounts(intent, payment, sourceOperation);
        } catch (PaymentCoreException validationFailure) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("code", validationFailure.code());
            evidence.put("source_operation", sourceOperation.name());
            evidence.put("outcome", payment.outcome().name());
            evidence.put("provider_request_id", payment.providerRequestId());
            evidence.put("provider_transaction_id", value(payment.providerPaymentId()));
            evidence.put("authorized_minor", payment.authorized() == null
                    ? -1 : payment.authorized().amountMinor());
            evidence.put("captured_minor", payment.captured() == null
                    ? -1 : payment.captured().amountMinor());
            PaymentAttempt invalid = query.resolve(new AttemptResolution(AttemptState.UNKNOWN,
                    OutcomeClass.UNKNOWN, CanonicalPayload.sha256Hex(evidence),
                    payment.providerRequestId(), payment.providerPaymentId(),
                    "adapter.query.invalid_result", validationFailure.code(), clock.instant()));
            repository.resolveAttempt(invalid, intent, intent.version(),
                    "payment.query.invalid_provider_result.v1", correlationId);
            repository.releaseAttemptLease(source, clock.instant());
            throw validationFailure;
        }
    }

    private void validateOrRecordInvalidResult(PaymentIntent intent, PaymentAttempt attempt,
            ProviderPayment payment, String correlationId, AttemptOperation operation,
            long requestedCaptureAmount) {
        try {
            validateProviderAmounts(intent, payment, operation, requestedCaptureAmount);
        } catch (PaymentCoreException validationFailure) {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("code", validationFailure.code());
            evidence.put("outcome", payment.outcome().name());
            evidence.put("provider_request_id", payment.providerRequestId());
            evidence.put("provider_transaction_id", value(payment.providerPaymentId()));
            evidence.put("authorized_minor", payment.authorized() == null
                    ? -1 : payment.authorized().amountMinor());
            evidence.put("authorized_currency", payment.authorized() == null
                    ? "" : payment.authorized().currency().code());
            evidence.put("captured_minor", payment.captured() == null
                    ? -1 : payment.captured().amountMinor());
            evidence.put("captured_currency", payment.captured() == null
                    ? "" : payment.captured().currency().code());
            PaymentAttempt invalid = attempt.resolve(new AttemptResolution(AttemptState.UNKNOWN,
                    OutcomeClass.UNKNOWN, CanonicalPayload.sha256Hex(evidence),
                    payment.providerRequestId(), payment.providerPaymentId(),
                    "adapter.invalid_result", validationFailure.code(), clock.instant()));
            repository.resolveAttempt(invalid, intent, intent.version(),
                    "payment.attempt.invalid_provider_result.v1", correlationId);
            throw validationFailure;
        }
    }

    private PaymentIntent nextIntent(PaymentIntent intent, ProviderPayment payment,
            AttemptOperation operation, long requestedCaptureAmount) {
        ProviderOutcome outcome = payment.outcome();
        if (operation == AttemptOperation.PAYMENT || operation == AttemptOperation.QUERY) {
            if (outcome == ProviderOutcome.REQUIRES_ACTION) {
                return stateMachine.transition(intent, IntentState.REQUIRES_ACTION,
                        AuthoritySource.SERVER_SIDE_PROVIDER_RESULT, clock.instant());
            }
            if (outcome == ProviderOutcome.AUTHORIZED) {
                return stateMachine.transition(intent, IntentState.AUTHORIZED,
                        AuthoritySource.SERVER_SIDE_PROVIDER_RESULT, clock.instant());
            }
            if (outcome == ProviderOutcome.SUCCEEDED) {
                return stateMachine.recordCapture(intent, intent.amount().amountMinor(), true,
                        AuthoritySource.SERVER_SIDE_PROVIDER_RESULT, clock.instant());
            }
            return intent;
        }
        if (operation == AttemptOperation.CAPTURE && outcome == ProviderOutcome.SUCCEEDED) {
            long expected = Math.addExact(intent.capturedAmountMinor(), requestedCaptureAmount);
            return stateMachine.recordCapture(intent, expected,
                    expected == intent.amount().amountMinor(),
                    AuthoritySource.SERVER_SIDE_PROVIDER_RESULT, clock.instant());
        }
        if (operation == AttemptOperation.CANCEL
                && (outcome == ProviderOutcome.CANCELED || outcome == ProviderOutcome.SUCCEEDED)) {
            return stateMachine.transition(intent, IntentState.CANCELED,
                    AuthoritySource.SERVER_SIDE_PROVIDER_RESULT, clock.instant());
        }
        if (operation == AttemptOperation.CLOSE
                && (outcome == ProviderOutcome.CANCELED || outcome == ProviderOutcome.SUCCEEDED)) {
            return stateMachine.closeAfterPartialCapture(intent,
                    AuthoritySource.SERVER_SIDE_PROVIDER_RESULT, clock.instant());
        }
        return intent;
    }

    private PaymentIntent nextRecoveredIntent(PaymentIntent intent, ProviderPayment payment,
            AttemptOperation sourceOperation) {
        if (sourceOperation == AttemptOperation.CAPTURE
                && payment.outcome() == ProviderOutcome.SUCCEEDED) {
            long cumulative = payment.captured().amountMinor();
            return stateMachine.recordCapture(intent, cumulative,
                    cumulative == intent.amount().amountMinor(),
                    AuthoritySource.SERVER_SIDE_PROVIDER_RESULT, clock.instant());
        }
        return nextIntent(intent, payment, sourceOperation, 0);
    }

    private AttemptResolution normalize(ProviderPayment payment, AttemptOperation operation) {
        AttemptState state = AttemptState.UNKNOWN;
        OutcomeClass outcomeClass = OutcomeClass.UNKNOWN;
        switch (payment.outcome()) {
            case AUTHORIZED -> {
                if (operation == AttemptOperation.PAYMENT || operation == AttemptOperation.QUERY) {
                    state = AttemptState.SUCCEEDED;
                    outcomeClass = OutcomeClass.SUCCEEDED;
                }
            }
            case SUCCEEDED -> {
                state = AttemptState.SUCCEEDED;
                outcomeClass = OutcomeClass.SUCCEEDED;
            }
            case CANCELED -> {
                if (operation == AttemptOperation.CANCEL || operation == AttemptOperation.CLOSE) {
                    state = AttemptState.SUCCEEDED;
                    outcomeClass = OutcomeClass.SUCCEEDED;
                } else {
                    state = AttemptState.FAILED;
                    outcomeClass = OutcomeClass.FAILED_FINAL;
                }
            }
            case DECLINED, FAILED -> {
                state = AttemptState.FAILED;
                outcomeClass = OutcomeClass.FAILED_FINAL;
            }
            case REQUIRES_ACTION -> {
                // The provider call itself completed successfully and produced a durable
                // client action. It must not block the follow-up confirmation call.
                if (operation == AttemptOperation.PAYMENT || operation == AttemptOperation.QUERY) {
                    state = AttemptState.SUCCEEDED;
                    outcomeClass = OutcomeClass.SUCCEEDED;
                }
            }
            case UNKNOWN -> {
                state = AttemptState.UNKNOWN;
                outcomeClass = OutcomeClass.UNKNOWN;
            }
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("provider_request_id", payment.providerRequestId());
        evidence.put("provider_transaction_id", value(payment.providerPaymentId()));
        evidence.put("outcome", payment.outcome().name());
        evidence.put("authorized_minor", payment.authorized() == null
                ? -1 : payment.authorized().amountMinor());
        evidence.put("captured_minor", payment.captured() == null
                ? -1 : payment.captured().amountMinor());
        String providerCode = payment.clientAction().getOrDefault(
                "provider_code", payment.outcome().name());
        return new AttemptResolution(state, outcomeClass, CanonicalPayload.sha256Hex(evidence),
                payment.providerRequestId(), payment.providerPaymentId(), "adapter.normalized",
                providerCode, clock.instant());
    }

    private static void validateProviderAmounts(PaymentIntent intent, ProviderPayment payment,
            AttemptOperation operation, long requestedCaptureAmount) {
        if (operation == AttemptOperation.PAYMENT || operation == AttemptOperation.QUERY) {
            requireCurrencyIfPresent(payment.authorized(), intent.amount());
            requireCurrencyIfPresent(payment.captured(), intent.amount());
            if (payment.outcome() == ProviderOutcome.AUTHORIZED) {
                requireExactProviderAmount(payment.authorized(), intent.amount(), "authorization");
            } else if (payment.outcome() == ProviderOutcome.SUCCEEDED) {
                requireExactProviderAmount(payment.captured(), intent.amount(), "successful payment");
                if (payment.authorized() != null) {
                    requireExactProviderAmount(payment.authorized(), intent.amount(),
                            "successful payment authorization");
                }
            }
        } else if (operation == AttemptOperation.CAPTURE
                && payment.outcome() == ProviderOutcome.SUCCEEDED) {
            Money expected = Money.of(requestedCaptureAmount, intent.amount().currency().code());
            requireCurrencyIfPresent(payment.authorized(), expected);
            requireExactProviderAmount(payment.captured(), expected, "capture");
        }
    }

    private static void validateRecoveryAmounts(PaymentIntent intent, ProviderPayment payment,
            AttemptOperation sourceOperation) {
        if (sourceOperation == AttemptOperation.PAYMENT) {
            validateProviderAmounts(intent, payment, AttemptOperation.PAYMENT, 0);
            return;
        }
        if (sourceOperation == AttemptOperation.CAPTURE
                && payment.outcome() == ProviderOutcome.SUCCEEDED) {
            Money captured = payment.captured();
            if (captured == null) {
                throw new PaymentCoreException("PROVIDER_AMOUNT_MISSING",
                        "provider capture query is missing the cumulative captured amount");
            }
            requireCurrencyIfPresent(captured, intent.amount());
            if (captured.amountMinor() <= intent.capturedAmountMinor()
                    || captured.amountMinor() > intent.amount().amountMinor()) {
                throw new PaymentCoreException("PROVIDER_AMOUNT_MISMATCH",
                        "provider capture query returned an invalid cumulative captured amount");
            }
        }
    }

    private static void requireCurrencyIfPresent(Money actual, Money expected) {
        if (actual != null
                && !actual.currency().code().equals(expected.currency().code())) {
            throw new PaymentCoreException("PROVIDER_CURRENCY_MISMATCH",
                    "provider money currency does not match the immutable intent currency");
        }
    }

    private static void requireExactProviderAmount(Money actual, Money expected,
            String amountKind) {
        if (actual == null) {
            throw new PaymentCoreException("PROVIDER_AMOUNT_MISSING",
                    "provider " + amountKind + " is missing a trusted amount");
        }
        requireCurrencyIfPresent(actual, expected);
        if (actual.amountMinor() != expected.amountMinor()) {
            throw new PaymentCoreException("PROVIDER_AMOUNT_MISMATCH",
                    "provider " + amountKind + " amount does not match the requested amount");
        }
    }

    private static String confirmationDigest(PaymentIntent intent, ConfirmationCommand command,
            Map<String, String> parameters) {
        return CanonicalPayload.sha256Hex(Map.ofEntries(
                Map.entry("intent_id", intent.id().toString()),
                Map.entry("operation", AttemptOperation.PAYMENT.name()),
                Map.entry("amount_minor", intent.amount().amountMinor()),
                Map.entry("currency", intent.amount().currency().code()),
                Map.entry("method", command.paymentMethod().method()),
                Map.entry("approved_return_route_id", value(command.approvedReturnRouteId())),
                Map.entry("parameters", parameters)));
    }

    private static String captureDigest(PaymentIntent intent, CaptureCommand command) {
        return CanonicalPayload.sha256Hex(Map.of(
                "intent_id", intent.id().toString(),
                "operation", AttemptOperation.CAPTURE.name(),
                "amount_minor", command.amountMinor(),
                "currency", intent.amount().currency().code()));
    }

    private static String voidDigest(PaymentIntent intent, IntentActionCommand command) {
        return CanonicalPayload.sha256Hex(Map.of(
                "intent_id", intent.id().toString(),
                "operation", AttemptOperation.CANCEL.name(),
                "reason", command.reason()));
    }

    private static String closeDigest(PaymentIntent intent, IntentActionCommand command) {
        // Deliberately not voidDigest: a void and a close of the same intent with the same reason
        // must not collide in the idempotency replay lookup. They release different amounts.
        return CanonicalPayload.sha256Hex(Map.of(
                "intent_id", intent.id().toString(),
                "operation", AttemptOperation.CLOSE.name(),
                "captured_minor", intent.capturedAmountMinor(),
                "reason", command.reason()));
    }

    private static String directCancelDigest(PaymentIntent intent, IntentActionCommand command) {
        return CanonicalPayload.sha256Hex(Map.of(
                "intent_id", intent.id().toString(),
                "operation", DIRECT_CANCEL_OPERATION,
                "reason", command.reason()));
    }

    private PaymentAttempt findAttemptByKey(PaymentIntent intent, String key,
            AttemptOperation expectedOperation, String expectedDigest) {
        if (repository.findActionReceipt(intent.tenantId(), intent.id(), key).isPresent()) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "idempotency key already belongs to a non-provider payment action");
        }
        PaymentAttempt replay = repository.attempts(intent.tenantId(), intent.id()).stream()
                .filter(attempt -> attempt.idempotencyKey().equals(key))
                .findFirst().orElse(null);
        if (replay != null && (replay.operation() != expectedOperation
                || !replay.requestDigest().equals(expectedDigest))) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "idempotency key was reused for a different operation or canonical payload");
        }
        return replay;
    }

    private void requireNoProviderAttemptKey(PaymentIntent intent, String key) {
        if (repository.attempts(intent.tenantId(), intent.id()).stream()
                .anyMatch(attempt -> attempt.idempotencyKey().equals(key))) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "idempotency key already belongs to a provider operation");
        }
    }

    private PaymentAttempt lastProviderTransaction(PaymentIntent intent) {
        List<PaymentAttempt> candidates = new ArrayList<>(
                repository.attempts(intent.tenantId(), intent.id()));
        for (int index = candidates.size() - 1; index >= 0; index--) {
            PaymentAttempt attempt = candidates.get(index);
            if (attempt.providerTransactionId() != null) {
                return attempt;
            }
        }
        throw new PaymentCoreException("PROVIDER_TRANSACTION_MISSING",
                "intent has no attributable provider transaction");
    }

    private ProviderAccount requireAccount(PaymentIntent intent, UUID accountId) {
        return merchantConfiguration.findAccount(intent.tenantId(), intent.projectId(), accountId)
                .orElseThrow(() -> new PaymentCoreException("PROVIDER_ACCOUNT_NOT_FOUND",
                        "provider account does not belong to this tenant and project"));
    }

    private PaymentIntent requireIntent(UUID tenantId, UUID intentId) {
        return repository.find(tenantId, intentId).orElseThrow(() -> new PaymentCoreException(
                "RESOURCE_NOT_FOUND", "payment intent does not exist in this tenant"));
    }

    private static ProviderRequestContext context(ProviderAccount account, String key,
            String correlationId) {
        return new ProviderRequestContext(account.tenantId(), account.projectId(), account.id(),
                key, correlationId, account.credentialVersion());
    }

    private void requireRiskApproval(RiskEvaluationRequest request) {
        try {
            RiskGateEnforcer.requireApproved(riskGate, request);
        } catch (RiskGateException exception) {
            String code = exception.action() == RiskAction.BLOCK
                    ? "RISK_BLOCKED" : "RISK_REVIEW_REQUIRED";
            throw new PaymentCoreException(code, exception.getMessage(), exception);
        }
    }

    private static String riskRequestId(RiskOperation operation, String idempotencyKey) {
        return operation.name() + ":" + idempotencyKey;
    }

    private static void requireSameCreateRequest(PaymentIntent existing,
            CreateIntentCommand command) {
        boolean same = existing.projectId().equals(command.projectId())
                && existing.merchantId().equals(command.merchantId())
                && existing.externalReference().equals(command.externalReference())
                && existing.amount().equals(command.amount())
                && existing.allowedMethods().equals(command.allowedMethods())
                && existing.confirmationMode() == command.confirmationMode()
                && existing.region().equalsIgnoreCase(command.region())
                && existing.expiresAt().equals(existing.createdAt().plus(command.timeToLive()))
                && existing.createIdempotencyKey().equals(command.idempotencyKey());
        if (!same) {
            throw new PaymentCoreException("IDEMPOTENCY_KEY_REUSE",
                    "idempotency key or order reference was reused with a different request");
        }
    }

    private static String eventType(AttemptOperation operation) {
        return switch (operation) {
            case PAYMENT -> "payment.attempt.resolved.v1";
            case CAPTURE -> "payment.capture.resolved.v1";
            case CANCEL -> "payment.void.resolved.v1";
            case CLOSE -> "payment.authorization.closed.v1";
            case QUERY -> "payment.query.resolved.v1";
        };
    }

    private static String value(String nullable) {
        return nullable == null ? "" : nullable;
    }

    private PaymentAttempt beginAttempt(AttemptDraft draft) {
        return repository.beginAttempt(draft);
    }

    private java.time.Instant attemptStartedAt() {
        return clock.instant();
    }

    private java.time.Instant attemptLeaseExpiresAt() {
        return clock.instant().plus(attemptLease);
    }

    private String newLeaseOwner(String purpose) {
        return purpose + ":" + UUID.randomUUID();
    }

    private InstantLease newLease(String purpose) {
        java.time.Instant startedAt = clock.instant();
        return new InstantLease(startedAt, startedAt.plus(attemptLease), newLeaseOwner(purpose));
    }

    private record InstantLease(java.time.Instant startedAt, java.time.Instant expiresAt,
            String owner) {
    }
}
