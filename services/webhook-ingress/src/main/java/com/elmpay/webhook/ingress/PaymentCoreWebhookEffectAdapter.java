package com.elmpay.webhook.ingress;

import com.elmpay.payment.ProviderWebhookEffectService;
import com.elmpay.payment.ProviderWebhookEffectService.EffectRejectedException;
import com.elmpay.payment.VerifiedProviderEffectCommand;
import com.elmpay.payment.VerifiedProviderEffectCommand.EffectKind;
import java.sql.Connection;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Production adapter from verified ingress facts to the payment-core transaction service. */
public final class PaymentCoreWebhookEffectAdapter implements WebhookEffectPort {
    private static final Map<EventKey, EffectKind> EVENT_MAP_V1 = Map.ofEntries(
            // Stripe PaymentIntent webhook types with unambiguous aggregate semantics.
            Map.entry(key("stripe", "payment_intent.processing"),
                    EffectKind.PAYMENT_PENDING),
            Map.entry(key("stripe", "payment_intent.amount_capturable_updated"),
                    EffectKind.PAYMENT_AUTHORIZED),
            Map.entry(key("stripe", "payment_intent.succeeded"),
                    EffectKind.PAYMENT_CAPTURED),
            Map.entry(key("stripe", "payment_intent.payment_failed"),
                    EffectKind.PAYMENT_FAILED),
            Map.entry(key("stripe", "payment_intent.canceled"),
                    EffectKind.PAYMENT_CANCELED),
            Map.entry(key("stripe", "refund.created"), EffectKind.REFUND_PENDING),
            Map.entry(key("stripe", "refund.failed"), EffectKind.REFUND_FAILED),

            // WeChat transaction callback verifier currently supports this transaction shape.
            Map.entry(key("wechat", "TRANSACTION.SUCCESS"),
                    EffectKind.PAYMENT_CAPTURED),

            // Alipay certificate-mode notification statuses emitted by AlipayProviderBridge.
            Map.entry(key("alipay", "alipay.wait_buyer_pay"),
                    EffectKind.PAYMENT_PENDING),
            Map.entry(key("alipay", "alipay.trade_success"),
                    EffectKind.PAYMENT_CAPTURED),
            Map.entry(key("alipay", "alipay.trade_finished"),
                    EffectKind.PAYMENT_CAPTURED),
            Map.entry(key("alipay", "alipay.trade_closed"),
                    EffectKind.PAYMENT_CANCELED),

            // PayPal Orders v2 authorization/capture/refund lifecycle event names.
            Map.entry(key("paypal", "PAYMENT.AUTHORIZATION.CREATED"),
                    EffectKind.PAYMENT_AUTHORIZED),
            Map.entry(key("paypal", "PAYMENT.AUTHORIZATION.VOIDED"),
                    EffectKind.PAYMENT_CANCELED),
            Map.entry(key("paypal", "PAYMENT.CAPTURE.PENDING"),
                    EffectKind.PAYMENT_PENDING),
            Map.entry(key("paypal", "PAYMENT.CAPTURE.COMPLETED"),
                    EffectKind.PAYMENT_CAPTURED),
            Map.entry(key("paypal", "PAYMENT.CAPTURE.DENIED"),
                    EffectKind.PAYMENT_FAILED),
            Map.entry(key("paypal", "PAYMENT.CAPTURE.DECLINED"),
                    EffectKind.PAYMENT_FAILED),
            Map.entry(key("paypal", "PAYMENT.CAPTURE.REVERSED"),
                    EffectKind.PAYMENT_CANCELED),
            Map.entry(key("paypal", "PAYMENT.REFUND.PENDING"),
                    EffectKind.REFUND_PENDING),
            Map.entry(key("paypal", "PAYMENT.REFUND.COMPLETED"),
                    EffectKind.REFUND_SUCCEEDED),
            Map.entry(key("paypal", "PAYMENT.REFUND.FAILED"),
                    EffectKind.REFUND_FAILED),
            Map.entry(key("paypal", "PAYMENT.REFUND.CANCELLED"),
                    EffectKind.REFUND_CANCELED));

    private final ProviderWebhookEffectService service;

    public PaymentCoreWebhookEffectAdapter(ProviderWebhookEffectService service) {
        this.service = Objects.requireNonNull(service, "service");
    }

    @Override
    public void apply(Connection transaction, Effect effect) throws EffectFailure {
        Objects.requireNonNull(transaction, "transaction");
        Objects.requireNonNull(effect, "effect");
        EffectKind kind = EVENT_MAP_V1.get(new EventKey(effect.provider(), effect.eventType()));
        if (kind == null) {
            throw new EffectFailure("PROVIDER_EVENT_TYPE_QUARANTINED", true,
                    new IllegalArgumentException("provider event type is not in mapping v1"));
        }
        try {
            service.apply(transaction, command(effect, kind));
        } catch (EffectRejectedException rejection) {
            throw new EffectFailure(rejection.failureCode(), rejection.permanent(), rejection);
        } catch (IllegalArgumentException | SecurityException rejection) {
            throw new EffectFailure("PROVIDER_EFFECT_COMMAND_REJECTED", true, rejection);
        } catch (RuntimeException failure) {
            throw new EffectFailure("PROVIDER_EFFECT_RUNTIME_FAILURE", false, failure);
        }
    }

    static EffectKind mappedEffect(String provider, String eventType) throws EffectFailure {
        EffectKind result = EVENT_MAP_V1.get(new EventKey(provider, eventType));
        if (result == null) {
            throw new EffectFailure("PROVIDER_EVENT_TYPE_QUARANTINED", true,
                    new IllegalArgumentException("provider event type is not in mapping v1"));
        }
        return result;
    }

    private static VerifiedProviderEffectCommand command(Effect effect, EffectKind kind) {
        return new VerifiedProviderEffectCommand(VerifiedProviderEffectCommand.SCHEMA_V1,
                VerifiedProviderEffectCommand.MAPPING_V1, uuid(effect.tenantId(), "tenantId"),
                uuid(effect.projectId(), "projectId"),
                uuid(effect.merchantAccountId(), "merchantAccountId"), effect.provider(),
                effect.providerEventId(), effect.eventType(), kind, effect.providerPaymentId(),
                effect.businessOrderNo(), effect.amountMinor(), effect.currency(),
                effect.occurredAt(), effect.receivedAt(), effect.verificationDigest(),
                effect.canonicalPayloadSha256(),
                "webhook-" + effect.verificationDigest().substring(0, 32));
    }

    private static UUID uuid(String value, String field) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException failure) {
            throw new SecurityException(field + " is not a UUID", failure);
        }
    }

    private static EventKey key(String provider, String eventType) {
        return new EventKey(provider, eventType);
    }

    private record EventKey(String provider, String eventType) {
        private EventKey {
            Objects.requireNonNull(provider, "provider");
            Objects.requireNonNull(eventType, "eventType");
        }
    }
}
