package com.elmpay.webhook.ingress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.payment.VerifiedProviderEffectCommand.EffectKind;
import org.junit.jupiter.api.Test;

final class PaymentCoreWebhookEffectAdapterTest {
    @Test
    void mapsOnlyVersionOneUnambiguousProviderLifecycleEvents() throws Exception {
        assertEquals(EffectKind.PAYMENT_CAPTURED,
                PaymentCoreWebhookEffectAdapter.mappedEffect("stripe",
                        "payment_intent.succeeded"));
        assertEquals(EffectKind.PAYMENT_CAPTURED,
                PaymentCoreWebhookEffectAdapter.mappedEffect("wechat",
                        "TRANSACTION.SUCCESS"));
        assertEquals(EffectKind.PAYMENT_CANCELED,
                PaymentCoreWebhookEffectAdapter.mappedEffect("alipay",
                        "alipay.trade_closed"));
        assertEquals(EffectKind.REFUND_SUCCEEDED,
                PaymentCoreWebhookEffectAdapter.mappedEffect("paypal",
                        "PAYMENT.REFUND.COMPLETED"));
    }

    @Test
    void ambiguousOrUnknownEventIsPermanentlyQuarantined() {
        WebhookEffectPort.EffectFailure stripeAmbiguous = assertThrows(
                WebhookEffectPort.EffectFailure.class,
                () -> PaymentCoreWebhookEffectAdapter.mappedEffect("stripe",
                        "refund.updated"));
        assertEquals("PROVIDER_EVENT_TYPE_QUARANTINED", stripeAmbiguous.failureCode());
        assertTrue(stripeAmbiguous.permanent());

        WebhookEffectPort.EffectFailure unknown = assertThrows(
                WebhookEffectPort.EffectFailure.class,
                () -> PaymentCoreWebhookEffectAdapter.mappedEffect("paypal",
                        "MERCHANT.UNKNOWN.EVENT"));
        assertTrue(unknown.permanent());
    }
}
