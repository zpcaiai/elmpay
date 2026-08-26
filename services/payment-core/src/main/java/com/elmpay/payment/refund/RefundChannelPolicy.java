package com.elmpay.payment.refund;

import com.elmpay.merchant.ProviderAccount;
import com.elmpay.payment.PaymentIntent;

/** Provider capability snapshot check. Implementations must fail closed on missing config. */
@FunctionalInterface
public interface RefundChannelPolicy {
    void validate(ProviderAccount account, PaymentIntent intent, long amountMinor,
            RefundReason reason);
}
