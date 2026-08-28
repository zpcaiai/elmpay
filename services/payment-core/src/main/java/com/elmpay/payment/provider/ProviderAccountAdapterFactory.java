package com.elmpay.payment.provider;

import com.elmpay.merchant.ProviderAccount;
/** Builds one short-lived, account-bound adapter from an opaque credential lease. */
public interface ProviderAccountAdapterFactory {
    String provider();

    ProviderRuntimeAdapter create(ProviderAccount account, ProviderCredential credential);
}
