package com.elmpay.payment.provider;

import com.elmpay.provider.ProviderAdapter;

/**
 * One-operation provider adapter built from a short-lived credential lease.
 *
 * <p>The account-aware dispatcher closes the adapter before it closes the credential lease. That
 * ordering lets implementations wipe derived key buffers while the lease is still available for
 * any provider-specific cleanup. Implementations must make {@link #close()} idempotent and must
 * never include credential material in close failures.
 */
public interface ProviderRuntimeAdapter extends ProviderAdapter, AutoCloseable {
    @Override
    void close();
}
