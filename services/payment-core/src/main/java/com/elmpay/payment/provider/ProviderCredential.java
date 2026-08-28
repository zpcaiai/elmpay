package com.elmpay.payment.provider;

/**
 * Opaque, versioned secret-manager lease. Connector factories may define a richer subtype;
 * payment-core deliberately has no API that can log or stringify secret material.
 */
public interface ProviderCredential extends AutoCloseable {
    String version();

    @Override
    void close();
}
