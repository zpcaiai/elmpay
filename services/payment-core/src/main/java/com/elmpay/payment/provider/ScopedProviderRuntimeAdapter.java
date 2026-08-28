package com.elmpay.payment.provider;

import com.elmpay.money.Money;
import com.elmpay.provider.CreatePaymentCommand;
import com.elmpay.provider.ProviderAdapter;
import com.elmpay.provider.ProviderPayment;
import com.elmpay.provider.ProviderRefund;
import com.elmpay.provider.ProviderRequestContext;
import com.elmpay.provider.RefundCommand;
import com.elmpay.provider.VerifiedProviderEvent;
import com.elmpay.provider.WebhookRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/** Delegating provider runtime that deterministically destroys derived credential material. */
public final class ScopedProviderRuntimeAdapter implements ProviderRuntimeAdapter {
    private final ProviderAdapter delegate;
    private final List<Runnable> destroyers;
    private final AtomicBoolean closed = new AtomicBoolean();

    public ScopedProviderRuntimeAdapter(ProviderAdapter delegate, Runnable... destroyers) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        Objects.requireNonNull(destroyers, "destroyers");
        List<Runnable> copy = new ArrayList<>(destroyers.length);
        for (Runnable destroyer : destroyers) {
            copy.add(Objects.requireNonNull(destroyer, "destroyer"));
        }
        this.destroyers = List.copyOf(copy);
    }

    @Override
    public String provider() {
        return delegate.provider();
    }

    @Override
    public boolean configured() {
        return !closed.get() && delegate.configured();
    }

    @Override
    public ProviderPayment createPayment(CreatePaymentCommand command) {
        ensureOpen();
        return delegate.createPayment(command);
    }

    @Override
    public ProviderPayment queryPayment(ProviderRequestContext context, String providerPaymentId,
            String businessOrderNo) {
        ensureOpen();
        return delegate.queryPayment(context, providerPaymentId, businessOrderNo);
    }

    @Override
    public ProviderPayment capture(ProviderRequestContext context, String providerPaymentId,
            Money amount) {
        ensureOpen();
        return delegate.capture(context, providerPaymentId, amount);
    }

    @Override
    public ProviderPayment cancel(ProviderRequestContext context, String providerPaymentId,
            String reason) {
        ensureOpen();
        return delegate.cancel(context, providerPaymentId, reason);
    }

    @Override
    public ProviderRefund refund(RefundCommand command) {
        ensureOpen();
        return delegate.refund(command);
    }

    @Override
    public ProviderRefund queryRefund(ProviderRequestContext context, String providerRefundId,
            String refundReference) {
        ensureOpen();
        return delegate.queryRefund(context, providerRefundId, refundReference);
    }

    @Override
    public VerifiedProviderEvent verifyWebhook(WebhookRequest request) {
        ensureOpen();
        return delegate.verifyWebhook(request);
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        RuntimeException failure = null;
        for (int index = destroyers.size() - 1; index >= 0; index--) {
            try {
                destroyers.get(index).run();
            } catch (RuntimeException exception) {
                if (failure == null) {
                    failure = exception;
                } else {
                    failure.addSuppressed(exception);
                }
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    private void ensureOpen() {
        if (closed.get()) {
            throw new IllegalStateException("provider runtime adapter is closed");
        }
    }
}
