package com.elmpay.gateway;

import com.elmpay.payment.checkout.DurablePaymentLinkService;
import com.elmpay.payment.checkout.HmacPaymentLinkSigner;
import com.elmpay.payment.checkout.InMemoryPaymentLinkRepository;
import com.elmpay.payment.checkout.JdbcPaymentLinkRepository;
import com.elmpay.payment.checkout.PaymentLinkSigner;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

/** B57 runtime factory; production has no embedded signing key or in-memory fallback. */
public final class PaymentLinkRuntimeFactory {
    private PaymentLinkRuntimeFactory() {}

    public static DurablePaymentLinkService create(Map<String, String> environment) {
        String mode = environment.get("ELMPAY_RUNTIME_MODE");
        if ("local".equals(mode)) {
            byte[] local = new byte[32];
            java.util.Arrays.fill(local, (byte) 0x57);
            return new DurablePaymentLinkService(new InMemoryPaymentLinkRepository(),
                    new HmacPaymentLinkSigner(Map.of("local-link-v1", local), "local-link-v1"),
                    Clock.systemUTC());
        }
        if (!"postgres".equals(mode)) {
            throw new IllegalStateException("payment-link runtime mode is unsupported");
        }
        List<PaymentLinkSigner> signers = new ArrayList<>();
        ServiceLoader.load(PaymentLinkSigner.class).forEach(signers::add);
        if (signers.size() != 1 || !signers.getFirst().ready()) {
            throw new IllegalStateException(
                    "production payment links require exactly one ready KMS/HSM MAC signer");
        }
        var dataSource = new DriverManagerDataSource(required(environment, "ELMPAY_DATABASE_URL"),
                required(environment, "ELMPAY_DATABASE_USER"),
                required(environment, "ELMPAY_DATABASE_PASSWORD"));
        return new DurablePaymentLinkService(new JdbcPaymentLinkRepository(dataSource),
                signers.getFirst(), Clock.systemUTC());
    }

    private static String required(Map<String, String> environment, String name) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required for payment links");
        }
        return value;
    }
}
