package com.elmpay.payment.checkout;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class CheckoutSessionServiceTest {
    private static CheckoutSessionService service() {
        return new CheckoutSessionService(Map.of("k1", new byte[32]), "k1",
                Set.of(URI.create("https://merchant.example/payment/return")),
                Clock.fixed(Instant.parse("2026-08-26T00:00:00Z"), ZoneOffset.UTC));
    }
    @Test void signatureBindsMoneyReturnAndDevice() {
        var service = service();
        var session = service.create(new CheckoutSessionService.CreateRequest("t1", "p1", "o1", 1234,
                "usd", URI.create("https://merchant.example/payment/return"), "device-digest", Duration.ofMinutes(5)));
        assertTrue(service.verify(session, session.signature()));
        var tampered = new CheckoutSessionService.Session(session.id(), session.tenantId(), session.projectId(),
                session.orderReference(), 1235, session.currency(), session.returnUri(), session.deviceContextDigest(),
                session.expiresAt(), session.keyId(), session.nonce(), session.signature(), session.status());
        assertFalse(service.verify(tampered, session.signature()));
        assertThrows(SecurityException.class, () -> service.create(new CheckoutSessionService.CreateRequest("t1", "p1", "o1", 1,
                "USD", URI.create("https://evil.example/return"), "d", Duration.ofMinutes(1))));
    }
    @Test void sessionCanBeConsumedExactlyOnceUnderConcurrency() throws Exception {
        var service = service();
        var session = service.create(new CheckoutSessionService.CreateRequest("t", "p", "o", 1, "USD",
                URI.create("https://merchant.example/payment/return"), "d", Duration.ofMinutes(1)));
        try (var executor = Executors.newFixedThreadPool(8)) {
            var tasks = java.util.stream.IntStream.range(0, 32).<Callable<Boolean>>mapToObj(i ->
                    () -> service.consume("t", session.id(), session.signature()).consumed()).toList();
            long winners = executor.invokeAll(tasks).stream().filter(future -> {
                try { return future.get(); } catch (Exception failure) { throw new AssertionError(failure); }
            }).count();
            assertEquals(1, winners);
        }
    }
    @Test void paymentLinkIsSignedShortLivedAndOneTime() {
        var links = new PaymentLinkService(new byte[32], Clock.fixed(Instant.parse("2026-08-26T00:00:00Z"), ZoneOffset.UTC));
        var link = links.create("tenant", "session", Duration.ofMinutes(1));
        assertTrue(links.qrPayload(link).startsWith("/checkout/link/"));
        assertEquals("session", links.redeem("tenant", link.token()));
        assertThrows(SecurityException.class, () -> links.redeem("tenant", link.token()));
        char replacement = link.token().charAt(link.token().length() - 1) == 'A' ? 'B' : 'A';
        String tampered = link.token().substring(0, link.token().length() - 1) + replacement;
        assertThrows(SecurityException.class, () -> links.redeem("tenant", tampered));
    }
}
