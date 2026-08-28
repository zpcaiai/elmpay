package com.elmpay.payment.provider;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.elmpay.provider.ProviderException;
import com.elmpay.provider.ProviderOutcome;
import com.elmpay.provider.ProviderPayment;
import com.elmpay.provider.ProviderRefund;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class JdbcProviderCallCircuitBreakerTest {
    @Test
    void derivesHealthOnlyFromCapturedReturnValues() {
        JdbcProviderCallCircuitBreaker.Observation succeeded =
                JdbcProviderCallCircuitBreaker.resultObservation(new ProviderPayment(
                        "request-healthy", "payment-healthy", ProviderOutcome.SUCCEEDED,
                        null, null, true, Map.of()));
        JdbcProviderCallCircuitBreaker.Observation declined =
                JdbcProviderCallCircuitBreaker.resultObservation(new ProviderPayment(
                        "request-declined", "payment-declined", ProviderOutcome.DECLINED,
                        null, null, true, Map.of()));
        JdbcProviderCallCircuitBreaker.Observation unknown =
                JdbcProviderCallCircuitBreaker.resultObservation(new ProviderRefund(
                        "refund-unknown", ProviderOutcome.UNKNOWN, null, false));

        assertTrue(succeeded.succeeded());
        assertNull(succeeded.errorClass());
        assertTrue(declined.succeeded(), "business decline is not provider unavailability");
        assertFalse(unknown.succeeded());
    }

    @Test
    void derivesFailureClassFromCapturedExceptionAndNotCallerInput() {
        JdbcProviderCallCircuitBreaker.Observation retryable =
                JdbcProviderCallCircuitBreaker.exceptionObservation(new ProviderException(
                        "PROVIDER_TIMEOUT", "provider timed out", true, false));
        JdbcProviderCallCircuitBreaker.Observation unknown =
                JdbcProviderCallCircuitBreaker.exceptionObservation(new ProviderException(
                        "PROVIDER_UNKNOWN", "provider outcome is unknown", false, true));
        JdbcProviderCallCircuitBreaker.Observation rejected =
                JdbcProviderCallCircuitBreaker.exceptionObservation(new SecurityException(
                        "invalid webhook signature"));

        assertFalse(retryable.succeeded());
        assertFalse(unknown.succeeded());
        assertTrue(rejected.succeeded(), "invalid caller data must not poison provider health");
    }

    @Test
    void unknownAndConcurrentHalfOpenStatesFailClosed() {
        Instant now = Instant.parse("2026-08-28T00:00:00Z");
        assertEquals(JdbcProviderCallCircuitBreaker.Admission.DENY,
                JdbcProviderCallCircuitBreaker.admission("UNKNOWN", null, 0, false, now, 3));
        assertEquals(JdbcProviderCallCircuitBreaker.Admission.DENY,
                JdbcProviderCallCircuitBreaker.admission("HALF_OPEN", null, 0, true, now, 3));
        assertEquals(JdbcProviderCallCircuitBreaker.Admission.DENY,
                JdbcProviderCallCircuitBreaker.admission("HALF_OPEN", null, 3, false, now, 3));
        assertEquals(JdbcProviderCallCircuitBreaker.Admission.DENY,
                JdbcProviderCallCircuitBreaker.admission(
                        "OPEN", now.plusSeconds(1), 0, false, now, 3));
        assertEquals(JdbcProviderCallCircuitBreaker.Admission.BEGIN_HALF_OPEN,
                JdbcProviderCallCircuitBreaker.admission(
                        "OPEN", now.minusSeconds(1), 0, false, now, 3));
        assertEquals(JdbcProviderCallCircuitBreaker.Admission.BEGIN_HALF_OPEN,
                JdbcProviderCallCircuitBreaker.admission(
                        "HALF_OPEN", null, 2, false, now, 3));
    }
}
