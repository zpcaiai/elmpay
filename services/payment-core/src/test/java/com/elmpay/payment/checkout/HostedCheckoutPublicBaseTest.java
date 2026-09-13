package com.elmpay.payment.checkout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import org.junit.jupiter.api.Test;

class HostedCheckoutPublicBaseTest {
    @Test
    void publicCheckoutBaseCannotCarryCredentialsQueryOrFragment() {
        assertEquals(URI.create("https://checkout.example/pay"),
                HostedCheckoutService.validatePublicBase(
                        URI.create("https://checkout.example/pay")));
        for (String unsafe : new String[]{
                "https://user:pass@checkout.example/pay",
                "https://checkout.example/pay?token=leaked",
                "https://checkout.example/pay#session=forged",
                "http://checkout.example/pay"
        }) {
            assertThrows(IllegalArgumentException.class,
                    () -> HostedCheckoutService.validatePublicBase(URI.create(unsafe)), unsafe);
        }
    }
}
