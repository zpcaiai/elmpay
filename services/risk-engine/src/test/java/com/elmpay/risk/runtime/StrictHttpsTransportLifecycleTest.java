package com.elmpay.risk.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class StrictHttpsTransportLifecycleTest {
    @Test
    void responseIsExplicitlyCloseableAndRejectsUseAfterClear() {
        byte[] source = "sensitive-risk-response".getBytes(StandardCharsets.UTF_8);
        StrictHttpsTransport.Response response = new StrictHttpsTransport.Response(
                200, "application/json", source);
        byte[] exposed = response.body();
        assertArrayEquals(source, exposed);

        response.close();
        response.close();
        assertThrows(IllegalStateException.class, response::body);
        assertArrayEquals("sensitive-risk-response".getBytes(StandardCharsets.UTF_8), source);
        java.util.Arrays.fill(exposed, (byte) 0);
    }
}
