package com.elmpay.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Flow;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class BoundedHttpTransportTest {
    @TempDir Path temporary;

    @Test
    void responseIsDefensiveCloseableAndRejectsUseAfterClose() {
        byte[] supplied = {1, 2, 3};
        var response = new BoundedHttpTransport.Response(200, headers(Map.of()), supplied);
        supplied[0] = 9;
        byte[] first = response.body();
        assertArrayEquals(new byte[] {1, 2, 3}, first);
        first[1] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, response.body());

        response.close();
        response.close();

        assertThrows(IllegalStateException.class, response::body);
        assertThrows(IllegalStateException.class, response::bodyLength);
    }

    @Test
    void clientPolicyPinsTls13HttpsIdentityAndRejectsRedirects() {
        SSLParameters exact = new SSLParameters();
        exact.setProtocols(new String[] {"TLSv1.3"});
        exact.setEndpointIdentificationAlgorithm("HTTPS");
        HttpClient client = HttpClient.newBuilder().sslParameters(exact)
                .followRedirects(HttpClient.Redirect.NEVER).build();
        assertDoesNotThrow(() -> BoundedHttpTransport.requireHttpsClient(client));

        assertThrows(SecurityException.class, () -> BoundedHttpTransport.requireHttpsClient(
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build()));
    }

    @Test
    void subscriberCompletesWithinBoundAndCancelsOnClose() {
        var subscription = new TrackingSubscription();
        var subscriber = new BoundedHttpTransport.BoundedBodySubscriber(4);
        subscriber.onSubscribe(subscription);
        subscriber.onNext(List.of(ByteBuffer.wrap(new byte[] {1, 2, 3, 4})));
        subscriber.onComplete();

        byte[] result = subscriber.getBody().toCompletableFuture().join();
        assertArrayEquals(new byte[] {1, 2, 3, 4}, result);
        assertEquals(Long.MAX_VALUE, subscription.requested);
        subscriber.close();
        assertArrayEquals(new byte[] {0, 0, 0, 0}, result);
    }

    @Test
    void oversizeDuplicateSubscriptionAndLateCallbacksFailClosed() {
        var first = new TrackingSubscription();
        var duplicate = new TrackingSubscription();
        var duplicateSubscriber = new BoundedHttpTransport.BoundedBodySubscriber(4);
        duplicateSubscriber.onSubscribe(first);
        duplicateSubscriber.onSubscribe(duplicate);
        assertTrue(first.cancelled);
        assertTrue(duplicate.cancelled);
        assertThrows(CompletionException.class,
                () -> duplicateSubscriber.getBody().toCompletableFuture().join());

        var overflowSubscription = new TrackingSubscription();
        var overflow = new BoundedHttpTransport.BoundedBodySubscriber(3);
        overflow.onSubscribe(overflowSubscription);
        overflow.onNext(List.of(ByteBuffer.wrap(new byte[] {1, 2}),
                ByteBuffer.wrap(new byte[] {3, 4})));
        assertTrue(overflowSubscription.cancelled);
        assertThrows(CompletionException.class,
                () -> overflow.getBody().toCompletableFuture().join());

        var lateSubscription = new TrackingSubscription();
        var late = new BoundedHttpTransport.BoundedBodySubscriber(4);
        late.onSubscribe(lateSubscription);
        late.onNext(List.of(ByteBuffer.wrap(new byte[] {9, 9})));
        late.close();
        late.onNext(List.of(ByteBuffer.wrap(new byte[] {7, 7})));
        late.onComplete();
        assertTrue(lateSubscription.cancelled);
        assertThrows(CompletionException.class,
                () -> late.getBody().toCompletableFuture().join());

        var broken = new BoundedHttpTransport.BoundedBodySubscriber(4);
        broken.onSubscribe(new Flow.Subscription() {
            @Override public void request(long count) { }
            @Override public void cancel() { throw new AssertionError("broken cancel"); }
        });
        broken.onNext(List.of(ByteBuffer.wrap(new byte[] {5, 6})));
        IllegalStateException upstream = new IllegalStateException("upstream failure");
        broken.onError(upstream);
        assertEquals(1, upstream.getSuppressed().length);
        assertThrows(CompletionException.class,
                () -> broken.getBody().toCompletableFuture().join());
    }

    @Test
    void contentLengthIsRejectedBeforeSubscriptionWhenMissingBound() {
        var oversized = new BoundedHttpTransport.BoundedBodyHandler(4);
        assertThrows(SecurityException.class, () -> oversized.apply(
                responseInfo(headers(Map.of("Content-Length", List.of("5"))))));

        var ambiguous = new BoundedHttpTransport.BoundedBodyHandler(4);
        assertThrows(SecurityException.class, () -> ambiguous.apply(
                responseInfo(headers(Map.of("Content-Length", List.of("2", "2"))))));

        var oversizedHeader = new BoundedHttpTransport.BoundedBodyHandler(4);
        assertThrows(SecurityException.class, () -> oversizedHeader.apply(
                responseInfo(headers(Map.of("X-Oversized", List.of("x".repeat(8_193)))))));

        var exact = new BoundedHttpTransport.BoundedBodyHandler(4);
        HttpResponse.BodySubscriber<byte[]> subscriber = exact.apply(
                responseInfo(headers(Map.of("Content-Length", List.of("4")))));
        assertThrows(SecurityException.class, () -> exact.apply(responseInfo(headers(Map.of()))));
        exact.close();
        assertThrows(CompletionException.class,
                () -> subscriber.getBody().toCompletableFuture().join());
    }

    @Test
    void wipeableJsonRejectsInvalidUtf8AndNeverExposesSecretAsString() {
        byte[] document = "{\"id\":\"expected\",\"secret\":\"c2VjcmV0\"}"
                .getBytes(StandardCharsets.UTF_8);
        WipeableFlatJson parsed = WipeableFlatJson.parse(document);
        parsed.requireBound("id", "expected");
        byte[] decoded = parsed.requireBase64Url("secret", 6, 6);
        assertArrayEquals("secret".getBytes(StandardCharsets.US_ASCII), decoded);
        parsed.close();
        Arrays.fill(decoded, (byte) 0);
        assertThrows(IllegalStateException.class, parsed::keys);

        assertThrows(SecurityException.class,
                () -> WipeableFlatJson.parse(new byte[] {'{', '"', 'x', '"', ':', '"',
                        (byte) 0xc3, (byte) 0x28, '"', '}'}));
        try (WipeableFlatJson padded = WipeableFlatJson.parse(
                "{\"x\":\"YQ==\"}".getBytes(StandardCharsets.UTF_8))) {
            assertThrows(SecurityException.class,
                    () -> padded.requireBase64Url("x", 1, 1));
        }
        assertThrows(SecurityException.class, () -> WipeableFlatJson.parse(
                "{\"x\":\"a\",\"x\":\"b\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void mountedAccessTokenIsBoundedStrictAndExactPathConfigurationFailsClosed()
            throws Exception {
        Path token = temporary.resolve("token");
        Files.writeString(token, "abcdefghijklmnopqrstuvwxyzABCDEF\n",
                StandardCharsets.US_ASCII);
        Files.setPosixFilePermissions(token, java.util.Set.of(PosixFilePermission.OWNER_READ));
        assertEquals("abcdefghijklmnopqrstuvwxyzABCDEF",
                MountedHttpsClient.readTokenForTest(token));

        Files.setPosixFilePermissions(token, java.util.Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
        Files.writeString(token, "abcdefghijklmnop\npoison", StandardCharsets.US_ASCII);
        Files.setPosixFilePermissions(token, java.util.Set.of(PosixFilePermission.OWNER_READ));
        assertThrows(SecurityException.class,
                () -> MountedHttpsClient.readTokenForTest(token));

        assertThrows(IllegalStateException.class, () -> MountedHttpsClient.fromEnvironment(
                Map.of("ELMPAY_TEST_MTLS_CLIENT_CERT_FILE",
                        temporary.resolve("tls.crt").toString()),
                "ELMPAY_TEST", "test-client", Clock.systemUTC(), Duration.ofSeconds(1)));
        assertThrows(IllegalStateException.class, () -> MountedHttpsClient.fromEnvironment(
                Map.of("ELMPAY_TEST_MTLS", "true"), "ELMPAY_TEST", "test-client",
                Clock.systemUTC(), Duration.ofSeconds(1)));
    }

    private static HttpHeaders headers(Map<String, List<String>> values) {
        return HttpHeaders.of(values, (name, value) -> true);
    }

    private static HttpResponse.ResponseInfo responseInfo(HttpHeaders headers) {
        return new HttpResponse.ResponseInfo() {
            @Override
            public int statusCode() {
                return 200;
            }

            @Override
            public HttpHeaders headers() {
                return headers;
            }

            @Override
            public HttpClient.Version version() {
                return HttpClient.Version.HTTP_2;
            }
        };
    }

    private static final class TrackingSubscription implements Flow.Subscription {
        private long requested;
        private boolean cancelled;

        @Override
        public void request(long count) {
            requested = count;
        }

        @Override
        public void cancel() {
            cancelled = true;
        }
    }
}
