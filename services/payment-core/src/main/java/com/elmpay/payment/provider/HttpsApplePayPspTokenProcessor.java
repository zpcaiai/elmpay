package com.elmpay.payment.provider;

import com.elmpay.connectors.applepay.ApplePayAdapter;
import com.elmpay.security.BoundedHttpTransport;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/** mTLS boundary that forwards an opaque Apple Pay envelope to an approved PSP broker. */
public final class HttpsApplePayPspTokenProcessor implements ApplePayAdapter.PspTokenProcessor {
    public interface Transport {
        Response post(URI endpoint, Map<String, String> headers, byte[] body, Duration timeout);
    }

    private static final int MAX_RESPONSE_BYTES = 65_536;

    public static final class Response implements AutoCloseable {
        private final int statusCode;
        private final HttpHeaders headers;
        private byte[] body;
        private boolean closed;

        public Response(int statusCode, HttpHeaders headers, byte[] body) {
            this.statusCode = statusCode;
            this.headers = Objects.requireNonNull(headers, "headers");
            this.body = Objects.requireNonNull(body, "body").clone();
        }

        public int statusCode() {
            return statusCode;
        }

        public HttpHeaders headers() {
            return headers;
        }

        public synchronized int bodyLength() {
            ensureOpen();
            return body.length;
        }

        public synchronized byte[] body() {
            ensureOpen();
            return body.clone();
        }

        @Override
        public synchronized void close() {
            if (closed) {
                return;
            }
            closed = true;
            Arrays.fill(body, (byte) 0);
            body = new byte[0];
        }

        private void ensureOpen() {
            if (closed) {
                throw new IllegalStateException("Apple Pay PSP response is closed");
            }
        }
    }

    private static final class JdkTransport implements Transport {
        private final HttpClient client;

        private JdkTransport(SSLContext mutualTlsContext, Duration connectTimeout) {
            SSLParameters tls = new SSLParameters();
            tls.setProtocols(new String[] {"TLSv1.3"});
            tls.setEndpointIdentificationAlgorithm("HTTPS");
            client = HttpClient.newBuilder().sslContext(Objects.requireNonNull(
                    mutualTlsContext, "mutualTlsContext")).sslParameters(tls)
                    .connectTimeout(connectTimeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }

        @Override
        public Response post(URI endpoint, Map<String, String> headers, byte[] body,
                Duration timeout) {
            HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint).timeout(timeout)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            headers.forEach(builder::header);
            try (BoundedHttpTransport.Response response = BoundedHttpTransport.send(
                    client, builder.build(), MAX_RESPONSE_BYTES)) {
                byte[] received = response.body();
                try {
                    return new Response(response.statusCode(), response.headers(), received);
                } finally {
                    Arrays.fill(received, (byte) 0);
                }
            } catch (IOException exception) {
                throw new IllegalStateException("Apple Pay PSP broker is unavailable", exception);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Apple Pay PSP forwarding was interrupted", exception);
            }
        }
    }

    private final URI endpoint;
    private final SecretMaterialProviderCredential credential;
    private final ApplePayAdapter.Psp delegatedPsp;
    private final Transport transport;
    private final Duration timeout;

    public HttpsApplePayPspTokenProcessor(URI endpoint,
            SecretMaterialProviderCredential credential, ApplePayAdapter.Psp delegatedPsp,
            SSLContext mutualTlsContext, Duration timeout) {
        this(endpoint, credential, delegatedPsp,
                new JdkTransport(mutualTlsContext, timeout), timeout);
    }

    HttpsApplePayPspTokenProcessor(URI endpoint, SecretMaterialProviderCredential credential,
            ApplePayAdapter.Psp delegatedPsp, Transport transport, Duration timeout) {
        this.endpoint = requireHttpsBase(endpoint).resolve("v1/apple-pay/tokens");
        this.credential = Objects.requireNonNull(credential, "credential");
        this.delegatedPsp = Objects.requireNonNull(delegatedPsp, "delegatedPsp");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative()
                || timeout.compareTo(Duration.ofSeconds(10)) > 0) {
            throw new IllegalArgumentException("Apple Pay PSP timeout must be 1ms..10s");
        }
    }

    @Override
    public ApplePayAdapter.Result process(ApplePayAdapter.Psp psp,
            ApplePayAdapter.PspRequest request) {
        Objects.requireNonNull(psp, "psp");
        Objects.requireNonNull(request, "request");
        if (psp != delegatedPsp) {
            throw new SecurityException("Apple Pay PSP selection is outside the account policy");
        }
        byte[] opaqueToken = request.opaquePaymentToken();
        byte[] body = null;
        try {
            validateRequest(request, opaqueToken);
            ProviderCredentialMaterial.require(credential);
            if (!credential.expiresAt().isAfter(java.time.Instant.now().plus(timeout))) {
                throw new SecurityException(
                        "Apple Pay PSP credential expires before the request deadline");
            }
            body = requestBody(psp, request, opaqueToken);
            String accessToken = ProviderCredentialMaterial.text(credential,
                    "psp_broker_access_token", 8_192);
            if (!accessToken.matches("[A-Za-z0-9\\-._~+/]+=*")) {
                throw new SecurityException("Apple Pay PSP access token is malformed");
            }
            try (Response response = transport.post(endpoint, Map.of(
                        "Accept", "application/json",
                        "Authorization", "Bearer " + accessToken,
                        "Content-Type", "application/json",
                        "Idempotency-Key", request.idempotencyKey()), body, timeout)) {
                if (response.statusCode() != 200 || response.bodyLength() == 0
                        || response.bodyLength() > MAX_RESPONSE_BYTES) {
                    throw new IllegalStateException(
                            "Apple Pay PSP broker returned an unsafe response");
                }
                requireJsonContentType(response.headers());
                byte[] received = response.body();
                try {
                    return parse(received);
                } finally {
                    Arrays.fill(received, (byte) 0);
                }
            }
        } finally {
            Arrays.fill(opaqueToken, (byte) 0);
            if (body != null) {
                Arrays.fill(body, (byte) 0);
            }
        }
    }

    private static byte[] requestBody(ApplePayAdapter.Psp psp,
            ApplePayAdapter.PspRequest request, byte[] opaqueToken) {
        byte[] encodedToken = null;
        byte[] prefix = null;
        byte[] suffix = null;
        byte[] result = null;
        try {
            encodedToken = Base64.getEncoder().encode(opaqueToken);
            prefix = ("{\"amount_minor\":" + request.amountMinor()
                    + ",\"currency\":\"" + request.currency()
                    + "\",\"merchant_account_id\":\"" + request.merchantAccountId()
                    + "\",\"opaque_token_b64\":\"").getBytes(StandardCharsets.US_ASCII);
            suffix = ("\",\"psp\":\""
                    + psp.name().toLowerCase(java.util.Locale.ROOT)
                    + "\",\"tenant_id\":\"" + request.tenantId() + "\"}")
                    .getBytes(StandardCharsets.US_ASCII);
            result = new byte[Math.addExact(Math.addExact(prefix.length,
                    encodedToken.length), suffix.length)];
            System.arraycopy(prefix, 0, result, 0, prefix.length);
            System.arraycopy(encodedToken, 0, result, prefix.length, encodedToken.length);
            System.arraycopy(suffix, 0, result, prefix.length + encodedToken.length,
                    suffix.length);
            byte[] owned = result;
            result = null;
            return owned;
        } finally {
            wipe(encodedToken);
            wipe(prefix);
            wipe(suffix);
            wipe(result);
        }
    }

    private static ApplePayAdapter.Result parse(byte[] raw) {
        byte[] first = "{\"provider_payment_id\":\"".getBytes(StandardCharsets.US_ASCII);
        byte[] second = "\",\"state\":\"".getBytes(StandardCharsets.US_ASCII);
        byte[] third = "\",\"final\":".getBytes(StandardCharsets.US_ASCII);
        int providerStart = match(raw, 0, first);
        int providerEnd = find(raw, providerStart, (byte) '"');
        int stateStart = match(raw, providerEnd, second);
        int stateEnd = find(raw, stateStart, (byte) '"');
        int finalStart = match(raw, stateEnd, third);
        boolean finalState;
        if (matches(raw, finalStart, "true}")) {
            finalState = true;
        } else if (matches(raw, finalStart, "false}")) {
            finalState = false;
        } else {
            throw new SecurityException("Apple Pay PSP broker response is malformed");
        }
        if (providerEnd - providerStart < 6 || providerEnd - providerStart > 128
                || stateEnd - stateStart < 3 || stateEnd - stateStart > 32
                || !asciiMatches(raw, providerStart, providerEnd, false)
                || !asciiMatches(raw, stateStart, stateEnd, true)) {
            throw new SecurityException("Apple Pay PSP broker response is malformed");
        }
        return new ApplePayAdapter.Result(
                new String(raw, providerStart, providerEnd - providerStart,
                        StandardCharsets.US_ASCII),
                new String(raw, stateStart, stateEnd - stateStart,
                        StandardCharsets.US_ASCII), finalState);
    }

    private static int match(byte[] source, int at, byte[] expected) {
        if (at < 0 || at + expected.length > source.length) {
            throw new SecurityException("Apple Pay PSP broker response is malformed");
        }
        for (byte value : expected) {
            if (source[at++] != value) {
                throw new SecurityException("Apple Pay PSP broker response is malformed");
            }
        }
        return at;
    }

    private static int find(byte[] source, int at, byte expected) {
        for (int index = at; index < source.length; index++) {
            if (source[index] == expected) {
                return index;
            }
        }
        throw new SecurityException("Apple Pay PSP broker response is malformed");
    }

    private static boolean matches(byte[] source, int at, String expected) {
        byte[] ascii = expected.getBytes(StandardCharsets.US_ASCII);
        if (source.length - at != ascii.length) {
            return false;
        }
        for (byte value : ascii) {
            if (source[at++] != value) {
                return false;
            }
        }
        return true;
    }

    private static boolean asciiMatches(byte[] source, int start, int end, boolean state) {
        for (int index = start; index < end; index++) {
            int value = Byte.toUnsignedInt(source[index]);
            boolean valid = value >= 'A' && value <= 'Z';
            if (!state) {
                valid = valid || value >= 'a' && value <= 'z'
                        || value >= '0' && value <= '9' || value == '_' || value == '-';
            } else {
                valid = valid || value == '_';
            }
            if (!valid) {
                return false;
            }
        }
        return true;
    }

    private static void validateRequest(ApplePayAdapter.PspRequest request, byte[] opaqueToken) {
        if (request.tenantId() == null
                || !request.tenantId().matches("[A-Za-z0-9_-]{3,64}")
                || request.merchantAccountId() == null
                || !request.merchantAccountId().matches("[A-Za-z0-9_-]{3,64}")
                || request.amountMinor() <= 0
                || request.currency() == null || !request.currency().matches("[A-Z]{3}")
                || opaqueToken.length < 16 || opaqueToken.length > 32_768
                || request.idempotencyKey() == null
                || !request.idempotencyKey().matches("[A-Za-z0-9._:-]{16,128}")) {
            throw new SecurityException("Apple Pay PSP request is malformed");
        }
    }

    private static void requireJsonContentType(HttpHeaders headers) {
        var values = headers.allValues("Content-Type");
        if (values.size() != 1 || !"application/json".equalsIgnoreCase(values.getFirst())) {
            throw new SecurityException("Apple Pay PSP response content type is unsafe");
        }
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static URI requireHttpsBase(URI value) {
        Objects.requireNonNull(value, "endpoint");
        if (!"https".equalsIgnoreCase(value.getScheme()) || value.getHost() == null
                || value.getUserInfo() != null || value.getQuery() != null
                || value.getFragment() != null) {
            throw new IllegalArgumentException("Apple Pay PSP endpoint must be HTTPS");
        }
        String text = value.toString();
        return text.endsWith("/") ? value : URI.create(text + "/");
    }
}
