package com.elmpay.payment.provider;

import com.elmpay.connectors.applepay.ApplePayAdapter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.SSLContext;

/** mTLS boundary that forwards an opaque Apple Pay envelope to an approved PSP broker. */
public final class HttpsApplePayPspTokenProcessor implements ApplePayAdapter.PspTokenProcessor {
    public interface Transport {
        Response post(URI endpoint, Map<String, String> headers, byte[] body, Duration timeout);
    }

    public record Response(int statusCode, byte[] body) {
        public Response {
            body = Objects.requireNonNull(body, "body").clone();
        }

        @Override
        public byte[] body() {
            return body.clone();
        }
    }

    private static final class JdkTransport implements Transport {
        private final HttpClient client;

        private JdkTransport(SSLContext mutualTlsContext, Duration connectTimeout) {
            client = HttpClient.newBuilder().sslContext(Objects.requireNonNull(
                    mutualTlsContext, "mutualTlsContext")).connectTimeout(connectTimeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        }

        @Override
        public Response post(URI endpoint, Map<String, String> headers, byte[] body,
                Duration timeout) {
            HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint).timeout(timeout)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            headers.forEach(builder::header);
            try {
                HttpResponse<byte[]> response = client.send(builder.build(),
                        HttpResponse.BodyHandlers.ofByteArray());
                return new Response(response.statusCode(), response.body());
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
            String token = Base64.getEncoder().encodeToString(opaqueToken);
            String document = "{\"amount_minor\":" + request.amountMinor()
                    + ",\"currency\":\"" + request.currency()
                    + "\",\"merchant_account_id\":\"" + request.merchantAccountId()
                    + "\",\"opaque_token_b64\":\"" + token
                    + "\",\"psp\":\"" + psp.name().toLowerCase(java.util.Locale.ROOT)
                    + "\",\"tenant_id\":\"" + request.tenantId() + "\"}";
            body = document.getBytes(StandardCharsets.UTF_8);
            String accessToken = ProviderCredentialMaterial.text(credential,
                    "psp_broker_access_token", 8_192);
            Response response = transport.post(endpoint, Map.of(
                    "Accept", "application/json",
                    "Authorization", "Bearer " + accessToken,
                    "Content-Type", "application/json",
                    "Idempotency-Key", request.idempotencyKey()), body, timeout);
            if (response.statusCode() != 200 || response.body().length == 0
                    || response.body().length > 65_536) {
                throw new IllegalStateException("Apple Pay PSP broker returned an unsafe response");
            }
            return parse(response.body());
        } finally {
            Arrays.fill(opaqueToken, (byte) 0);
            if (body != null) {
                Arrays.fill(body, (byte) 0);
            }
        }
    }

    private static ApplePayAdapter.Result parse(byte[] raw) {
        String value = new String(raw, StandardCharsets.UTF_8);
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(
                "\\{\\\"provider_payment_id\\\":\\\"([A-Za-z0-9_-]{6,128})\\\","
                        + "\\\"state\\\":\\\"([A-Z_]{3,32})\\\","
                        + "\\\"final\\\":(true|false)\\}").matcher(value);
        if (!matcher.matches()) {
            throw new SecurityException("Apple Pay PSP broker response is malformed");
        }
        return new ApplePayAdapter.Result(matcher.group(1), matcher.group(2),
                Boolean.parseBoolean(matcher.group(3)));
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
