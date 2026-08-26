package com.elmpay.connectors.applepay;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Apple Pay's default path: validate eligibility, then forward the opaque token
 * directly to an approved PSP. This class never decrypts or retains the token.
 */
public final class ApplePayAdapter {
    private static final int MAX_TOKEN_BYTES = 32_768;
    private static final Pattern IDEMPOTENCY_KEY = Pattern.compile("[A-Za-z0-9._:-]{16,128}");

    public enum Psp { STRIPE, PAYPAL }

    public enum Capability { AVAILABLE, NO_WALLET, DOMAIN_NOT_VERIFIED, CERTIFICATE_UNAVAILABLE, TOKEN_REVOKED }

    public record Request(String tenantId, String merchantAccountId, String domain, long amountMinor,
            String currency, byte[] opaquePaymentToken, Psp psp, String merchantTokenReference,
            String idempotencyKey, Instant requestedAt) {
        public Request {
            requireId(tenantId, "tenantId");
            requireId(merchantAccountId, "merchantAccountId");
            requireText(domain, "domain");
            if (amountMinor <= 0) {
                throw new IllegalArgumentException("amount must be positive");
            }
            if (currency == null || !currency.matches("[A-Z]{3}")) {
                throw new IllegalArgumentException("currency must be three uppercase letters");
            }
            opaquePaymentToken = Objects.requireNonNull(opaquePaymentToken, "opaquePaymentToken").clone();
            Objects.requireNonNull(psp, "psp");
            if (idempotencyKey == null || !IDEMPOTENCY_KEY.matcher(idempotencyKey).matches()) {
                throw new IllegalArgumentException("invalid idempotency key");
            }
            Objects.requireNonNull(requestedAt, "requestedAt");
        }

        @Override
        public byte[] opaquePaymentToken() {
            return opaquePaymentToken.clone();
        }

        void clear() {
            Arrays.fill(opaquePaymentToken, (byte) 0);
        }
    }

    public record PspRequest(String tenantId, String merchantAccountId, long amountMinor,
            String currency, byte[] opaquePaymentToken, String idempotencyKey) {
        public PspRequest {
            opaquePaymentToken = opaquePaymentToken.clone();
        }

        @Override
        public byte[] opaquePaymentToken() {
            return opaquePaymentToken.clone();
        }

        void clear() {
            Arrays.fill(opaquePaymentToken, (byte) 0);
        }
    }

    public record Result(String providerPaymentId, String state, boolean finalState) {
        public Result {
            requireText(providerPaymentId, "providerPaymentId");
            requireText(state, "state");
        }
    }

    public record Authorization(Capability capability, String activeCertificateVersion) {
        public Authorization {
            Objects.requireNonNull(capability, "capability");
            activeCertificateVersion = activeCertificateVersion == null ? "" : activeCertificateVersion;
        }
    }

    @FunctionalInterface
    public interface LifecyclePolicy {
        Authorization authorize(String tenantId, String merchantAccountId, String domain,
                String merchantTokenReference, Instant at);
    }

    @FunctionalInterface
    public interface PspTokenProcessor {
        Result process(Psp psp, PspRequest request);
    }

    private final LifecyclePolicy lifecyclePolicy;
    private final PspTokenProcessor tokenProcessor;

    public ApplePayAdapter(LifecyclePolicy lifecyclePolicy, PspTokenProcessor tokenProcessor) {
        this.lifecyclePolicy = Objects.requireNonNull(lifecyclePolicy, "lifecyclePolicy");
        this.tokenProcessor = Objects.requireNonNull(tokenProcessor, "tokenProcessor");
    }

    public Capability capability(String tenantId, String merchantAccountId, String domain,
            boolean deviceHasWallet, String merchantTokenReference, Instant at) {
        if (!deviceHasWallet) {
            return Capability.NO_WALLET;
        }
        return lifecyclePolicy.authorize(tenantId, merchantAccountId, domain,
                merchantTokenReference, at).capability();
    }

    public Result forward(Request request) {
        Objects.requireNonNull(request, "request");
        byte[] token = request.opaquePaymentToken();
        PspRequest pspRequest = null;
        try {
            Authorization authorization = lifecyclePolicy.authorize(request.tenantId(),
                    request.merchantAccountId(), request.domain(), request.merchantTokenReference(),
                    request.requestedAt());
            if (authorization.capability() != Capability.AVAILABLE) {
                throw new IllegalStateException("Apple Pay is unavailable: " + authorization.capability());
            }
            validateOpaqueToken(token);
            pspRequest = new PspRequest(request.tenantId(), request.merchantAccountId(),
                    request.amountMinor(), request.currency(), token, request.idempotencyKey());
            return tokenProcessor.process(request.psp(), pspRequest);
        } finally {
            Arrays.fill(token, (byte) 0);
            if (pspRequest != null) {
                pspRequest.clear();
            }
            request.clear();
        }
    }

    private static void validateOpaqueToken(byte[] token) {
        if (token.length < 16 || token.length > MAX_TOKEN_BYTES) {
            throw new IllegalArgumentException("invalid Apple Pay token size");
        }
        String json;
        try {
            json = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(token)).toString().trim();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("Apple Pay token is not valid UTF-8", exception);
        }
        if (!json.startsWith("{") || !json.endsWith("}")) {
            throw new IllegalArgumentException("Apple Pay token must be a JSON object");
        }
        String lower = json.toLowerCase(Locale.ROOT);
        for (String forbidden : new String[] {"\"applicationprimaryaccountnumber\"", "\"cardnumber\"",
                "\"pan\"", "\"cvv\"", "\"cvc\"", "\"track1\"", "\"track2\""}) {
            if (lower.contains(forbidden)) {
                throw new IllegalArgumentException("raw card data is forbidden");
            }
        }
        if (!lower.contains("\"data\"") || !lower.contains("\"signature\"")
                || !lower.contains("\"header\"")) {
            throw new IllegalArgumentException("Apple Pay token envelope is incomplete");
        }
    }

    private static void requireId(String value, String name) {
        if (value == null || !value.matches("[A-Za-z0-9_-]{3,64}")) {
            throw new IllegalArgumentException(name + " has an invalid format");
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }
}
