package com.elmpay.payment.checkout;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Explicit local/test signer; production uses a ServiceLoader KMS/HSM implementation. */
public final class HmacPaymentLinkSigner implements PaymentLinkSigner {
    private final Map<String, byte[]> keys;
    private final String activeVersion;

    public HmacPaymentLinkSigner(Map<String, byte[]> keys, String activeVersion) {
        if (keys == null || keys.isEmpty() || activeVersion == null
                || !keys.containsKey(activeVersion)) {
            throw new IllegalArgumentException("active payment-link signing key is required");
        }
        java.util.LinkedHashMap<String, byte[]> copy = new java.util.LinkedHashMap<>();
        keys.forEach((version, key) -> {
            if (version == null || version.isBlank() || key == null || key.length < 32) {
                throw new IllegalArgumentException("payment-link keys must be at least 256 bits");
            }
            copy.put(version, key.clone());
        });
        this.keys = Map.copyOf(copy);
        this.activeVersion = activeVersion;
    }

    @Override
    public Signature sign(byte[] canonicalPayload) {
        return new Signature(activeVersion, mac(keys.get(activeVersion), canonicalPayload));
    }

    @Override
    public String activeKeyVersion() {
        return activeVersion;
    }

    @Override
    public boolean verify(String keyVersion, byte[] canonicalPayload, String signature) {
        byte[] key = keys.get(keyVersion);
        if (key == null || signature == null) {
            return false;
        }
        return MessageDigest.isEqual(mac(key, canonicalPayload).getBytes(StandardCharsets.US_ASCII),
                signature.getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public boolean ready() {
        return true;
    }

    private static String mac(byte[] key, byte[] value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(value));
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("JDK HMAC-SHA256 is unavailable", unavailable);
        }
    }
}
