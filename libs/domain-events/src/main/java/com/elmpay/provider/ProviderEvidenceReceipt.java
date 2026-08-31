package com.elmpay.provider;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/** Externally signed provider evidence; booleans and caller assertions are never accepted. */
public record ProviderEvidenceReceipt(String evidenceType, Map<String, String> fields,
        String keyId, Instant issuedAt, Instant expiresAt, String nonce, byte[] signature) {
    private static final Pattern NAME = Pattern.compile("[A-Z][A-Z0-9_]{2,79}");
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    private static final Pattern NONCE = Pattern.compile("[A-Za-z0-9._:-]{16,160}");
    private static final Pattern FIELD = Pattern.compile("[A-Za-z][A-Za-z0-9]{0,63}");

    public ProviderEvidenceReceipt {
        if (evidenceType == null || !NAME.matcher(evidenceType).matches()) {
            throw new IllegalArgumentException("provider evidence type is invalid");
        }
        fields = Map.copyOf(Objects.requireNonNull(fields, "fields"));
        if (fields.isEmpty() || fields.size() > 32) {
            throw new IllegalArgumentException("provider evidence fields are invalid");
        }
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            if (!FIELD.matcher(entry.getKey()).matches() || entry.getValue() == null
                    || entry.getValue().isEmpty() || entry.getValue().length() > 512
                    || entry.getValue().chars().anyMatch(character -> character < 0x20)) {
                throw new IllegalArgumentException("provider evidence field is invalid");
            }
        }
        if (keyId == null || !KEY_ID.matcher(keyId).matches()) {
            throw new IllegalArgumentException("provider evidence key id is invalid");
        }
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (nonce == null || !NONCE.matcher(nonce).matches()) {
            throw new IllegalArgumentException("provider evidence nonce is invalid");
        }
        signature = Objects.requireNonNull(signature, "signature").clone();
        if (signature.length != 64) {
            throw new IllegalArgumentException("provider evidence must use Ed25519");
        }
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }
}
