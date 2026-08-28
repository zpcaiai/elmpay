package com.elmpay.payment.provider;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;

/** Strict parsing helpers for account-bound secret leases. */
final class ProviderCredentialMaterial {
    private ProviderCredentialMaterial() {
    }

    static SecretMaterialProviderCredential require(ProviderCredential credential) {
        if (!(credential instanceof SecretMaterialProviderCredential material)) {
            throw new SecurityException("provider factory requires a secret-material lease");
        }
        if (!material.expiresAt().isAfter(Instant.now())) {
            throw new SecurityException("provider credential lease is expired");
        }
        return material;
    }

    static String text(SecretMaterialProviderCredential credential, String field,
            int maximumBytes) {
        return credential.use(field, value -> {
            if (value.length == 0 || value.length > maximumBytes) {
                throw new SecurityException("provider credential text field has an invalid size");
            }
            try {
                String result = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(value)).toString();
                if (result.isBlank() || result.chars().anyMatch(character -> character < 0x20)) {
                    throw new SecurityException("provider credential text field is malformed");
                }
                return result;
            } catch (CharacterCodingException exception) {
                throw new SecurityException("provider credential text field is not UTF-8", exception);
            }
        });
    }

    static byte[] bytes(SecretMaterialProviderCredential credential, String field,
            int minimumBytes, int maximumBytes) {
        byte[] value = credential.require(field);
        if (value.length < minimumBytes || value.length > maximumBytes) {
            Arrays.fill(value, (byte) 0);
            throw new SecurityException("provider credential binary field has an invalid size");
        }
        return value;
    }

    static PrivateKey rsaPrivateKey(SecretMaterialProviderCredential credential, String field) {
        byte[] encoded = bytes(credential, field, 512, 16_384);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (GeneralSecurityException exception) {
            throw new SecurityException("provider RSA private key is invalid", exception);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    static PublicKey rsaPublicKey(SecretMaterialProviderCredential credential, String field) {
        byte[] encoded = bytes(credential, field, 256, 16_384);
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException exception) {
            throw new SecurityException("provider RSA public key is invalid", exception);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    static void requireAccountBinding(SecretMaterialProviderCredential credential,
            String expectedProviderMerchantId) {
        String actual = text(credential, "provider_merchant_id", 256);
        if (!java.security.MessageDigest.isEqual(
                actual.getBytes(StandardCharsets.UTF_8),
                expectedProviderMerchantId.getBytes(StandardCharsets.UTF_8))) {
            throw new SecurityException("credential provider-account binding mismatch");
        }
    }
}
