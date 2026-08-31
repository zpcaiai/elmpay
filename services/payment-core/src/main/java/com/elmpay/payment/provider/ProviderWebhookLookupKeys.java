package com.elmpay.payment.provider;

import com.elmpay.events.StrictJson;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Extracts lookup keys only; these untrusted values never become expected money facts. */
final class ProviderWebhookLookupKeys {
    private ProviderWebhookLookupKeys() {
    }

    static String alipayBusinessReference(byte[] rawBody) {
        String form = utf8(rawBody);
        String result = null;
        for (String field : form.split("&", -1)) {
            int separator = field.indexOf('=');
            if (separator <= 0
                    || !"out_trade_no".equals(decodeForm(field.substring(0, separator)))) {
                continue;
            }
            if (result != null) {
                throw new SecurityException(
                        "Alipay callback has an ambiguous business reference lookup key");
            }
            result = requireReference(decodeForm(field.substring(separator + 1)));
        }
        if (result == null) {
            throw new SecurityException("Alipay callback has no business reference lookup key");
        }
        return result;
    }

    static String stripeProviderObject(byte[] rawBody) {
        Map<String, Object> root = jsonObject(rawBody, "Stripe");
        Map<String, Object> data = requiredObject(root, "data", "Stripe");
        Map<String, Object> object = requiredObject(data, "object", "Stripe");
        String value = requiredString(object, "id", "Stripe");
        if (!value.matches("(?:pi|re)_[A-Za-z0-9_]{4,128}")) {
            throw new SecurityException(
                    "Stripe callback has no durable payment-object lookup key");
        }
        return requireReference(value);
    }

    static String payPalProviderObject(byte[] rawBody) {
        Map<String, Object> root = jsonObject(rawBody, "PayPal");
        Map<String, Object> resource = requiredObject(root, "resource", "PayPal");
        String value = requiredString(resource, "id", "PayPal");
        if (value.startsWith("WH-") || !value.matches("[A-Za-z0-9_-]{6,128}")) {
            throw new SecurityException(
                    "PayPal callback has no durable provider-object lookup key");
        }
        return requireReference(value);
    }

    private static Map<String, Object> jsonObject(byte[] rawBody, String provider) {
        try {
            return StrictJson.object(utf8(rawBody));
        } catch (IllegalArgumentException exception) {
            throw new SecurityException(provider + " callback JSON is invalid", exception);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> requiredObject(Map<String, Object> source, String name,
            String provider) {
        Object value = source.get(name);
        if (!(value instanceof Map<?, ?> map)) {
            throw new SecurityException(provider + " callback field " + name
                    + " must be an object");
        }
        return (Map<String, Object>) map;
    }

    private static String requiredString(Map<String, Object> source, String name,
            String provider) {
        Object value = source.get(name);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new SecurityException(provider + " callback field " + name
                    + " must be a non-empty string");
        }
        return text;
    }

    private static String utf8(byte[] value) {
        if (value == null || value.length == 0 || value.length > 1_048_576) {
            throw new SecurityException("provider callback body has an invalid size");
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException exception) {
            throw new SecurityException("provider callback body is not UTF-8", exception);
        }
    }

    private static String decodeForm(String value) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(value.length());
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current == '+') {
                bytes.write(' ');
            } else if (current == '%') {
                if (index + 2 >= value.length()) {
                    throw new SecurityException("provider callback has invalid percent encoding");
                }
                int high = Character.digit(value.charAt(++index), 16);
                int low = Character.digit(value.charAt(++index), 16);
                if (high < 0 || low < 0) {
                    throw new SecurityException("provider callback has invalid percent encoding");
                }
                bytes.write((high << 4) | low);
            } else if (current <= 0x7f) {
                bytes.write(current);
            } else {
                // Preserve supplementary Unicode code points as one scalar.  Encoding each
                // UTF-16 half separately would silently replace it with two '?' bytes and
                // could make an otherwise valid business reference fail to round-trip.
                int codePoint = value.codePointAt(index);
                bytes.writeBytes(new String(Character.toChars(codePoint))
                        .getBytes(StandardCharsets.UTF_8));
                if (Character.charCount(codePoint) == 2) {
                    index++;
                }
            }
        }
        return utf8(bytes.toByteArray());
    }

    private static String requireReference(String value) {
        if (value == null || value.isBlank() || value.length() > 256
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new SecurityException("provider callback lookup key is invalid");
        }
        return value;
    }
}
