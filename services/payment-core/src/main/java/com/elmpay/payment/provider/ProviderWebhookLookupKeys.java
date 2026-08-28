package com.elmpay.payment.provider;

import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Extracts lookup keys only; these untrusted values never become expected money facts. */
final class ProviderWebhookLookupKeys {
    private ProviderWebhookLookupKeys() {
    }

    static String alipayBusinessReference(byte[] rawBody) {
        String form = utf8(rawBody);
        for (String field : form.split("&", -1)) {
            int separator = field.indexOf('=');
            if (separator <= 0 || !"out_trade_no".equals(field.substring(0, separator))) {
                continue;
            }
            String decoded = URLDecoder.decode(field.substring(separator + 1), StandardCharsets.UTF_8);
            return requireReference(decoded);
        }
        throw new SecurityException("Alipay callback has no business reference lookup key");
    }

    static String stripeProviderObject(byte[] rawBody) {
        return jsonIds(rawBody).stream()
                .filter(value -> value.matches("(pi|re)_[A-Za-z0-9_]{4,128}"))
                .findFirst().map(ProviderWebhookLookupKeys::requireReference)
                .orElseThrow(() -> new SecurityException(
                        "Stripe callback has no durable payment-object lookup key"));
    }

    static String payPalProviderObject(byte[] rawBody) {
        return jsonIds(rawBody).stream()
                .filter(value -> !value.startsWith("WH-"))
                .filter(value -> value.matches("[A-Za-z0-9_-]{6,128}"))
                .findFirst().map(ProviderWebhookLookupKeys::requireReference)
                .orElseThrow(() -> new SecurityException(
                        "PayPal callback has no durable provider-object lookup key"));
    }

    private static List<String> jsonIds(byte[] rawBody) {
        String source = utf8(rawBody);
        List<String> result = new ArrayList<>();
        int cursor = 0;
        while ((cursor = source.indexOf("\"id\"", cursor)) >= 0) {
            int colon = skipWhitespace(source, cursor + 4);
            if (colon >= source.length() || source.charAt(colon) != ':') {
                cursor += 4;
                continue;
            }
            int start = skipWhitespace(source, colon + 1);
            if (start >= source.length() || source.charAt(start) != '\"') {
                cursor = start;
                continue;
            }
            StringBuilder value = new StringBuilder();
            boolean escaped = false;
            int index = start + 1;
            for (; index < source.length(); index++) {
                char character = source.charAt(index);
                if (escaped) {
                    if (character != '\"' && character != '\\' && character != '/') {
                        throw new SecurityException("provider callback id contains unsafe escaping");
                    }
                    value.append(character);
                    escaped = false;
                } else if (character == '\\') {
                    escaped = true;
                } else if (character == '\"') {
                    result.add(value.toString());
                    break;
                } else if (character < 0x20) {
                    throw new SecurityException("provider callback id contains control data");
                } else {
                    value.append(character);
                }
                if (value.length() > 256) {
                    throw new SecurityException("provider callback id is too long");
                }
            }
            if (index >= source.length()) {
                throw new SecurityException("provider callback JSON is truncated");
            }
            cursor = index + 1;
        }
        return List.copyOf(result);
    }

    private static int skipWhitespace(String value, int cursor) {
        while (cursor < value.length() && Character.isWhitespace(value.charAt(cursor))) {
            cursor++;
        }
        return cursor;
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

    private static String requireReference(String value) {
        if (value == null || value.isBlank() || value.length() > 256
                || value.chars().anyMatch(character -> character < 0x20)) {
            throw new SecurityException("provider callback lookup key is invalid");
        }
        return value;
    }
}
