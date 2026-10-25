package com.elmpay.security;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.AbstractMap;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Deterministic JSON encoding used for request digests and signed sessions. */
public final class CanonicalPayload {
    private CanonicalPayload() {
    }

    public static byte[] encode(Object value) {
        StringBuilder builder = new StringBuilder();
        append(builder, value);
        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static String sha256Hex(Object value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(encode(value)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("JDK is missing SHA-256", exception);
        }
    }

    private static void append(StringBuilder builder, Object value) {
        if (value == null) {
            builder.append("null");
        } else if (value instanceof String text) {
            appendString(builder, text);
        } else if (value instanceof Boolean bool) {
            builder.append(bool.booleanValue());
        } else if (value instanceof Byte || value instanceof Short || value instanceof Integer
                || value instanceof Long || value instanceof BigInteger) {
            builder.append(value);
        } else if (value instanceof Float || value instanceof Double) {
            throw new IllegalArgumentException("binary floating point is forbidden in canonical payloads");
        } else if (value instanceof Enum<?> enumeration) {
            appendString(builder, enumeration.name());
        } else if (value instanceof UUID || value instanceof Instant) {
            appendString(builder, value.toString());
        } else if (value instanceof Map<?, ?> map) {
            appendMap(builder, map);
        } else if (value instanceof Iterable<?> iterable) {
            appendIterable(builder, iterable);
        } else {
            throw new IllegalArgumentException("unsupported canonical payload type: "
                    + value.getClass().getName());
        }
    }

    private static void appendMap(StringBuilder builder, Map<?, ?> map) {
        List<Map.Entry<String, Object>> entries = new ArrayList<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("canonical map keys must be strings");
            }
            entries.add(new AbstractMap.SimpleImmutableEntry<>(key, entry.getValue()));
        }
        entries.sort(Comparator.comparing(Map.Entry::getKey));
        builder.append('{');
        for (int index = 0; index < entries.size(); index++) {
            if (index > 0) {
                builder.append(',');
            }
            Map.Entry<String, Object> entry = entries.get(index);
            appendString(builder, entry.getKey());
            builder.append(':');
            append(builder, entry.getValue());
        }
        builder.append('}');
    }

    private static void appendIterable(StringBuilder builder, Iterable<?> iterable) {
        builder.append('[');
        boolean first = true;
        for (Object item : iterable) {
            if (!first) {
                builder.append(',');
            }
            append(builder, item);
            first = false;
        }
        builder.append(']');
    }

    private static void appendString(StringBuilder builder, String value) {
        Objects.requireNonNull(value, "value");
        builder.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 >= value.length()
                        || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    throw new IllegalArgumentException("canonical strings require valid Unicode");
                }
                builder.append(character).append(value.charAt(++index));
                continue;
            }
            if (Character.isLowSurrogate(character)) {
                throw new IllegalArgumentException("canonical strings require valid Unicode");
            }
            switch (character) {
                case '"' -> builder.append("\\\"");
                case '\\' -> builder.append("\\\\");
                case '\b' -> builder.append("\\b");
                case '\f' -> builder.append("\\f");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                default -> {
                    if (character < 0x20) {
                        builder.append(String.format("\\u%04x", (int) character));
                    } else {
                        builder.append(character);
                    }
                }
            }
        }
        builder.append('"');
    }
}
