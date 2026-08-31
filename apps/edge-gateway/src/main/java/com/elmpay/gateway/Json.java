package com.elmpay.gateway;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small strict JSON codec. Numbers are integer-only to protect money fields. */
public final class Json {
    private Json() {
    }

    public static Object parse(String input) {
        Parser parser = new Parser(input);
        Object value = parser.value();
        parser.whitespace();
        if (!parser.done()) {
            throw new IllegalArgumentException("unexpected JSON content");
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(String input) {
        Object parsed = parse(input);
        if (!(parsed instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("JSON body must be an object");
        }
        return (Map<String, Object>) parsed;
    }

    public static String stringify(Object value) {
        StringBuilder output = new StringBuilder();
        write(output, value);
        return output.toString();
    }

    private static void write(StringBuilder output, Object value) {
        if (value == null) {
            output.append("null");
        } else if (value instanceof String text) {
            string(output, text);
        } else if (value instanceof Boolean || value instanceof Byte || value instanceof Short
                || value instanceof Integer || value instanceof Long) {
            output.append(value);
        } else if (value instanceof Enum<?> enumeration) {
            string(output, enumeration.name().toLowerCase(java.util.Locale.ROOT));
        } else if (value instanceof java.util.UUID || value instanceof java.time.Instant) {
            string(output, value.toString());
        } else if (value instanceof Map<?, ?> map) {
            output.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key)) {
                    throw new IllegalArgumentException("JSON object keys must be strings");
                }
                if (!first) {
                    output.append(',');
                }
                string(output, key);
                output.append(':');
                write(output, entry.getValue());
                first = false;
            }
            output.append('}');
        } else if (value instanceof Collection<?> collection) {
            output.append('[');
            boolean first = true;
            for (Object item : collection) {
                if (!first) {
                    output.append(',');
                }
                write(output, item);
                first = false;
            }
            output.append(']');
        } else {
            throw new IllegalArgumentException("unsupported JSON type: " + value.getClass().getName());
        }
    }

    private static void string(StringBuilder output, String value) {
        output.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isHighSurrogate(character)) {
                if (index + 1 >= value.length()
                        || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    throw new IllegalArgumentException("JSON string contains an unpaired surrogate");
                }
                output.append(character).append(value.charAt(++index));
                continue;
            }
            if (Character.isLowSurrogate(character)) {
                throw new IllegalArgumentException("JSON string contains an unpaired surrogate");
            }
            switch (character) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (character < 0x20) {
                        output.append(String.format("\\u%04x", (int) character));
                    } else {
                        output.append(character);
                    }
                }
            }
        }
        output.append('"');
    }

    private static final class Parser {
        private final String input;
        private int index;

        private Parser(String input) {
            this.input = java.util.Objects.requireNonNull(input, "input");
        }

        private Object value() {
            whitespace();
            if (done()) {
                throw new IllegalArgumentException("empty JSON");
            }
            return switch (input.charAt(index)) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Map<String, Object> object() {
            index++;
            Map<String, Object> result = new LinkedHashMap<>();
            whitespace();
            if (consume('}')) {
                return Collections.unmodifiableMap(result);
            }
            while (true) {
                whitespace();
                if (done() || input.charAt(index) != '"') {
                    throw new IllegalArgumentException("JSON object key must be a string");
                }
                String key = string();
                whitespace();
                expect(':');
                if (result.containsKey(key)) {
                    throw new IllegalArgumentException("duplicate JSON key: " + key);
                }
                result.put(key, value());
                whitespace();
                if (consume('}')) {
                    return Collections.unmodifiableMap(result);
                }
                expect(',');
            }
        }

        private List<Object> array() {
            index++;
            List<Object> result = new ArrayList<>();
            whitespace();
            if (consume(']')) {
                return List.copyOf(result);
            }
            while (true) {
                result.add(value());
                whitespace();
                if (consume(']')) {
                    return Collections.unmodifiableList(result);
                }
                expect(',');
            }
        }

        private String string() {
            expect('"');
            StringBuilder result = new StringBuilder();
            while (!done()) {
                char character = input.charAt(index++);
                if (character == '"') {
                    return result.toString();
                }
                if (character == '\\') {
                    if (done()) {
                        break;
                    }
                    char escape = input.charAt(index++);
                    switch (escape) {
                        case '"', '\\', '/' -> result.append(escape);
                        case 'b' -> result.append('\b');
                        case 'f' -> result.append('\f');
                        case 'n' -> result.append('\n');
                        case 'r' -> result.append('\r');
                        case 't' -> result.append('\t');
                        case 'u' -> unicode(result);
                        default -> throw new IllegalArgumentException("invalid JSON escape");
                    }
                } else if (character < 0x20) {
                    throw new IllegalArgumentException("control character in JSON string");
                } else if (Character.isHighSurrogate(character)) {
                    if (done() || !Character.isLowSurrogate(input.charAt(index))) {
                        throw new IllegalArgumentException(
                                "JSON string contains an unpaired surrogate");
                    }
                    result.append(character).append(input.charAt(index++));
                } else if (Character.isLowSurrogate(character)) {
                    throw new IllegalArgumentException("JSON string contains an unpaired surrogate");
                } else {
                    result.append(character);
                }
            }
            throw new IllegalArgumentException("unterminated JSON string");
        }

        private void unicode(StringBuilder result) {
            char first = unicodeCodeUnit();
            if (Character.isLowSurrogate(first)) {
                throw new IllegalArgumentException("JSON string contains an unpaired surrogate");
            }
            if (!Character.isHighSurrogate(first)) {
                result.append(first);
                return;
            }
            if (index + 6 > input.length() || input.charAt(index) != '\\'
                    || input.charAt(index + 1) != 'u') {
                throw new IllegalArgumentException("JSON string contains an unpaired surrogate");
            }
            index += 2;
            char second = unicodeCodeUnit();
            if (!Character.isLowSurrogate(second)) {
                throw new IllegalArgumentException("JSON string contains an unpaired surrogate");
            }
            result.append(first).append(second);
        }

        private char unicodeCodeUnit() {
            if (index + 4 > input.length()) {
                throw new IllegalArgumentException("invalid JSON unicode escape");
            }
            try {
                char value = (char) Integer.parseInt(input.substring(index, index + 4), 16);
                index += 4;
                return value;
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("invalid JSON unicode escape", exception);
            }
        }

        private Long number() {
            int start = index;
            if (consume('-') && done()) {
                throw new IllegalArgumentException("invalid JSON number");
            }
            if (consume('0')) {
                if (!done() && Character.isDigit(input.charAt(index))) {
                    throw new IllegalArgumentException("JSON number has a leading zero");
                }
            } else {
                while (!done() && Character.isDigit(input.charAt(index))) {
                    index++;
                }
            }
            if (start == index || (input.charAt(start) == '-' && start + 1 == index)
                    || (!done() && ".eE".indexOf(input.charAt(index)) >= 0)) {
                throw new IllegalArgumentException("only integer JSON numbers are accepted");
            }
            try {
                return Long.valueOf(input.substring(start, index));
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("JSON integer is outside int64", exception);
            }
        }

        private Object literal(String expected, Object value) {
            if (!input.startsWith(expected, index)) {
                throw new IllegalArgumentException("invalid JSON literal");
            }
            index += expected.length();
            return value;
        }

        private void whitespace() {
            while (!done()) {
                char character = input.charAt(index);
                if (character != ' ' && character != '\t'
                        && character != '\r' && character != '\n') {
                    return;
                }
                index++;
            }
        }

        private boolean consume(char expected) {
            if (!done() && input.charAt(index) == expected) {
                index++;
                return true;
            }
            return false;
        }

        private void expect(char expected) {
            if (!consume(expected)) {
                throw new IllegalArgumentException("expected '" + expected + "' in JSON");
            }
        }

        private boolean done() {
            return index >= input.length();
        }
    }
}
