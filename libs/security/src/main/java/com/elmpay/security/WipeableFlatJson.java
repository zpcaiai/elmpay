package com.elmpay.security;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Strict flat JSON string-object parser whose value storage is explicitly wipeable.
 *
 * <p>Keys may become immutable {@link String} instances; values never do unless a caller invokes
 * a metadata-only accessor. Secret values should be consumed with {@link #requireBase64Url}.
 */
public final class WipeableFlatJson implements AutoCloseable {
    private static final int MAX_FIELDS = 128;
    private static final int MAX_KEY_CHARS = 128;
    private static final int MAX_DOCUMENT_BYTES = 16 * 1024 * 1024;

    private final Map<String, char[]> values;
    private boolean closed;

    private WipeableFlatJson(Map<String, char[]> values) {
        this.values = values;
    }

    /** Decodes strict UTF-8 and parses one flat object containing string values only. */
    public static WipeableFlatJson parse(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length == 0 || encoded.length > MAX_DOCUMENT_BYTES) {
            throw new SecurityException("JSON document size is outside its configured bound");
        }
        char[] decoded = new char[encoded.length];
        int decodedLength;
        try {
            CharBuffer output = CharBuffer.wrap(decoded);
            var decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            var result = decoder.decode(ByteBuffer.wrap(encoded), output, true);
            if (result.isError()) {
                result.throwException();
            }
            result = decoder.flush(output);
            if (result.isError()) {
                result.throwException();
            }
            decodedLength = output.position();
        } catch (CharacterCodingException exception) {
            Arrays.fill(decoded, '\0');
            throw new SecurityException("JSON document is not strict UTF-8", exception);
        }

        Map<String, char[]> parsed = new LinkedHashMap<>();
        try {
            int[] cursor = {0};
            skipWhitespace(decoded, decodedLength, cursor);
            expect(decoded, decodedLength, cursor, '{');
            skipWhitespace(decoded, decodedLength, cursor);
            if (peek(decoded, decodedLength, cursor) == '}') {
                cursor[0]++;
            } else {
                while (true) {
                    if (parsed.size() == MAX_FIELDS) {
                        throw new SecurityException("JSON object has too many fields");
                    }
                    char[] keyChars = jsonString(decoded, decodedLength, cursor, MAX_KEY_CHARS);
                    String key;
                    try {
                        if (keyChars.length == 0 || containsControl(keyChars)) {
                            throw new SecurityException("JSON object has an invalid key");
                        }
                        key = new String(keyChars);
                    } finally {
                        Arrays.fill(keyChars, '\0');
                    }
                    skipWhitespace(decoded, decodedLength, cursor);
                    expect(decoded, decodedLength, cursor, ':');
                    skipWhitespace(decoded, decodedLength, cursor);
                    char[] value = jsonString(decoded, decodedLength, cursor, encoded.length);
                    boolean stored = false;
                    try {
                        if (parsed.putIfAbsent(key, value) != null) {
                            throw new SecurityException("JSON object has a duplicate key");
                        }
                        stored = true;
                    } finally {
                        if (!stored) {
                            Arrays.fill(value, '\0');
                        }
                    }
                    skipWhitespace(decoded, decodedLength, cursor);
                    char next = peek(decoded, decodedLength, cursor);
                    if (next == '}') {
                        cursor[0]++;
                        break;
                    }
                    expect(decoded, decodedLength, cursor, ',');
                    skipWhitespace(decoded, decodedLength, cursor);
                }
            }
            skipWhitespace(decoded, decodedLength, cursor);
            if (cursor[0] != decodedLength) {
                throw new SecurityException("JSON document has trailing data");
            }
            return new WipeableFlatJson(parsed);
        } catch (RuntimeException | Error exception) {
            wipe(parsed);
            throw exception;
        } finally {
            Arrays.fill(decoded, '\0');
        }
    }

    public synchronized Set<String> keys() {
        ensureOpen();
        return Set.copyOf(values.keySet());
    }

    /** Returns non-secret metadata as a String. Never use this for secret material. */
    public synchronized String requireMetadata(String key, int maximumCharacters) {
        char[] value = require(key);
        if (maximumCharacters < 1 || value.length == 0 || value.length > maximumCharacters
                || containsControl(value)) {
            throw new SecurityException("JSON metadata field has an invalid format");
        }
        return new String(value);
    }

    /** Compares a binding without converting the response value to an immutable String. */
    public synchronized void requireBound(String key, String expected) {
        Objects.requireNonNull(expected, "expected");
        char[] actual = require(key);
        int difference = actual.length ^ expected.length();
        int length = Math.max(actual.length, expected.length());
        for (int index = 0; index < length; index++) {
            char left = index < actual.length ? actual[index] : 0;
            char right = index < expected.length() ? expected.charAt(index) : 0;
            difference |= left ^ right;
        }
        if (difference != 0) {
            throw new SecurityException("JSON response binding mismatch");
        }
    }

    /** Decodes canonical, unpadded Base64URL directly from wipeable value storage. */
    public synchronized byte[] requireBase64Url(String key, int minimumBytes, int maximumBytes) {
        if (minimumBytes < 0 || maximumBytes < minimumBytes) {
            throw new IllegalArgumentException("invalid decoded byte bounds");
        }
        char[] value = require(key);
        byte[] encoded = new byte[value.length];
        byte[] decoded = null;
        try {
            for (int index = 0; index < value.length; index++) {
                if (value[index] > 0x7f) {
                    throw new SecurityException("JSON secret material is not ASCII Base64URL");
                }
                encoded[index] = (byte) value[index];
            }
            decoded = Base64.getUrlDecoder().decode(encoded);
            if (decoded.length < minimumBytes || decoded.length > maximumBytes) {
                throw new SecurityException("JSON secret material has an invalid decoded size");
            }
            byte[] canonical = Base64.getUrlEncoder().withoutPadding().encode(decoded);
            try {
                if (!MessageDigest.isEqual(encoded, canonical)) {
                    throw new SecurityException("JSON secret material is not canonical Base64URL");
                }
            } finally {
                Arrays.fill(canonical, (byte) 0);
            }
            byte[] result = decoded;
            decoded = null;
            return result;
        } catch (IllegalArgumentException exception) {
            throw new SecurityException("JSON secret material is invalid Base64URL", exception);
        } finally {
            Arrays.fill(encoded, (byte) 0);
            if (decoded != null) {
                Arrays.fill(decoded, (byte) 0);
            }
        }
    }

    public synchronized Instant requireInstant(String key) {
        String value = requireMetadata(key, 64);
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException exception) {
            throw new SecurityException("JSON timestamp is invalid", exception);
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        wipe(values);
        values.clear();
    }

    private char[] require(String key) {
        ensureOpen();
        char[] value = values.get(Objects.requireNonNull(key, "key"));
        if (value == null) {
            throw new SecurityException("JSON response is missing a required field");
        }
        return value;
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("JSON document is closed");
        }
    }

    private static char[] jsonString(char[] source, int length, int[] cursor, int maximumChars) {
        expect(source, length, cursor, '"');
        char[] value = new char[Math.min(maximumChars,
                Math.max(1, Math.min(64, length - cursor[0])))];
        int size = 0;
        try {
            while (cursor[0] < length) {
                char next = source[cursor[0]++];
                if (next == '"') {
                    return Arrays.copyOf(value, size);
                }
                char decoded = next;
                if (next == '\\') {
                    if (cursor[0] >= length) {
                        throw new SecurityException("JSON escape is truncated");
                    }
                    char escaped = source[cursor[0]++];
                    decoded = switch (escaped) {
                        case '"', '\\', '/' -> escaped;
                        case 'b' -> '\b';
                        case 'f' -> '\f';
                        case 'n' -> '\n';
                        case 'r' -> '\r';
                        case 't' -> '\t';
                        default -> throw new SecurityException("JSON escape is unsupported");
                    };
                } else if (next < 0x20) {
                    throw new SecurityException("JSON string contains a control character");
                }
                if (size == maximumChars) {
                    throw new SecurityException("JSON string exceeds its configured limit");
                }
                if (size == value.length) {
                    int nextLength = Math.min(maximumChars,
                            Math.max(size + 1, Math.multiplyExact(value.length, 2)));
                    char[] expanded = Arrays.copyOf(value, nextLength);
                    Arrays.fill(value, '\0');
                    value = expanded;
                }
                value[size++] = decoded;
            }
            throw new SecurityException("JSON string is unterminated");
        } finally {
            Arrays.fill(value, '\0');
        }
    }

    private static boolean containsControl(char[] value) {
        for (char character : value) {
            if (character < 0x20) {
                return true;
            }
        }
        return false;
    }

    private static void skipWhitespace(char[] source, int length, int[] cursor) {
        while (cursor[0] < length) {
            char value = source[cursor[0]];
            if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
                return;
            }
            cursor[0]++;
        }
    }

    private static void expect(char[] source, int length, int[] cursor, char expected) {
        if (peek(source, length, cursor) != expected) {
            throw new SecurityException("JSON document is malformed");
        }
        cursor[0]++;
    }

    private static char peek(char[] source, int length, int[] cursor) {
        if (cursor[0] >= length) {
            throw new SecurityException("JSON document is truncated");
        }
        return source[cursor[0]];
    }

    private static void wipe(Map<String, char[]> values) {
        values.values().forEach(value -> Arrays.fill(value, '\0'));
    }
}
