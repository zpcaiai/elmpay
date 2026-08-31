package com.elmpay.gateway;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Shared fail-closed request framing for edge-gateway JSON APIs. */
final class StrictJsonHttpRequest {
    private static final int MAX_PATH_BYTES = 2_048;
    private static final int MAX_QUERY_BYTES = 8_192;
    private static final int MAX_HEADER_VALUES = 128;
    private static final int MAX_HEADER_BYTES = 65_536;

    private StrictJsonHttpRequest() {
    }

    static void validateEnvelope(HttpExchange exchange) {
        Objects.requireNonNull(exchange, "exchange");
        URI request = exchange.getRequestURI();
        String rawPath = request.getRawPath();
        String rawQuery = request.getRawQuery();
        if (request.isAbsolute() || request.getRawAuthority() != null
                || request.getRawFragment() != null || rawPath == null || rawPath.isEmpty()
                || rawPath.length() > MAX_PATH_BYTES || rawPath.indexOf('%') >= 0
                || !rawPath.equals(request.getPath())
                || !rawPath.equals(request.normalize().getRawPath()) || rawPath.contains("//")
                || !rawPath.matches("/[A-Za-z0-9._~/-]*")
                || (rawQuery != null && (rawQuery.length() > MAX_QUERY_BYTES
                        || rawQuery.chars().anyMatch(value -> value < 0x20 || value == 0x7f)))) {
            throw new IllegalArgumentException("request target is not canonical origin-form");
        }
        int values = 0;
        int bytes = 0;
        Set<String> normalizedNames = new HashSet<>();
        for (Map.Entry<String, List<String>> header
                : exchange.getRequestHeaders().entrySet()) {
            String name = header.getKey();
            if (name == null || !name.matches("[A-Za-z0-9-]{1,64}")) {
                throw new IllegalArgumentException("request header name is invalid");
            }
            if (!normalizedNames.add(name.toLowerCase(Locale.ROOT))) {
                throw new IllegalArgumentException("request header name is duplicated");
            }
            bytes = Math.addExact(bytes, name.length());
            values = Math.addExact(values, header.getValue().size());
            for (String value : header.getValue()) {
                if (value == null || value.length() > 8_192
                        || value.chars().anyMatch(character -> character < 0x20
                                || character == 0x7f)) {
                    throw new IllegalArgumentException("request header value is invalid");
                }
                bytes = Math.addExact(bytes, value.length());
            }
            if (values > MAX_HEADER_VALUES || bytes > MAX_HEADER_BYTES) {
                throw new IllegalArgumentException("request headers exceed their bound");
            }
        }
        List<String> transferEncoding = exchange.getRequestHeaders().get("Transfer-Encoding");
        List<String> contentLength = exchange.getRequestHeaders().get("Content-Length");
        if (transferEncoding != null && contentLength != null) {
            throw new IllegalArgumentException(
                    "Content-Length and Transfer-Encoding cannot both be supplied");
        }
    }

    static Map<String, Object> body(HttpExchange exchange, int maximumBytes,
            Set<String> allowedFields) throws IOException {
        if (maximumBytes < 2 || maximumBytes > 16 * 1024 * 1024) {
            throw new IllegalArgumentException("JSON request body limit is invalid");
        }
        Objects.requireNonNull(allowedFields, "allowedFields");
        String contentType = requiredHeader(exchange, "Content-Type", 128);
        if (!"application/json".equalsIgnoreCase(contentType)) {
            throw new IllegalArgumentException("one exact application/json content type is required");
        }
        List<String> lengths = exchange.getRequestHeaders().get("Content-Length");
        long declaredLength = -1;
        if (lengths != null) {
            if (lengths.size() != 1
                    || !lengths.getFirst().matches("(?:0|[1-9][0-9]{0,8})")) {
                throw new IllegalArgumentException("Content-Length is ambiguous or non-canonical");
            }
            declaredLength = Long.parseLong(lengths.getFirst());
            if (declaredLength < 2 || declaredLength > maximumBytes) {
                throw new IllegalArgumentException("request body is outside its bound");
            }
        }
        byte[] raw = exchange.getRequestBody().readNBytes(maximumBytes + 1);
        try {
            if (raw.length < 2 || raw.length > maximumBytes
                    || (declaredLength >= 0 && raw.length != declaredLength)) {
                throw new IllegalArgumentException("request body is outside its bound");
            }
            Map<String, Object> value = Json.object(strictUtf8(raw));
            if (!allowedFields.containsAll(value.keySet())) {
                throw new IllegalArgumentException("unknown request field");
            }
            return value;
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    static String requiredHeader(HttpExchange exchange, String name, int maximumLength) {
        String value = optionalHeader(exchange, name, maximumLength);
        if (value == null) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    static String optionalHeader(HttpExchange exchange, String name, int maximumLength) {
        if (maximumLength < 1 || maximumLength > 8_192) {
            throw new IllegalArgumentException("header length bound is invalid");
        }
        List<String> values = exchange.getRequestHeaders().get(name);
        if (values == null) {
            return null;
        }
        if (values.size() != 1) {
            throw new IllegalArgumentException(name + " is ambiguous");
        }
        String value = values.getFirst();
        if (value == null || value.isBlank() || value.length() > maximumLength
                || value.chars().anyMatch(character -> character < 0x20
                        || character == 0x7f)) {
            throw new IllegalArgumentException(name + " is invalid");
        }
        return value;
    }

    private static String strictUtf8(byte[] value) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("request body is not strict UTF-8", exception);
        }
    }
}
