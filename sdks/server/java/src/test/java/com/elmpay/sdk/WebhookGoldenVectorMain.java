package com.elmpay.sdk;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** JDK-only executable check used by scripts/sdk-contract-smoke.py. */
public final class WebhookGoldenVectorMain {
    private WebhookGoldenVectorMain() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("golden vector path is required");
        }
        String vector = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
        long timestamp = Long.parseLong(field(vector, "timestamp", "([0-9]+)"));
        byte[] secret = Base64.getUrlDecoder().decode(field(vector, "secret_base64url",
                "\"([A-Za-z0-9_-]+)\""));
        byte[] body = unescape(field(vector, "raw_body_utf8",
                "\"((?:\\\\.|[^\"\\\\])*)\"")).getBytes(StandardCharsets.UTF_8);
        String header = field(vector, "signature_header", "\"([^\"]+)\"");
        Clock clock = Clock.fixed(Instant.ofEpochSecond(timestamp), ZoneOffset.UTC);
        if (!ElmpayClient.verifyWebhook(secret, body, header, clock, Duration.ofMinutes(5))) {
            throw new AssertionError("Java SDK rejected the webhook golden vector");
        }
        if (ElmpayClient.verifyWebhook(secret, "{}".getBytes(StandardCharsets.UTF_8), header,
                clock, Duration.ofMinutes(5))) {
            throw new AssertionError("Java SDK accepted tampered webhook bytes");
        }
        System.out.println("java webhook golden vector: PASS");
    }

    private static String field(String json, String name, String valuePattern) {
        Matcher matcher = Pattern.compile("\\\"" + Pattern.quote(name)
                + "\\\"\\s*:\\s*" + valuePattern).matcher(json);
        if (!matcher.find()) {
            throw new IllegalArgumentException("golden vector field is missing: " + name);
        }
        return matcher.group(1);
    }

    private static String unescape(String value) {
        StringBuilder result = new StringBuilder(value.length());
        boolean escaped = false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (escaped) {
                result.append(switch (character) {
                    case '"', '\\', '/' -> character;
                    case 'b' -> '\b';
                    case 'f' -> '\f';
                    case 'n' -> '\n';
                    case 'r' -> '\r';
                    case 't' -> '\t';
                    default -> throw new IllegalArgumentException("unsupported JSON escape");
                });
                escaped = false;
            } else if (character == '\\') {
                escaped = true;
            } else {
                result.append(character);
            }
        }
        if (escaped) {
            throw new IllegalArgumentException("invalid JSON string escape");
        }
        return result.toString();
    }
}
