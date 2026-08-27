package com.elmpay.payment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import com.elmpay.money.Money;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * B34 conformance — replays {@code contracts/capture/vectors.json} against the real state machine.
 *
 * <p>The vectors are generated from {@code governance/capture-lifecycle.json} and the Python
 * reference. This test is the other half of that contract: it drives {@link PaymentStateMachine},
 * not a Java copy of the model, so relaxing a rule in either implementation shows up as a failing
 * case here rather than as two systems that quietly disagree about how much of the payer's money
 * is still on hold.
 *
 * <p>Unknown-outcome resolution is deliberately absent: it belongs to B33 and is proven by that
 * batch's vectors. A case list that grew to cover it here would be testing someone else's rule.
 */
class CaptureLifecycleVectorsTest {

    private static final String VECTORS = "contracts/capture/vectors.json";
    private static final String CURRENCY = "CNY";
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(START, ZoneOffset.UTC);
    private static final AuthoritySource AUTHORITY = AuthoritySource.SERVER_SIDE_PROVIDER_RESULT;

    @TestFactory
    Stream<DynamicTest> replaysEveryCaptureLifecycleVector() throws IOException {
        Map<String, Object> vectors = readVectors();
        long authorized = number(vectors.get("authorized_minor"));
        List<Object> cases = list(vectors.get("cases"));
        assertTrue(cases.size() >= 10,
                "the conformance vectors are missing; an empty contract proves nothing");
        return cases.stream().map(entry -> {
            Map<String, Object> vector = map(entry);
            String id = String.valueOf(vector.get("id"));
            return dynamicTest(id, () -> replay(id, authorized, vector));
        });
    }

    private void replay(String id, long authorized, Map<String, Object> vector) {
        PaymentStateMachine machine = new PaymentStateMachine();
        PaymentIntent intent = seed(String.valueOf(vector.get("initial_state")), authorized);
        Map<String, Object> expected = map(vector.get("expected"));

        Integer refusedAtStep = null;
        String refusedWith = null;
        List<Object> operations = list(vector.get("operations"));
        for (int index = 0; index < operations.size(); index++) {
            Map<String, Object> step = map(operations.get(index));
            try {
                intent = apply(machine, intent, step, authorized);
            } catch (PaymentCoreException refusal) {
                refusedAtStep = index;
                refusedWith = refusal.code();
                break;
            }
        }

        assertEquals(expected.get("refused_with"), refusedWith,
                id + ": refused for a different reason than the contract states");
        assertEquals(expected.get("refused_at_step") == null
                        ? null : (int) number(expected.get("refused_at_step")), refusedAtStep,
                id + ": refused at a different step");
        assertEquals(String.valueOf(expected.get("state")), lifecycleState(intent),
                id + ": ended in a different lifecycle state");
        assertEquals(number(expected.get("captured_minor")), intent.capturedAmountMinor(),
                id + ": captured a different amount");
        assertEquals(number(expected.get("released_minor")), released(intent, authorized),
                id + ": released a different amount of the payer's hold");
        assertEquals(number(expected.get("held_until_expiry_minor")), heldUntilExpiry(intent),
                id + ": left a different amount held until expiry");
    }

    private PaymentIntent apply(PaymentStateMachine machine, PaymentIntent intent,
            Map<String, Object> step, long authorized) {
        String operation = String.valueOf(step.get("op"));
        return switch (operation) {
            case "capture" -> {
                long amount = number(step.get("amount_minor"));
                long cumulative = intent.capturedAmountMinor() + amount;
                yield machine.recordCapture(intent, cumulative, cumulative == authorized,
                        AUTHORITY, CLOCK.instant());
            }
            case "void" -> machine.voidAuthorization(intent, AUTHORITY, CLOCK.instant());
            case "close" -> machine.closeAfterPartialCapture(intent, AUTHORITY, CLOCK.instant());
            case "expire" -> machine.expire(intent, intent.expiresAt().plusSeconds(1));
            default -> throw new IllegalStateException("unknown vector operation " + operation);
        };
    }

    private PaymentIntent seed(String initialState, long authorized) {
        PaymentIntent intent = PaymentIntent.create(new CreateIntentCommand(
                UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), "order-" + initialState,
                Money.of(authorized, CURRENCY), Set.of("card"), ConfirmationMode.MANUAL_CAPTURE,
                "CN", Duration.ofHours(1), "idem-" + UUID.randomUUID()), CLOCK);
        return switch (initialState) {
            case "created" -> intent;
            case "authorized" -> intent.withState(IntentState.AUTHORIZED, CLOCK.instant());
            default -> throw new IllegalStateException("unknown initial state " + initialState);
        };
    }

    /** Collapse the intent state onto the vocabulary the contract speaks. */
    private static String lifecycleState(PaymentIntent intent) {
        return switch (intent.state()) {
            case CREATED, REQUIRES_ACTION, AUTHORIZED -> "active";
            case CAPTURED -> "captured";
            case CANCELED -> "canceled";
            case EXPIRED -> "expired";
            case FAILED -> "failed";
        };
    }

    private static long released(PaymentIntent intent, long authorized) {
        return switch (intent.state()) {
            case CANCELED -> authorized;
            case CAPTURED -> authorized - intent.capturedAmountMinor();
            default -> 0L;
        };
    }

    private static long heldUntilExpiry(PaymentIntent intent) {
        return intent.state() == IntentState.EXPIRED
                ? intent.amount().amountMinor() - intent.capturedAmountMinor() : 0L;
    }

    private static Map<String, Object> readVectors() throws IOException {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.isRegularFile(root.resolve(VECTORS))) {
            root = root.getParent();
        }
        assertTrue(root != null, "cannot find " + VECTORS + " above the working directory");
        return map(Json.parse(Files.readString(root.resolve(VECTORS), StandardCharsets.UTF_8)));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Object value) {
        return (List<Object>) value;
    }

    private static long number(Object value) {
        return ((Number) value).longValue();
    }

    /**
     * A JSON reader small enough to read in one sitting.
     *
     * <p>The toolchain forbids third-party runtime dependencies, and a conformance test that
     * needed one would be the first place that rule got bent.
     */
    private static final class Json {
        private final String source;
        private int at;

        private Json(String source) {
            this.source = source;
        }

        static Object parse(String source) {
            Json json = new Json(source);
            json.skipWhitespace();
            Object value = json.readValue();
            json.skipWhitespace();
            if (json.at != source.length()) {
                throw new IllegalStateException("trailing JSON at offset " + json.at);
            }
            return value;
        }

        private Object readValue() {
            skipWhitespace();
            char c = source.charAt(at);
            return switch (c) {
                case '{' -> readObject();
                case '[' -> readArray();
                case '"' -> readString();
                case 't' -> readLiteral("true", Boolean.TRUE);
                case 'f' -> readLiteral("false", Boolean.FALSE);
                case 'n' -> readLiteral("null", null);
                default -> readNumber();
            };
        }

        private Map<String, Object> readObject() {
            Map<String, Object> result = new LinkedHashMap<>();
            at++;
            skipWhitespace();
            if (source.charAt(at) == '}') {
                at++;
                return result;
            }
            while (true) {
                skipWhitespace();
                String key = readString();
                skipWhitespace();
                expect(':');
                result.put(key, readValue());
                skipWhitespace();
                char c = source.charAt(at++);
                if (c == '}') {
                    return result;
                }
                if (c != ',') {
                    throw new IllegalStateException("expected , or } at offset " + (at - 1));
                }
            }
        }

        private List<Object> readArray() {
            List<Object> result = new ArrayList<>();
            at++;
            skipWhitespace();
            if (source.charAt(at) == ']') {
                at++;
                return result;
            }
            while (true) {
                result.add(readValue());
                skipWhitespace();
                char c = source.charAt(at++);
                if (c == ']') {
                    return result;
                }
                if (c != ',') {
                    throw new IllegalStateException("expected , or ] at offset " + (at - 1));
                }
            }
        }

        private String readString() {
            expect('"');
            StringBuilder builder = new StringBuilder();
            while (true) {
                char c = source.charAt(at++);
                if (c == '"') {
                    return builder.toString();
                }
                if (c != '\\') {
                    builder.append(c);
                    continue;
                }
                char escape = source.charAt(at++);
                switch (escape) {
                    case '"', '\\', '/' -> builder.append(escape);
                    case 'b' -> builder.append('\b');
                    case 'f' -> builder.append('\f');
                    case 'n' -> builder.append('\n');
                    case 'r' -> builder.append('\r');
                    case 't' -> builder.append('\t');
                    case 'u' -> {
                        builder.append((char) Integer.parseInt(source.substring(at, at + 4), 16));
                        at += 4;
                    }
                    default -> throw new IllegalStateException("bad escape \\" + escape);
                }
            }
        }

        private Object readLiteral(String literal, Object value) {
            if (!source.startsWith(literal, at)) {
                throw new IllegalStateException("expected " + literal + " at offset " + at);
            }
            at += literal.length();
            return value;
        }

        private Object readNumber() {
            int start = at;
            while (at < source.length() && "+-.eE0123456789".indexOf(source.charAt(at)) >= 0) {
                at++;
            }
            String text = source.substring(start, at);
            return text.contains(".") || text.contains("e") || text.contains("E")
                    ? (Object) Double.valueOf(text) : (Object) Long.valueOf(text);
        }

        private void expect(char expected) {
            if (source.charAt(at++) != expected) {
                throw new IllegalStateException("expected " + expected + " at offset " + (at - 1));
            }
        }

        private void skipWhitespace() {
            while (at < source.length() && Character.isWhitespace(source.charAt(at))) {
                at++;
            }
        }
    }
}
