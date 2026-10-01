package dev.ubc.support;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal, dependency-free JSON reader scoped to what spec/vectors/vectors.json actually
 * contains (objects, arrays, strings, non-negative integers, booleans, null). Test/tooling-only
 * code — not shipped in the library — written by hand instead of adding a JSON library
 * dependency, mirroring the same choice the Rust port's test support makes for the same file.
 */
public final class MiniJson {
    private final byte[] input;
    private int offset;

    private MiniJson(byte[] input) {
        this.input = input;
    }

    public static Object parse(byte[] input) {
        MiniJson parser = new MiniJson(input);
        Object value = parser.value();
        parser.whitespace();
        if (parser.offset != input.length) {
            throw new IllegalArgumentException("unexpected JSON content at byte " + parser.offset);
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(Object value) {
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("expected a JSON object");
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> array(Object value) {
        if (!(value instanceof List)) {
            throw new IllegalArgumentException("expected a JSON array");
        }
        return (List<Object>) value;
    }

    public static String string(Object value) {
        if (!(value instanceof String)) {
            throw new IllegalArgumentException("expected a JSON string");
        }
        return (String) value;
    }

    public static long number(Object value) {
        if (!(value instanceof Long)) {
            throw new IllegalArgumentException("expected a JSON number");
        }
        return (Long) value;
    }

    private Object value() {
        whitespace();
        Integer next = peek();
        if (next == null) {
            throw new IllegalArgumentException("invalid JSON value at byte " + offset);
        }
        return switch (next.intValue()) {
            case 'n' -> literal("null", null);
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case '"' -> string();
            case '[' -> array();
            case '{' -> object();
            default -> {
                if (next >= '0' && next <= '9') {
                    yield number();
                }
                throw new IllegalArgumentException("invalid JSON value at byte " + offset);
            }
        };
    }

    private Object literal(String expected, Object value) {
        byte[] bytes = expected.getBytes(StandardCharsets.US_ASCII);
        if (offset + bytes.length > input.length) {
            throw new IllegalArgumentException("invalid JSON literal at byte " + offset);
        }
        for (int i = 0; i < bytes.length; i++) {
            if (input[offset + i] != bytes[i]) {
                throw new IllegalArgumentException("invalid JSON literal at byte " + offset);
            }
        }
        offset += bytes.length;
        return value;
    }

    private long number() {
        int start = offset;
        while (peek() != null && peek() >= '0' && peek() <= '9') {
            offset++;
        }
        String digits = new String(input, start, offset - start, StandardCharsets.US_ASCII);
        return Long.parseLong(digits);
    }

    private String string() {
        expect('"');
        StringBuilder output = new StringBuilder();
        while (true) {
            Integer b = next();
            if (b == null) {
                throw new IllegalArgumentException("unterminated JSON string");
            }
            if (b == '"') {
                return output.toString();
            }
            if (b == '\\') {
                escape(output);
            } else if (b < 0x20) {
                throw new IllegalArgumentException("control byte in JSON string");
            } else {
                output.append((char) (int) b);
            }
        }
    }

    private void escape(StringBuilder output) {
        Integer b = next();
        if (b == null) {
            throw new IllegalArgumentException("truncated JSON escape");
        }
        switch (b.intValue()) {
            case '"' -> output.append('"');
            case '\\' -> output.append('\\');
            case '/' -> output.append('/');
            case 'b' -> output.append('\b');
            case 'f' -> output.append('\f');
            case 'n' -> output.append('\n');
            case 'r' -> output.append('\r');
            case 't' -> output.append('\t');
            case 'u' -> {
                if (offset + 4 > input.length) {
                    throw new IllegalArgumentException("truncated JSON unicode escape");
                }
                String digits = new String(input, offset, 4, StandardCharsets.US_ASCII);
                output.append((char) Integer.parseInt(digits, 16));
                offset += 4;
            }
            default -> throw new IllegalArgumentException("invalid JSON escape");
        }
    }

    private List<Object> array() {
        expect('[');
        List<Object> values = new ArrayList<>();
        whitespace();
        if (consume(']')) {
            return values;
        }
        while (true) {
            values.add(value());
            whitespace();
            if (consume(']')) {
                return values;
            }
            expect(',');
        }
    }

    private Map<String, Object> object() {
        expect('{');
        Map<String, Object> values = new LinkedHashMap<>();
        whitespace();
        if (consume('}')) {
            return values;
        }
        while (true) {
            whitespace();
            String key = string();
            whitespace();
            expect(':');
            Object value = value();
            if (values.put(key, value) != null) {
                throw new IllegalArgumentException("duplicate JSON object key: " + key);
            }
            whitespace();
            if (consume('}')) {
                return values;
            }
            expect(',');
        }
    }

    private void whitespace() {
        while (peek() != null && (peek() == ' ' || peek() == '\t' || peek() == '\n' || peek() == '\r')) {
            offset++;
        }
    }

    private Integer peek() {
        return offset < input.length ? Byte.toUnsignedInt(input[offset]) : null;
    }

    private Integer next() {
        Integer value = peek();
        if (value != null) {
            offset++;
        }
        return value;
    }

    private void expect(int expected) {
        Integer actual = next();
        if (actual == null || actual != expected) {
            throw new IllegalArgumentException("expected '" + (char) expected + "' at byte " + offset);
        }
    }

    private boolean consume(int expected) {
        if (peek() != null && peek() == expected) {
            offset++;
            return true;
        }
        return false;
    }
}
