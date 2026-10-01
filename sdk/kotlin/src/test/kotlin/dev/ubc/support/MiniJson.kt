package dev.ubc.support

import java.nio.charset.StandardCharsets

/**
 * A minimal, dependency-free JSON reader scoped to what spec/vectors/vectors.json actually
 * contains (objects, arrays, strings, non-negative integers, booleans, null). Test/tooling-
 * only code — not shipped in the library — written by hand instead of adding a JSON library
 * dependency, mirroring the same choice the Rust and Java ports' test support already make
 * for this same file (Kotlin/JVM has no JSON support in the bare JDK either).
 */
class MiniJson private constructor(private val input: ByteArray) {
    private var offset = 0

    companion object {
        fun parse(input: ByteArray): Any? {
            val parser = MiniJson(input)
            val value = parser.value()
            parser.whitespace()
            if (parser.offset != input.size) {
                throw IllegalArgumentException("unexpected JSON content at byte ${parser.offset}")
            }
            return value
        }

        @Suppress("UNCHECKED_CAST")
        fun asObject(value: Any?): Map<String, Any?> =
            value as? Map<String, Any?> ?: throw IllegalArgumentException("expected a JSON object")

        @Suppress("UNCHECKED_CAST")
        fun asArray(value: Any?): List<Any?> =
            value as? List<Any?> ?: throw IllegalArgumentException("expected a JSON array")

        fun asString(value: Any?): String = value as? String ?: throw IllegalArgumentException("expected a JSON string")

        fun asNumber(value: Any?): Long = value as? Long ?: throw IllegalArgumentException("expected a JSON number")
    }

    private fun value(): Any? {
        whitespace()
        val next = peek() ?: throw IllegalArgumentException("invalid JSON value at byte $offset")
        return when (next) {
            'n'.code -> literal("null", null)
            't'.code -> literal("true", true)
            'f'.code -> literal("false", false)
            '"'.code -> string()
            '['.code -> array()
            '{'.code -> objectValue()
            else -> if (next in '0'.code..'9'.code) number() else throw IllegalArgumentException("invalid JSON value at byte $offset")
        }
    }

    private fun literal(expected: String, value: Any?): Any? {
        val bytes = expected.toByteArray(StandardCharsets.US_ASCII)
        if (offset + bytes.size > input.size) {
            throw IllegalArgumentException("invalid JSON literal at byte $offset")
        }
        for (i in bytes.indices) {
            if (input[offset + i] != bytes[i]) {
                throw IllegalArgumentException("invalid JSON literal at byte $offset")
            }
        }
        offset += bytes.size
        return value
    }

    private fun number(): Long {
        val start = offset
        while (peek() != null && peek()!! in '0'.code..'9'.code) {
            offset++
        }
        return String(input, start, offset - start, StandardCharsets.US_ASCII).toLong()
    }

    private fun string(): String {
        expect('"'.code)
        val output = StringBuilder()
        while (true) {
            val b = next() ?: throw IllegalArgumentException("unterminated JSON string")
            when {
                b == '"'.code -> return output.toString()
                b == '\\'.code -> escape(output)
                b < 0x20 -> throw IllegalArgumentException("control byte in JSON string")
                else -> output.append(b.toChar())
            }
        }
    }

    private fun escape(output: StringBuilder) {
        val b = next() ?: throw IllegalArgumentException("truncated JSON escape")
        when (b) {
            '"'.code -> output.append('"')
            '\\'.code -> output.append('\\')
            '/'.code -> output.append('/')
            'b'.code -> output.append('\b')
            'f'.code -> output.append('')
            'n'.code -> output.append('\n')
            'r'.code -> output.append('\r')
            't'.code -> output.append('\t')
            'u'.code -> {
                if (offset + 4 > input.size) {
                    throw IllegalArgumentException("truncated JSON unicode escape")
                }
                val digits = String(input, offset, 4, StandardCharsets.US_ASCII)
                output.append(digits.toInt(16).toChar())
                offset += 4
            }
            else -> throw IllegalArgumentException("invalid JSON escape")
        }
    }

    private fun array(): List<Any?> {
        expect('['.code)
        val values = mutableListOf<Any?>()
        whitespace()
        if (consume(']'.code)) {
            return values
        }
        while (true) {
            values.add(value())
            whitespace()
            if (consume(']'.code)) {
                return values
            }
            expect(','.code)
        }
    }

    private fun objectValue(): Map<String, Any?> {
        expect('{'.code)
        val values = LinkedHashMap<String, Any?>()
        whitespace()
        if (consume('}'.code)) {
            return values
        }
        while (true) {
            whitespace()
            val key = string()
            whitespace()
            expect(':'.code)
            val value = value()
            if (values.put(key, value) != null) {
                throw IllegalArgumentException("duplicate JSON object key: $key")
            }
            whitespace()
            if (consume('}'.code)) {
                return values
            }
            expect(','.code)
        }
    }

    private fun whitespace() {
        while (peek() != null && (peek() == ' '.code || peek() == '\t'.code || peek() == '\n'.code || peek() == '\r'.code)) {
            offset++
        }
    }

    private fun peek(): Int? = if (offset < input.size) input[offset].toInt() and 0xFF else null

    private fun next(): Int? {
        val value = peek()
        if (value != null) offset++
        return value
    }

    private fun expect(expected: Int) {
        val actual = next()
        if (actual == null || actual != expected) {
            throw IllegalArgumentException("expected '${expected.toChar()}' at byte $offset")
        }
    }

    private fun consume(expected: Int): Boolean {
        if (peek() != null && peek() == expected) {
            offset++
            return true
        }
        return false
    }
}
