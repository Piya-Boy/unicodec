package dev.ubc

import java.io.File

object PlainVectorsTest {
    private fun vectorRoot(): File = File(System.getProperty("user.dir"), "../../spec/vectors").canonicalFile

    private fun readVector(relative: String): ByteArray = File(vectorRoot(), relative).readBytes()

    private fun hex(value: String): ByteArray {
        val result = ByteArray(value.length / 2)
        for (i in value.indices step 2) {
            result[i / 2] = value.substring(i, i + 2).toInt(16).toByte()
        }
        return result
    }

    fun register() {
        TestRunner.test("encodes every plain vector byte-exactly") {
            assertEquals(
                readVector("expected/plain-empty.ubc"),
                Payload.encodePlain(readVector("inputs/empty.bin"), emptyList(), 1L shl 20),
            )
            assertEquals(
                readVector("expected/plain-one-byte.ubc"),
                Payload.encodePlain(readVector("inputs/one-byte.bin"), emptyList(), 1L shl 20),
            )
            assertEquals(
                readVector("expected/plain-chunk-1m.ubc"),
                Payload.encodePlain(readVector("inputs/chunk-1m.bin"), emptyList(), 1L shl 20),
            )
            assertEquals(
                readVector("expected/plain-chunk-1m-plus-one.ubc"),
                Payload.encodePlain(readVector("inputs/chunk-1m-plus-one.bin"), emptyList(), 1L shl 20),
            )
            assertEquals(
                readVector("expected/plain-multi-3m.ubc"),
                Payload.encodePlain(readVector("inputs/multi-3m.bin"), emptyList(), 1L shl 20),
            )

            val entries = listOf(
                MetadataEntry(0x0001, hex("e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874")),
                MetadataEntry(0x0002, hex("746578742f706c61696e")),
                MetadataEntry(0x0003, hex("00a8da769b010000")),
                MetadataEntry(0x1000, hex("00ff7f")),
            )
            assertEquals(
                readVector("expected/plain-metadata.ubc"),
                Payload.encodePlain(readVector("inputs/one-byte.bin"), entries, 1L shl 20),
            )
        }

        TestRunner.test("decodes every plain vector") {
            decodeMatchesInput("expected/plain-empty.ubc", "inputs/empty.bin")
            decodeMatchesInput("expected/plain-one-byte.ubc", "inputs/one-byte.bin")
            decodeMatchesInput("expected/plain-chunk-1m.ubc", "inputs/chunk-1m.bin")
            decodeMatchesInput("expected/plain-chunk-1m-plus-one.ubc", "inputs/chunk-1m-plus-one.bin")
            decodeMatchesInput("expected/plain-multi-3m.ubc", "inputs/multi-3m.bin")
            decodeMatchesInput("expected/plain-metadata.ubc", "inputs/one-byte.bin")
        }

        TestRunner.test("flipped plain payload returns ERR_ROOT_MISMATCH") {
            val container = readVector("expected/plain-chunk-1m.ubc")
            container[Header.SIZE + 4] = (container[Header.SIZE + 4].toInt() xor 0x01).toByte()
            assertThrowsUbc(ErrorCode.ERR_ROOT_MISMATCH) { Payload.decodePlain(container) }
        }

        val negatives = listOf(
            "negative-truncated.ubc" to ErrorCode.ERR_TRUNCATED,
            "negative-root-mismatch.ubc" to ErrorCode.ERR_ROOT_MISMATCH,
            "negative-trailing-data.ubc" to ErrorCode.ERR_TRAILING_DATA,
            "negative-oversized-clen.ubc" to ErrorCode.ERR_TRUNCATED,
        )
        for ((name, expected) in negatives) {
            TestRunner.test("plain negative vector: $name") {
                val container = readVector("expected/$name")
                assertThrowsUbc(expected, name) { Payload.decodePlain(container) }
            }
        }
    }

    private fun decodeMatchesInput(container: String, input: String) {
        val result = Payload.decodePlain(readVector(container))
        assertEquals(readVector(input), result.data, container)
    }
}
