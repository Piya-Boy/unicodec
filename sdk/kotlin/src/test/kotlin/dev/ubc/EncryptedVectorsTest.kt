package dev.ubc

import java.io.File

object EncryptedVectorsTest {
    private val KEY = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val BASE_NONCE = hex("f0e0d0c0b0a0908070605040")

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
        TestRunner.test("encodes every encrypted vector byte-exactly") {
            assertEquals(
                readVector("expected/encrypted-empty.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(readVector("inputs/empty.bin"), KEY, BASE_NONCE, emptyList(), 1L shl 20),
            )
            assertEquals(
                readVector("expected/encrypted-one-byte.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(readVector("inputs/one-byte.bin"), KEY, BASE_NONCE, emptyList(), 1L shl 20),
            )
            assertEquals(
                readVector("expected/encrypted-chunk-1m.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(readVector("inputs/chunk-1m.bin"), KEY, BASE_NONCE, emptyList(), 1L shl 20),
            )
            assertEquals(
                readVector("expected/encrypted-chunk-1m-plus-one.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(readVector("inputs/chunk-1m-plus-one.bin"), KEY, BASE_NONCE, emptyList(), 1L shl 20),
            )
            assertEquals(
                readVector("expected/encrypted-multi-3m.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(readVector("inputs/multi-3m.bin"), KEY, BASE_NONCE, emptyList(), 1L shl 20),
            )

            val entries = listOf(
                MetadataEntry(0x0001, hex("e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874")),
                MetadataEntry(0x0002, hex("746578742f706c61696e")),
                MetadataEntry(0x0003, hex("00a8da769b010000")),
                MetadataEntry(0x1000, hex("00ff7f")),
            )
            assertEquals(
                readVector("expected/encrypted-metadata.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(readVector("inputs/one-byte.bin"), KEY, BASE_NONCE, entries, 1L shl 20),
            )
        }

        TestRunner.test("decodes every encrypted vector") {
            decodeMatchesInput("expected/encrypted-empty.ubc", "inputs/empty.bin")
            decodeMatchesInput("expected/encrypted-one-byte.ubc", "inputs/one-byte.bin")
            decodeMatchesInput("expected/encrypted-chunk-1m.ubc", "inputs/chunk-1m.bin")
            decodeMatchesInput("expected/encrypted-chunk-1m-plus-one.ubc", "inputs/chunk-1m-plus-one.bin")
            decodeMatchesInput("expected/encrypted-multi-3m.ubc", "inputs/multi-3m.bin")
            decodeMatchesInput("expected/encrypted-metadata.ubc", "inputs/one-byte.bin")
        }

        TestRunner.test("wrong key returns ERR_CHUNK_AUTH on non-empty ciphertext") {
            val container = readVector("expected/encrypted-one-byte.ubc")
            val wrongKey = KEY.copyOf()
            wrongKey[0] = (wrongKey[0].toInt() xor 0x01).toByte()
            val options = DecodeOptions().withKey(wrongKey)
            assertThrowsUbc(ErrorCode.ERR_CHUNK_AUTH) { Crypto.decodeEncrypted(container, options) }
        }

        TestRunner.test("missing key returns ERR_MISSING_KEY") {
            val container = readVector("expected/encrypted-one-byte.ubc")
            assertThrowsUbc(ErrorCode.ERR_MISSING_KEY) { Crypto.decodeEncrypted(container, DecodeOptions()) }
        }

        val negatives = listOf(
            Triple("negative-chunk-auth.ubc", ErrorCode.ERR_CHUNK_AUTH, true),
            Triple("negative-encrypted-short-clen.ubc", ErrorCode.ERR_CHUNK_AUTH, true),
            Triple("negative-encrypted-metadata-tamper.ubc", ErrorCode.ERR_CHUNK_AUTH, true),
            Triple("negative-missing-key.ubc", ErrorCode.ERR_MISSING_KEY, false),
            Triple("negative-encrypted-cap-missing-key.ubc", ErrorCode.ERR_MISSING_KEY, false),
        )
        for ((name, expected, suppliesKey) in negatives) {
            TestRunner.test("encrypted negative vector: $name") {
                val container = readVector("expected/$name")
                val options = if (suppliesKey) DecodeOptions().withKey(KEY) else DecodeOptions()
                assertThrowsUbc(expected, name) { Crypto.decodeEncrypted(container, options) }
            }
        }

        TestRunner.test("encrypted-empty wrong key returns ERR_ROOT_MISMATCH") {
            val container = readVector("expected/negative-encrypted-empty-wrong-key.ubc")
            val wrongKey = hex("ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            val options = DecodeOptions().withKey(wrongKey)
            assertThrowsUbc(ErrorCode.ERR_ROOT_MISMATCH) { Crypto.decodeEncrypted(container, options) }
        }

        TestRunner.test("root key matches shared known answer") {
            val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            val baseNonce = hex("f0e0d0c0b0a0908070605040")
            val expectedRootKey = hex("52c04b400d73df15d8a0db6ba58919f46fe822fff200fb50d8dee097af3c688c")
            assertEquals(expectedRootKey, Crypto.rootKeyForTesting(key, baseNonce))
        }
    }

    private fun decodeMatchesInput(container: String, input: String) {
        val options = DecodeOptions().withKey(KEY)
        val result = Crypto.decodeEncrypted(readVector(container), options)
        assertEquals(readVector(input), result.data, container)
    }
}
