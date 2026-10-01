package dev.ubc

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream

object StreamingTest {
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

    private class OneByteAtATimeStream(data: ByteArray) : InputStream() {
        private val delegate = ByteArrayInputStream(data)

        override fun read(): Int = delegate.read()

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            val single = delegate.read()
            if (single < 0) return -1
            b[off] = single.toByte()
            return 1
        }
    }

    fun register() {
        TestRunner.test("streamed plain output is byte-exact and fragmented decode round-trips") {
            val input = readVector("inputs/multi-3m.bin")
            val sink = ByteArrayOutputStream()
            Encoder(sink, emptyList(), EncodeOptions().withChunkSize(1L shl 20)).use { encoder ->
                encoder.write(input, 0, input.size / 3)
                encoder.write(input, input.size / 3, input.size - input.size / 3)
            }
            val streamed = sink.toByteArray()
            assertEquals(readVector("expected/plain-multi-3m.ubc"), streamed)

            val decoder = Decoder(OneByteAtATimeStream(streamed), null)
            val decoded = ByteArrayOutputStream()
            val buffer = ByteArray(1)
            var count: Int
            while (true) {
                count = decoder.read(buffer, 0, 1)
                if (count == -1) break
                decoded.write(buffer, 0, count)
            }
            assertEquals(input, decoded.toByteArray())
        }

        TestRunner.test("streamed encrypted output is byte-exact and authenticates before release") {
            val input = readVector("inputs/chunk-1m-plus-one.bin")
            val sink = ByteArrayOutputStream()
            val options = EncodeOptions(1L shl 20, KEY, BASE_NONCE)
            Encoder(sink, emptyList(), options).use { encoder ->
                encoder.write(input, 0, input.size)
            }
            assertEquals(readVector("expected/encrypted-chunk-1m-plus-one.ubc"), sink.toByteArray())

            val decoder = Decoder(ByteArrayInputStream(sink.toByteArray()), DecodeOptions().withKey(KEY))
            val decoded = ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            var count: Int
            while (true) {
                count = decoder.read(buffer, 0, buffer.size)
                if (count == -1) break
                decoded.write(buffer, 0, count)
            }
            assertEquals(input, decoded.toByteArray())
        }

        TestRunner.test("streamed plain decoder withholds output until root verifies") {
            val container = readVector("expected/plain-chunk-1m.ubc")
            container[container.size - 1] = (container[container.size - 1].toInt() xor 0x01).toByte()
            val decoder = Decoder(ByteArrayInputStream(container), null)
            val buffer = ByteArray(4096)
            assertThrowsUbc(ErrorCode.ERR_TRUNCATED) {
                while (decoder.read(buffer, 0, buffer.size) != -1) {
                    // drain
                }
            }
        }

        TestRunner.test("streamed plain decoder withholds output until trailing data is checked") {
            val container = readVector("expected/plain-chunk-1m.ubc")
            val withTrailingByte = container.copyOf(container.size + 1)
            val decoder = Decoder(ByteArrayInputStream(withTrailingByte), null)
            val buffer = ByteArray(4096)
            assertThrowsUbc(ErrorCode.ERR_TRAILING_DATA) {
                while (decoder.read(buffer, 0, buffer.size) != -1) {
                    // drain
                }
            }
        }

        TestRunner.test("truncated encrypted footer precedes final chunk authentication") {
            // Corrupt both the final chunk's GCM tag AND truncate the footer. SPEC.md
            // section 5 requires truncation (stage 4) to win over chunk-auth failure (stage 5).
            val container = readVector("expected/encrypted-one-byte.ubc")
            val footerStart = container.size - 36
            container[footerStart - 1] = (container[footerStart - 1].toInt() xor 0x01).toByte()
            val truncated = container.copyOf(container.size - 10)

            val decoder = Decoder(ByteArrayInputStream(truncated), DecodeOptions().withKey(KEY))
            val buffer = ByteArray(4096)
            assertThrowsUbc(ErrorCode.ERR_TRUNCATED) {
                while (decoder.read(buffer, 0, buffer.size) != -1) {
                    // drain
                }
            }
        }

        TestRunner.test("streamed encoder with large chunk size only buffers written input") {
            // A chunk_size far larger than the actual input must not cause the encoder to
            // allocate a chunk_size-sized buffer (the historical Rust OOM bug this guards against).
            val input = byteArrayOf(1, 2, 3)
            val sink = ByteArrayOutputStream()
            Encoder(sink, emptyList(), EncodeOptions().withChunkSize(1L shl 28)).use { encoder ->
                encoder.write(input, 0, input.size)
            }
            val result = Payload.decodePlain(sink.toByteArray(), null)
            assertEquals(input, result.data)
        }

        TestRunner.test("streamed decoder enforces caps before allocating chunk data") {
            val container = readVector("expected/plain-chunk-1m.ubc")
            val tight = DecodeOptions(16L shl 20, 4, 1L shl 20, 1L shl 30, null)
            val decoder = Decoder(ByteArrayInputStream(container), tight)
            val buffer = ByteArray(4096)
            assertThrowsUbc(ErrorCode.ERR_TRUNCATED) { decoder.read(buffer, 0, buffer.size) }
        }

        TestRunner.test("verify and inspect have their documented read scopes") {
            val container = readVector("expected/plain-metadata.ubc")
            val ok = Streaming.verify(ByteArrayInputStream(container), null)
            assertTrue(ok.ok)

            val corrupted = container.copyOf()
            corrupted[Header.SIZE + 4] = (corrupted[Header.SIZE + 4].toInt() xor 0x01).toByte()
            val bad = Streaming.verify(ByteArrayInputStream(corrupted), null)
            assertFalse(bad.ok)
            assertEquals(ErrorCode.ERR_ROOT_MISMATCH, bad.error)

            // inspect only reads header + metadata; it must not touch (or require) the
            // payload or footer at all, so a stream with the footer deliberately mangled
            // still works.
            val mangledFooter = container.copyOf()
            mangledFooter[mangledFooter.size - 1] = (mangledFooter[mangledFooter.size - 1].toInt() xor 0x01).toByte()
            val info = Streaming.inspect(ByteArrayInputStream(mangledFooter), null)
            assertTrue(info.hasMetadata)
            assertFalse(info.encrypted)
            assertEquals(4, info.metadata.size)
        }
    }
}
