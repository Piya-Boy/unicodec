package dev.ubc

import java.io.File

object HeaderMetadataVectorsTest {
    private fun vectorRoot(): File = File(System.getProperty("user.dir"), "../../spec/vectors").canonicalFile

    private fun vector(name: String): ByteArray = File(vectorRoot(), "expected/$name").readBytes()

    fun register() {
        TestRunner.test("all positive vector headers round-trip byte-exactly") {
            val expectedDir = File(vectorRoot(), "expected")
            val files = expectedDir.listFiles { f -> f.name.endsWith(".ubc") } ?: emptyArray()
            assertTrue(files.isNotEmpty(), "vector directory must contain .ubc files")
            for (file in files) {
                val name = file.name
                if (name.startsWith("negative-")) continue
                val container = file.readBytes()
                val header = Header.parse(container, 0)
                val expectedHeader = container.copyOfRange(0, Header.SIZE)
                assertEquals(expectedHeader.toList(), header.toBytes().toList(), name)
            }
        }

        TestRunner.test("vector metadata round-trips byte-exactly") {
            val container = vector("plain-metadata.ubc")
            val header = Header.parse(container, 0)
            assertTrue(header.hasMetadata)

            val result = Metadata.parse(container, Header.SIZE, null)
            val reencoded = Metadata.encode(result.entries)
            val expected = container.copyOfRange(Header.SIZE, Header.SIZE + result.consumed)
            assertEquals(expected.toList(), reencoded.toList())
        }

        val headerNegatives = listOf(
            "negative-bad-magic.ubc" to ErrorCode.ERR_BAD_MAGIC,
            "negative-version-two.ubc" to ErrorCode.ERR_UNSUPPORTED_VER,
            "negative-hash-algo.ubc" to ErrorCode.ERR_UNSUPPORTED_ALGO,
            "negative-aead-algo.ubc" to ErrorCode.ERR_UNSUPPORTED_ALGO,
            "negative-reserved-flag.ubc" to ErrorCode.ERR_RESERVED_BITS,
            "negative-inconsistent-encryption.ubc" to ErrorCode.ERR_RESERVED_BITS,
            "negative-zero-chunk-size.ubc" to ErrorCode.ERR_RESERVED_BITS,
            "negative-encrypted-zero-chunk-size.ubc" to ErrorCode.ERR_RESERVED_BITS,
            "negative-encrypted-oversized-chunk-size.ubc" to ErrorCode.ERR_RESERVED_BITS,
        )
        for ((name, expected) in headerNegatives) {
            TestRunner.test("header negative vector: $name") {
                val container = vector(name)
                assertThrowsUbc(expected, name) { Header.parse(container, 0) }
            }
        }

        val metadataNegatives = listOf(
            "negative-meta-out-of-order.ubc",
            "negative-meta-duplicate.ubc",
            "negative-meta-overrun.ubc",
            "negative-empty-metadata.ubc",
            "negative-encrypted-reserved-metadata.ubc",
            "negative-reserved-metadata.ubc",
        )
        for (name in metadataNegatives) {
            TestRunner.test("metadata negative vector: $name") {
                val container = vector(name)
                assertThrowsUbc(ErrorCode.ERR_META_MALFORMED, name) { Metadata.parse(container, Header.SIZE, null) }
            }
        }

        TestRunner.test("metadata encoder sorts tags and rejects duplicates") {
            val entries = listOf(
                MetadataEntry(0x1000, byteArrayOf(1)),
                MetadataEntry(0x0001, "example.txt".toByteArray(Charsets.UTF_8)),
            )
            val encoded = Metadata.encode(entries)
            val result = Metadata.parse(encoded, 0, null)
            assertEquals(0x0001, result.entries[0].tag)
            assertEquals(0x1000, result.entries[1].tag)

            val duplicates = listOf(MetadataEntry(1, ByteArray(0)), MetadataEntry(1, ByteArray(0)))
            assertThrowsUbc(ErrorCode.ERR_META_MALFORMED) { Metadata.encode(duplicates) }
        }

        TestRunner.test("metadata length cap is checked before copying entries") {
            val oversized = byteArrayOf(0x01, 0x00, 0x00, 0x01) // declares a length larger than 16 MiB
            assertThrowsUbc(ErrorCode.ERR_META_MALFORMED) { Metadata.parse(oversized, 0, 16 shl 20) }

            val metadata = Metadata.encode(listOf(MetadataEntry(0x1000, byteArrayOf(1))))
            assertThrowsUbc(ErrorCode.ERR_META_MALFORMED) { Metadata.parse(metadata, 0, 6) }
        }
    }
}
