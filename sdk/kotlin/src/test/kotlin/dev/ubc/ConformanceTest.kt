package dev.ubc

import dev.ubc.support.VectorManifest
import java.security.MessageDigest

/** Drives every vector in spec/vectors/vectors.json through the Kotlin SDK — the manifest is the contract. */
object ConformanceTest {
    fun register() {
        TestRunner.test("every shared manifest vector conforms") {
            val root = VectorManifest.vectorsRoot()
            val manifest = VectorManifest.read(root)
            val canonicalKey = manifest.canonicalKey()
            var positiveCount = 0
            var negativeCount = 0
            val sha256 = MessageDigest.getInstance("SHA-256")

            for (vector in manifest.vectors) {
                val expected = java.io.File(root, vector.expected).readBytes()
                sha256.reset()
                assertEquals(vector.expectedSha256, sha256.digest(expected), "${vector.id}: expected artifact SHA-256 differs from vectors.json")

                if (vector.expectError != null) {
                    negativeCount++
                    val vectorKey = vector.options?.key
                    val decodeKey = if (requiresKey(vector.id)) (vectorKey ?: canonicalKey) else null
                    val decoded = vector.decode(expected, decodeKey)
                    assertTrue(decoded.error != null, "${vector.id}: negative vector must not decode successfully")
                    assertEquals(vector.expectError, decoded.error!!.stableId, "${vector.id}: stable error id differs")
                    continue
                }

                positiveCount++
                val input = java.io.File(root, vector.input!!).readBytes()
                val encoded = vector.encode(input)
                assertEquals(expected, encoded, "${vector.id}: encoded container differs from vectors.json artifact")

                val decoded = vector.decode(expected, vector.options!!.key)
                assertTrue(decoded.error == null, "${vector.id}: decode failed with ${decoded.error}")
                assertEquals(input, decoded.data, "${vector.id}: decoded plaintext differs")
                val expectedMetadata = vector.options.metadata
                assertEquals(expectedMetadata.size, decoded.metadata!!.size, "${vector.id}: decoded metadata count differs")
                for (i in expectedMetadata.indices) {
                    assertEquals(expectedMetadata[i].tag, decoded.metadata[i].tag, "${vector.id}: metadata tag $i")
                    assertEquals(expectedMetadata[i].value, decoded.metadata[i].value, "${vector.id}: metadata value $i")
                }
            }

            assertTrue(positiveCount > 0, "manifest must contain positive vectors")
            assertTrue(negativeCount > 0, "manifest must contain negative vectors")
        }
    }

    // Negative vectors whose own point is "decoded without a key" must actually be decoded
    // without one; every other negative vector decodes with the canonical/vector-supplied
    // key so a missing-key short-circuit doesn't mask the error the vector is meant to exercise.
    private fun requiresKey(id: String): Boolean = id != "negative-missing-key" && id != "negative-encrypted-cap-missing-key"
}
