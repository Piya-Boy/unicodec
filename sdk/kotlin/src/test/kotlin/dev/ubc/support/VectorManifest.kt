package dev.ubc.support

import dev.ubc.Crypto
import dev.ubc.DecodeOptions
import dev.ubc.ErrorCode
import dev.ubc.Header
import dev.ubc.MetadataEntry
import dev.ubc.Payload
import dev.ubc.UbcException
import java.io.File

/** Reads spec/vectors/vectors.json and encodes/decodes vectors through the Kotlin SDK. */
class VectorManifest(val vectors: List<Vector>) {
    companion object {
        fun vectorsRoot(): File = File(System.getProperty("user.dir"), "../../spec/vectors").canonicalFile

        fun read(vectorsRoot: File): VectorManifest {
            val bytes = File(vectorsRoot, "vectors.json").readBytes()
            val root = MiniJson.asObject(MiniJson.parse(bytes))
            val rawVectors = MiniJson.asArray(root["vectors"])
            val vectors = rawVectors.map { Vector.from(MiniJson.asObject(it)) }
            return VectorManifest(vectors)
        }
    }

    /** The key shared by every encrypted positive vector, used to decode negative vectors that omit options. */
    fun canonicalKey(): ByteArray {
        for (vector in vectors) {
            if (vector.expectError == null && vector.options?.key != null) {
                return vector.options.key
            }
        }
        throw IllegalStateException("manifest has no encrypted positive vector")
    }

    fun find(id: String): Vector = vectors.firstOrNull { it.id == id } ?: throw IllegalStateException("manifest vector is missing: $id")
}

class Vector(
    val id: String,
    val input: String?,
    val options: VectorOptions?,
    val expected: String,
    val expectedSha256: ByteArray,
    val expectError: String?,
) {
    companion object {
        fun from(raw: Map<String, Any?>): Vector {
            val id = MiniJson.asString(raw["id"])
            val input = raw["input"]?.let { MiniJson.asString(it) }
            val options = raw["options"]?.let { VectorOptions.from(MiniJson.asObject(it)) }
            val expected = MiniJson.asString(raw["expected"])
            val expectedSha256 = hex(MiniJson.asString(raw["expectedSha256"]))
            val expectError = raw["expectError"]?.let { MiniJson.asString(it) }
            return Vector(id, input, options, expected, expectedSha256, expectError)
        }
    }

    /** Encodes this vector's input through the Kotlin SDK using its declared options. */
    fun encode(inputBytes: ByteArray): ByteArray {
        val opts = options ?: throw IllegalStateException("$id: positive vector has no options")
        return if (opts.key != null && opts.baseNonce != null) {
            Crypto.encodeEncryptedWithFixedNonce(inputBytes, opts.key, opts.baseNonce, opts.metadata, opts.chunkSize)
        } else if (opts.key == null && opts.baseNonce == null) {
            Payload.encodePlain(inputBytes, opts.metadata, opts.chunkSize)
        } else {
            throw IllegalStateException("$id: key and baseNonce must be paired")
        }
    }

    /**
     * Decodes a container, auto-detecting plain vs encrypted from the header itself
     * (mirrors Go's single DecodeBytes entry point). key is used only if the container
     * turns out to be encrypted.
     */
    fun decode(container: ByteArray, key: ByteArray?): DecodedVector {
        return try {
            val encrypted = Header.parse(container, 0).encrypted
            if (encrypted) {
                val result = Crypto.decodeEncrypted(container, DecodeOptions().withKey(key))
                DecodedVector(result.data, result.metadata, null)
            } else {
                val result = Payload.decodePlain(container, null)
                DecodedVector(result.data, result.metadata, null)
            }
        } catch (e: UbcException) {
            DecodedVector(null, null, e.code)
        }
    }
}

class VectorOptions(
    val chunkSize: Long,
    val key: ByteArray?,
    val baseNonce: ByteArray?,
    val metadata: List<MetadataEntry>,
) {
    companion object {
        fun from(raw: Map<String, Any?>): VectorOptions {
            val chunkSize = MiniJson.asNumber(raw["chunkSize"])
            val key = raw["key"]?.let { hex(MiniJson.asString(it)) }
            val baseNonce = raw["baseNonce"]?.let { hex(MiniJson.asString(it)) }
            val metadata = mutableListOf<MetadataEntry>()
            val rawMetadata = raw["metadata"]?.let { MiniJson.asArray(it) }
            if (rawMetadata != null) {
                for (rawEntry in rawMetadata) {
                    val entry = MiniJson.asObject(rawEntry)
                    val tagHex = MiniJson.asString(entry["tag"])
                    val tag = tagHex.substring(2).toInt(16)
                    val value = hex(MiniJson.asString(entry["valueHex"]))
                    metadata.add(MetadataEntry(tag, value))
                }
            }
            return VectorOptions(chunkSize, key, baseNonce, metadata)
        }
    }
}

class DecodedVector(val data: ByteArray?, val metadata: List<MetadataEntry>?, val error: ErrorCode?)

fun hex(value: String): ByteArray {
    val result = ByteArray(value.length / 2)
    for (i in value.indices step 2) {
        result[i / 2] = value.substring(i, i + 2).toInt(16).toByte()
    }
    return result
}
