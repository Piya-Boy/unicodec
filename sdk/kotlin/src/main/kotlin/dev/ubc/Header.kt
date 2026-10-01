package dev.ubc

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * UBC v1 fixed 40-byte header (SPEC.md section 2.1).
 *
 * chunk_count/total_size are true uint64: stored as Kotlin's `Long` (JVM signed 64-bit, same
 * as the Java port) with every bit pattern treated as structurally valid — never reject on
 * `< 0`, never compare with signed `<`/`>` near 2^63 without [java.lang.Long.compareUnsigned].
 */
class Header(
    val flags: Int,
    val hashAlgo: Int,
    val aeadAlgo: Int,
    val chunkSize: Long,
    val chunkCount: Long,
    val totalSize: Long,
    baseNonce: ByteArray,
) {
    private val baseNonceBytes: ByteArray = baseNonce.copyOf()

    init {
        validate()
    }

    companion object {
        const val SIZE = 40
        const val VERSION = 1

        const val HASH_SHA256 = 0
        const val HASH_HMAC_SHA256 = 1
        const val AEAD_NONE = 0
        const val AEAD_AES_256_GCM = 1

        const val FLAG_ENCRYPTED = 1
        const val FLAG_HAS_METADATA = 1 shl 1

        private const val ALLOWED_FLAGS = FLAG_ENCRYPTED or FLAG_HAS_METADATA
        private const val MAX_ENCRYPTED_CHUNK_SIZE = 0xFFFF_FFEFL
        private const val UINT32_MAX = 0xFFFF_FFFFL
        private val MAGIC = byteArrayOf('U'.code.toByte(), 'B'.code.toByte(), 'C'.code.toByte(), '1'.code.toByte())

        fun parse(data: ByteArray, offset: Int = 0): Header {
            if (data.size - offset < SIZE) {
                throw UbcException(ErrorCode.ERR_TRUNCATED)
            }
            for (i in 0 until 4) {
                if (data[offset + i] != MAGIC[i]) {
                    throw UbcException(ErrorCode.ERR_BAD_MAGIC)
                }
            }
            val buffer = ByteBuffer.wrap(data, offset + 4, SIZE - 4).order(ByteOrder.LITTLE_ENDIAN)
            val version = buffer.get().toInt() and 0xFF
            val flags = buffer.get().toInt() and 0xFF
            val hashAlgo = buffer.get().toInt() and 0xFF
            val aeadAlgo = buffer.get().toInt() and 0xFF
            val chunkSize = buffer.int.toLong() and 0xFFFF_FFFFL
            val chunkCount = buffer.long
            val totalSize = buffer.long
            val baseNonce = ByteArray(12)
            buffer.get(baseNonce)

            if (version != VERSION) {
                throw UbcException(ErrorCode.ERR_UNSUPPORTED_VER)
            }
            return Header(flags, hashAlgo, aeadAlgo, chunkSize, chunkCount, totalSize, baseNonce)
        }
    }

    val encrypted: Boolean get() = (flags and FLAG_ENCRYPTED) != 0
    val hasMetadata: Boolean get() = (flags and FLAG_HAS_METADATA) != 0

    /** A defensive copy; mutating the result cannot affect this header's invariants. */
    fun baseNonce(): ByteArray = baseNonceBytes.copyOf()

    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(SIZE).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(MAGIC)
        buffer.put(VERSION.toByte())
        buffer.put(flags.toByte())
        buffer.put(hashAlgo.toByte())
        buffer.put(aeadAlgo.toByte())
        buffer.putInt(chunkSize.toInt())
        buffer.putLong(chunkCount)
        buffer.putLong(totalSize)
        buffer.put(baseNonceBytes)
        return buffer.array()
    }

    private fun validate() {
        if (hashAlgo != HASH_SHA256 && hashAlgo != HASH_HMAC_SHA256) {
            throw UbcException(ErrorCode.ERR_UNSUPPORTED_ALGO)
        }
        if (aeadAlgo != AEAD_NONE && aeadAlgo != AEAD_AES_256_GCM) {
            throw UbcException(ErrorCode.ERR_UNSUPPORTED_ALGO)
        }
        if ((flags and ALLOWED_FLAGS.inv()) != 0) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
        if (chunkSize < 0 || chunkSize > UINT32_MAX) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
        if (baseNonceBytes.size != 12) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }

        if (encrypted) {
            if (aeadAlgo != AEAD_AES_256_GCM || hashAlgo != HASH_HMAC_SHA256 ||
                chunkSize == 0L || chunkSize > MAX_ENCRYPTED_CHUNK_SIZE
            ) {
                throw UbcException(ErrorCode.ERR_RESERVED_BITS)
            }
            return
        }
        val zeroNonce = ByteArray(12)
        if (aeadAlgo != AEAD_NONE || hashAlgo != HASH_SHA256 || chunkSize == 0L || !baseNonceBytes.contentEquals(zeroNonce)) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
    }
}
