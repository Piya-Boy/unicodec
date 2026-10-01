package dev.ubc

/**
 * Options for a streaming Encoder. baseNonce exists only for deterministic conformance
 * tests; production callers must leave it null so a CSPRNG nonce is generated.
 */
class EncodeOptions(
    val chunkSize: Long = Payload.DEFAULT_CHUNK_SIZE,
    key: ByteArray? = null,
    baseNonce: ByteArray? = null,
) {
    val key: ByteArray? = key?.copyOf()
    val baseNonce: ByteArray? = baseNonce?.copyOf()

    init {
        if (chunkSize <= 0 || chunkSize > 0xFFFF_FFFFL) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
        if (key != null && key.size != 32) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
        if (baseNonce != null && baseNonce.size != 12) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
        if (key == null && baseNonce != null) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
    }

    fun withKey(key: ByteArray?): EncodeOptions = EncodeOptions(chunkSize, key, baseNonce)

    fun withChunkSize(chunkSize: Long): EncodeOptions = EncodeOptions(chunkSize, key, baseNonce)
}
