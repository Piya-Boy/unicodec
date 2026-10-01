package dev.ubc

/** Resource limits applied while decoding untrusted containers. */
class DecodeOptions(
    val maxMetaBytes: Long = DEFAULT_MAX_META_BYTES,
    val maxChunkLen: Long = DEFAULT_MAX_CHUNK_LEN,
    val maxChunkCount: Long = DEFAULT_MAX_CHUNK_COUNT,
    val maxTotalSize: Long = DEFAULT_MAX_TOTAL_SIZE,
    key: ByteArray? = null,
) {
    private val keyBytes: ByteArray? = key?.copyOf()

    companion object {
        const val DEFAULT_MAX_META_BYTES = 16L shl 20
        const val DEFAULT_MAX_CHUNK_LEN = 64L shl 20
        const val DEFAULT_MAX_CHUNK_COUNT = 1L shl 20
        const val DEFAULT_MAX_TOTAL_SIZE = 1L shl 30
    }

    fun key(): ByteArray? = keyBytes?.copyOf()

    fun withKey(key: ByteArray?): DecodeOptions =
        DecodeOptions(maxMetaBytes, maxChunkLen, maxChunkCount, maxTotalSize, key)
}
