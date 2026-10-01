package dev.ubc;

/** Resource limits applied while decoding untrusted containers. */
public final class DecodeOptions {
    public static final long DEFAULT_MAX_META_BYTES = 16L << 20;
    public static final long DEFAULT_MAX_CHUNK_LEN = 64L << 20;
    public static final long DEFAULT_MAX_CHUNK_COUNT = 1L << 20;
    public static final long DEFAULT_MAX_TOTAL_SIZE = 1L << 30;

    public final long maxMetaBytes;
    public final long maxChunkLen;
    public final long maxChunkCount;
    public final long maxTotalSize;
    public final byte[] key;

    public DecodeOptions() {
        this(DEFAULT_MAX_META_BYTES, DEFAULT_MAX_CHUNK_LEN, DEFAULT_MAX_CHUNK_COUNT, DEFAULT_MAX_TOTAL_SIZE, null);
    }

    public DecodeOptions(long maxMetaBytes, long maxChunkLen, long maxChunkCount, long maxTotalSize, byte[] key) {
        if (maxMetaBytes < 0 || maxChunkLen < 0 || maxChunkCount < 0 || maxTotalSize < 0) {
            throw new IllegalArgumentException("decode limits must be non-negative");
        }
        this.maxMetaBytes = maxMetaBytes;
        this.maxChunkLen = maxChunkLen;
        this.maxChunkCount = maxChunkCount;
        this.maxTotalSize = maxTotalSize;
        this.key = key == null ? null : key.clone();
    }

    public DecodeOptions withKey(byte[] key) {
        return new DecodeOptions(maxMetaBytes, maxChunkLen, maxChunkCount, maxTotalSize, key);
    }

    public byte[] key() {
        return key == null ? null : key.clone();
    }
}
