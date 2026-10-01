package dev.ubc;

/**
 * Options for a streaming {@link Encoder}. {@code baseNonce} exists only for deterministic
 * conformance tests; production callers must leave it null so a CSPRNG nonce is generated.
 */
public final class EncodeOptions {
    public final long chunkSize;
    public final byte[] key;
    public final byte[] baseNonce;

    public EncodeOptions() {
        this(Payload.DEFAULT_CHUNK_SIZE, null, null);
    }

    public EncodeOptions(long chunkSize, byte[] key, byte[] baseNonce) {
        if (chunkSize <= 0 || chunkSize > 0xFFFF_FFFFL) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
        if (key != null && key.length != 32) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
        if (baseNonce != null && baseNonce.length != 12) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
        if (key == null && baseNonce != null) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
        this.chunkSize = chunkSize;
        this.key = key == null ? null : key.clone();
        this.baseNonce = baseNonce == null ? null : baseNonce.clone();
    }

    public EncodeOptions withKey(byte[] key) {
        return new EncodeOptions(chunkSize, key, baseNonce);
    }

    public EncodeOptions withChunkSize(long chunkSize) {
        return new EncodeOptions(chunkSize, key, baseNonce);
    }
}
