package dev.ubc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/** UBC v1 fixed 40-byte header (SPEC.md section 2.1). */
public final class Header {
    public static final int SIZE = 40;
    public static final int VERSION = 1;

    public static final int HASH_SHA256 = 0;
    public static final int HASH_HMAC_SHA256 = 1;
    public static final int AEAD_NONE = 0;
    public static final int AEAD_AES_256_GCM = 1;

    public static final int FLAG_ENCRYPTED = 1;
    public static final int FLAG_HAS_METADATA = 1 << 1;

    private static final byte[] MAGIC = {'U', 'B', 'C', '1'};
    private static final int ALLOWED_FLAGS = FLAG_ENCRYPTED | FLAG_HAS_METADATA;
    private static final long MAX_ENCRYPTED_CHUNK_SIZE = 0xFFFF_FFEFL;
    private static final long UINT32_MAX = 0xFFFF_FFFFL;

    public final int flags;
    public final int hashAlgo;
    public final int aeadAlgo;
    public final long chunkSize;
    public final long chunkCount;
    public final long totalSize;
    private final byte[] baseNonce;

    public Header(int flags, int hashAlgo, int aeadAlgo, long chunkSize, long chunkCount,
            long totalSize, byte[] baseNonce) {
        this.flags = flags;
        this.hashAlgo = hashAlgo;
        this.aeadAlgo = aeadAlgo;
        this.chunkSize = chunkSize;
        this.chunkCount = chunkCount;
        this.totalSize = totalSize;
        this.baseNonce = baseNonce == null ? null : baseNonce.clone();
        validate();
    }

    /** Returns a defensive copy; mutating the result cannot affect this header's invariants. */
    public byte[] baseNonce() {
        return baseNonce.clone();
    }

    public boolean encrypted() {
        return (flags & FLAG_ENCRYPTED) != 0;
    }

    public boolean hasMetadata() {
        return (flags & FLAG_HAS_METADATA) != 0;
    }

    public byte[] toBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(SIZE).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(MAGIC);
        buffer.put((byte) VERSION);
        buffer.put((byte) flags);
        buffer.put((byte) hashAlgo);
        buffer.put((byte) aeadAlgo);
        buffer.putInt((int) chunkSize);
        buffer.putLong(chunkCount);
        buffer.putLong(totalSize);
        buffer.put(baseNonce);
        return buffer.array();
    }

    public static Header parse(byte[] data, int offset) {
        if (data.length - offset < SIZE) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (data[offset + i] != MAGIC[i]) {
                throw new UbcException(ErrorCode.ERR_BAD_MAGIC);
            }
        }
        ByteBuffer buffer = ByteBuffer.wrap(data, offset + 4, SIZE - 4).order(ByteOrder.LITTLE_ENDIAN);
        int version = Byte.toUnsignedInt(buffer.get());
        int flags = Byte.toUnsignedInt(buffer.get());
        int hashAlgo = Byte.toUnsignedInt(buffer.get());
        int aeadAlgo = Byte.toUnsignedInt(buffer.get());
        long chunkSize = Integer.toUnsignedLong(buffer.getInt());
        long chunkCount = buffer.getLong();
        long totalSize = buffer.getLong();
        byte[] baseNonce = new byte[12];
        buffer.get(baseNonce);

        if (version != VERSION) {
            throw new UbcException(ErrorCode.ERR_UNSUPPORTED_VER);
        }
        Header header = new Header(flags, hashAlgo, aeadAlgo, chunkSize, chunkCount, totalSize, baseNonce);
        return header;
    }

    private void validate() {
        if (hashAlgo != HASH_SHA256 && hashAlgo != HASH_HMAC_SHA256) {
            throw new UbcException(ErrorCode.ERR_UNSUPPORTED_ALGO);
        }
        if (aeadAlgo != AEAD_NONE && aeadAlgo != AEAD_AES_256_GCM) {
            throw new UbcException(ErrorCode.ERR_UNSUPPORTED_ALGO);
        }
        if ((flags & ~ALLOWED_FLAGS) != 0) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
        if (chunkSize < 0 || chunkSize > UINT32_MAX) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
        // chunkCount and totalSize are true uint64: every bit pattern (including a set sign
        // bit as a Java long) is a valid value per SPEC.md 2.1 and carries no reserved range.
        if (baseNonce == null || baseNonce.length != 12) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }

        if (encrypted()) {
            if (aeadAlgo != AEAD_AES_256_GCM || hashAlgo != HASH_HMAC_SHA256
                    || chunkSize == 0 || chunkSize > MAX_ENCRYPTED_CHUNK_SIZE) {
                throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
            }
            return;
        }
        byte[] zeroNonce = new byte[12];
        if (aeadAlgo != AEAD_NONE || hashAlgo != HASH_SHA256 || chunkSize == 0
                || !Arrays.equals(baseNonce, zeroNonce)) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
    }
}
