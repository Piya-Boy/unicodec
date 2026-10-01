package dev.ubc;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import javax.crypto.AEADBadTagException;

/** One-shot AES-256-GCM encrypted UBC v1 encoding and decoding (SPEC.md sections 3-4). */
public final class Crypto {
    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int FOOTER_SIZE = 36;
    private static final byte[] FOOTER_MAGIC = {'U', 'B', 'C', 'E'};

    private Crypto() {
    }

    /** Encodes with a CSPRNG-generated base_nonce. Production callers MUST use this. */
    public static byte[] encodeEncrypted(byte[] data, byte[] key, List<MetadataEntry> entries, long chunkSize) {
        byte[] baseNonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(baseNonce);
        return encodeEncryptedWithFixedNonce(data, key, baseNonce, entries, chunkSize);
    }

    /** Deterministic encoding for conformance vectors/tests only — never reuse a base_nonce in production. */
    public static byte[] encodeEncryptedWithFixedNonce(
            byte[] data, byte[] key, byte[] baseNonce, List<MetadataEntry> entries, long chunkSize) {
        validateEncodeKey(key);
        if (baseNonce == null || baseNonce.length != NONCE_SIZE) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
        if (chunkSize <= 0 || chunkSize > 0xFFFF_FFEFL) {
            throw new IllegalArgumentException("chunkSize must be a positive uint32 <= 0xffff_ffef when encrypted");
        }

        byte[] metadata = Metadata.encode(entries);
        long dataLength = data.length;
        long chunkCount = dataLength == 0 ? 0 : (dataLength + chunkSize - 1) / chunkSize;

        Header header = new Header(
                Header.FLAG_ENCRYPTED | (metadata.length > 0 ? Header.FLAG_HAS_METADATA : 0),
                Header.HASH_HMAC_SHA256,
                Header.AEAD_AES_256_GCM,
                chunkSize,
                chunkCount,
                data.length,
                baseNonce);
        byte[] headerBytes = header.toBytes();
        byte[] metadataDigest = CryptoInternal.sha256(metadata);

        RootAccumulator root = RootAccumulator.keyed(CryptoInternal.rootKey(key, baseNonce));
        root.update(headerBytes);
        root.update(metadata);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(headerBytes);
        output.writeBytes(metadata);

        long index = 0;
        for (long offset = 0; offset < dataLength; offset += chunkSize, index++) {
            int intOffset = (int) offset;
            int length = (int) Math.min(chunkSize, dataLength - offset);
            byte[] ciphertext = CryptoInternal.gcmEncrypt(key, CryptoInternal.chunkNonce(baseNonce, index), data,
                    intOffset, length, CryptoInternal.chunkAad(headerBytes, metadataDigest, index));
            ByteBuffer clen = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(ciphertext.length);
            output.writeBytes(clen.array());
            output.writeBytes(ciphertext);
            root.update(CryptoInternal.sha256(ciphertext));
        }

        output.writeBytes(root.finish());
        output.writeBytes(FOOTER_MAGIC);
        return output.toByteArray();
    }

    public static DecodeResult decodeEncrypted(byte[] container, DecodeOptions options) {
        DecodeOptions opts = options == null ? new DecodeOptions() : options;

        Header header = Header.parse(container, 0);
        byte[] headerBytes = Arrays.copyOfRange(container, 0, Header.SIZE);
        int offset = Header.SIZE;

        List<MetadataEntry> entries = List.of();
        byte[] metadataRegion = new byte[0];
        if (header.hasMetadata()) {
            Metadata.ParseResult result = Metadata.parse(container, offset, boundedIntCap(opts.maxMetaBytes));
            entries = result.entries;
            metadataRegion = Arrays.copyOfRange(container, offset, offset + result.consumed);
            offset += result.consumed;
        }

        if (!header.encrypted() || opts.key == null || opts.key.length != KEY_SIZE) {
            throw new UbcException(ErrorCode.ERR_MISSING_KEY);
        }
        if (Long.compareUnsigned(header.chunkCount, opts.maxChunkCount) > 0
                || Long.compareUnsigned(header.totalSize, opts.maxTotalSize) > 0) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }

        byte[] metadataDigest = CryptoInternal.sha256(metadataRegion);
        byte[] baseNonce = header.baseNonce();
        RootAccumulator root = RootAccumulator.keyed(CryptoInternal.rootKey(opts.key, baseNonce));
        root.update(headerBytes);
        root.update(metadataRegion);

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        long remaining = header.totalSize;
        long index = 0;
        for (long i = 0; Long.compareUnsigned(i, header.chunkCount) < 0; i++, index++) {
            if (container.length - offset < 4) {
                throw new UbcException(ErrorCode.ERR_TRUNCATED);
            }
            long chunkLength = Integer.toUnsignedLong(
                    ByteBuffer.wrap(container, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
            offset += 4;
            if (Long.compareUnsigned(chunkLength, opts.maxChunkLen) > 0
                    || chunkLength > container.length - offset) {
                throw new UbcException(ErrorCode.ERR_TRUNCATED);
            }
            int chunkLengthInt = (int) chunkLength;
            root.update(CryptoInternal.sha256Of(container, offset, chunkLengthInt));
            if (chunkLength < CryptoInternal.GCM_TAG_SIZE) {
                throw new UbcException(ErrorCode.ERR_CHUNK_AUTH);
            }
            byte[] plaintextChunk;
            try {
                plaintextChunk = CryptoInternal.gcmDecrypt(opts.key, CryptoInternal.chunkNonce(baseNonce, index),
                        container, offset, chunkLengthInt, CryptoInternal.chunkAad(headerBytes, metadataDigest, index));
            } catch (AEADBadTagException e) {
                throw new UbcException(ErrorCode.ERR_CHUNK_AUTH);
            }
            offset += chunkLengthInt;
            if (Long.compareUnsigned(plaintextChunk.length, remaining) > 0) {
                throw new UbcException(ErrorCode.ERR_ROOT_MISMATCH);
            }
            plaintext.write(plaintextChunk, 0, plaintextChunk.length);
            remaining -= plaintextChunk.length;
        }

        if (container.length - offset < FOOTER_SIZE) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }
        byte[] footerRoot = Arrays.copyOfRange(container, offset, offset + 32);
        byte[] footerMagic = Arrays.copyOfRange(container, offset + 32, offset + FOOTER_SIZE);
        if (!Arrays.equals(footerMagic, FOOTER_MAGIC)) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }
        byte[] plaintextBytes = plaintext.toByteArray();
        if (Integer.toUnsignedLong(plaintextBytes.length) != header.totalSize
                || !MessageDigest.isEqual(footerRoot, root.finish())) {
            throw new UbcException(ErrorCode.ERR_ROOT_MISMATCH);
        }
        if (container.length != offset + FOOTER_SIZE) {
            throw new UbcException(ErrorCode.ERR_TRAILING_DATA);
        }
        return new DecodeResult(plaintextBytes, entries);
    }

    /** Package-private: exposed only so conformance tests can check this against the shared known-answer fixture. */
    static byte[] rootKey(byte[] key, byte[] baseNonce) {
        return CryptoInternal.rootKey(key, baseNonce);
    }

    private static void validateEncodeKey(byte[] key) {
        if (key == null || key.length != KEY_SIZE) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
    }

    private static Integer boundedIntCap(long cap) {
        return cap > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) cap;
    }
}
