package dev.ubc;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** One-shot AES-256-GCM encrypted UBC v1 encoding and decoding (SPEC.md sections 3-4). */
public final class Crypto {
    private static final int GCM_TAG_SIZE = 16;
    private static final int GCM_TAG_BITS = GCM_TAG_SIZE * 8;
    private static final byte[] ROOT_INFO = "UBC1 root authentication".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
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
        byte[] metadataDigest = sha256(metadata);

        Mac root = hmacSha256(rootKey(key, baseNonce));
        root.update(headerBytes);
        root.update(metadata);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(headerBytes);
        output.writeBytes(metadata);

        long index = 0;
        for (long offset = 0; offset < dataLength; offset += chunkSize, index++) {
            int intOffset = (int) offset;
            int length = (int) Math.min(chunkSize, dataLength - offset);
            byte[] ciphertext = gcmEncrypt(key, chunkNonce(baseNonce, index), data, intOffset, length,
                    chunkAad(headerBytes, metadataDigest, index));
            ByteBuffer clen = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(ciphertext.length);
            output.writeBytes(clen.array());
            output.writeBytes(ciphertext);
            root.update(sha256(ciphertext));
        }

        output.writeBytes(root.doFinal());
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

        byte[] metadataDigest = sha256(metadataRegion);
        byte[] baseNonce = header.baseNonce();
        Mac root = hmacSha256(rootKey(opts.key, baseNonce));
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
            root.update(sha256Of(container, offset, chunkLengthInt));
            if (chunkLength < GCM_TAG_SIZE) {
                throw new UbcException(ErrorCode.ERR_CHUNK_AUTH);
            }
            byte[] plaintextChunk;
            try {
                plaintextChunk = gcmDecrypt(opts.key, chunkNonce(baseNonce, index), container, offset, chunkLengthInt,
                        chunkAad(headerBytes, metadataDigest, index));
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
                || !MessageDigest.isEqual(footerRoot, root.doFinal())) {
            throw new UbcException(ErrorCode.ERR_ROOT_MISMATCH);
        }
        if (container.length != offset + FOOTER_SIZE) {
            throw new UbcException(ErrorCode.ERR_TRAILING_DATA);
        }
        return new DecodeResult(plaintextBytes, entries);
    }

    /** Package-private: exposed only so conformance tests can check this against the shared known-answer fixture. */
    static byte[] rootKey(byte[] key, byte[] baseNonce) {
        Mac prkMac = hmacSha256(baseNonce);
        byte[] prk = prkMac.doFinal(key);
        Mac rootMac = hmacSha256(prk);
        rootMac.update(ROOT_INFO);
        return rootMac.doFinal(new byte[] {0x01});
    }

    private static byte[] chunkNonce(byte[] baseNonce, long index) {
        byte[] indexBytes = le96(index);
        byte[] nonce = new byte[NONCE_SIZE];
        for (int i = 0; i < NONCE_SIZE; i++) {
            nonce[i] = (byte) (baseNonce[i] ^ indexBytes[i]);
        }
        return nonce;
    }

    private static byte[] le96(long index) {
        // index is a zero-based chunk counter; SPEC.md 3 defines le96(i) as i encoded as a
        // 12-byte little-endian integer. The high 4 bytes are always zero at this scale.
        byte[] result = new byte[NONCE_SIZE];
        ByteBuffer.wrap(result, 0, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(index);
        return result;
    }

    private static byte[] chunkAad(byte[] headerBytes, byte[] metadataDigest, long index) {
        ByteBuffer buffer = ByteBuffer.allocate(headerBytes.length + metadataDigest.length + 8)
                .order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(headerBytes);
        buffer.put(metadataDigest);
        buffer.putLong(index);
        return buffer.array();
    }

    private static byte[] gcmEncrypt(byte[] key, byte[] nonce, byte[] data, int offset, int length, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(data, offset, length);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-GCM must be available on every JDK", e);
        }
    }

    private static byte[] gcmDecrypt(byte[] key, byte[] nonce, byte[] data, int offset, int length, byte[] aad)
            throws AEADBadTagException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(data, offset, length);
        } catch (AEADBadTagException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-GCM must be available on every JDK", e);
        }
    }

    private static byte[] sha256(byte[] data) {
        return sha256Of(data, 0, data.length);
    }

    private static byte[] sha256Of(byte[] data, int offset, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(data, offset, length);
            return digest.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on every JDK", e);
        }
    }

    private static Mac hmacSha256(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 must be available on every JDK", e);
        }
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
