package dev.ubc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Shared AES-256-GCM / HMAC-SHA-256 primitives (SPEC.md sections 3-4), used by both the
 * one-shot {@link Crypto} path and the streaming {@link Encoder}/{@link Decoder}. Keeping a
 * single implementation here means the two paths cannot silently diverge on nonce, AAD, or
 * root-key derivation.
 */
final class CryptoInternal {
    static final int GCM_TAG_SIZE = 16;
    private static final int GCM_TAG_BITS = GCM_TAG_SIZE * 8;
    private static final byte[] ROOT_INFO =
            "UBC1 root authentication".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int NONCE_SIZE = 12;

    private CryptoInternal() {
    }

    static byte[] rootKey(byte[] key, byte[] baseNonce) {
        Mac prkMac = hmacSha256(baseNonce);
        byte[] prk = prkMac.doFinal(key);
        Mac rootMac = hmacSha256(prk);
        rootMac.update(ROOT_INFO);
        return rootMac.doFinal(new byte[] {0x01});
    }

    static byte[] chunkNonce(byte[] baseNonce, long index) {
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

    static byte[] chunkAad(byte[] headerBytes, byte[] metadataDigest, long index) {
        ByteBuffer buffer = ByteBuffer.allocate(headerBytes.length + metadataDigest.length + 8)
                .order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(headerBytes);
        buffer.put(metadataDigest);
        buffer.putLong(index);
        return buffer.array();
    }

    static byte[] gcmEncrypt(byte[] key, byte[] nonce, byte[] data, int offset, int length, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(data, offset, length);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-GCM must be available on every JDK", e);
        }
    }

    static byte[] gcmDecrypt(byte[] key, byte[] nonce, byte[] data, int offset, int length, byte[] aad)
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

    static byte[] sha256(byte[] data) {
        return sha256Of(data, 0, data.length);
    }

    static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on every JDK", e);
        }
    }

    static byte[] sha256Of(byte[] data, int offset, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(data, offset, length);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on every JDK", e);
        }
    }

    static Mac hmacSha256(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 must be available on every JDK", e);
        }
    }
}
