package dev.ubc;

import java.security.MessageDigest;
import javax.crypto.Mac;

/**
 * SPEC.md section 4's root_hash accumulator: plain SHA-256 over root_input for plain
 * containers, or a keyed HMAC-SHA-256 (HKDF-derived root_key) for encrypted containers.
 * Wraps the two so encoder/decoder code can update() without branching on mode.
 */
final class RootAccumulator {
    private final MessageDigest digest;
    private final Mac mac;

    private RootAccumulator(MessageDigest digest, Mac mac) {
        this.digest = digest;
        this.mac = mac;
    }

    static RootAccumulator plain() {
        return new RootAccumulator(CryptoInternal.sha256Digest(), null);
    }

    static RootAccumulator keyed(byte[] rootKey) {
        return new RootAccumulator(null, CryptoInternal.hmacSha256(rootKey));
    }

    void update(byte[] data) {
        if (digest != null) {
            digest.update(data);
        } else {
            mac.update(data);
        }
    }

    byte[] finish() {
        return digest != null ? digest.digest() : mac.doFinal();
    }
}
