package dev.ubc

import java.security.MessageDigest
import javax.crypto.Mac

/**
 * SPEC.md section 4's root_hash accumulator: plain SHA-256 over root_input for plain
 * containers, or a keyed HMAC-SHA-256 (HKDF-derived root_key) for encrypted containers.
 * Wraps the two so encoder/decoder code can update() without branching on mode.
 */
internal class RootAccumulator private constructor(
    private val digest: MessageDigest?,
    private val mac: Mac?,
) {
    companion object {
        fun plain(): RootAccumulator = RootAccumulator(CryptoInternal.sha256Digest(), null)

        fun keyed(rootKey: ByteArray): RootAccumulator = RootAccumulator(null, CryptoInternal.hmacSha256(rootKey))
    }

    fun update(data: ByteArray) {
        if (digest != null) digest.update(data) else mac!!.update(data)
    }

    fun finish(): ByteArray = if (digest != null) digest.digest() else mac!!.doFinal()
}
