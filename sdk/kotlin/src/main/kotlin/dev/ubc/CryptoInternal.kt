package dev.ubc

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Shared AES-256-GCM / HMAC-SHA-256 primitives (SPEC.md sections 3-4), used by both the
 * one-shot and streaming encrypted paths. Keeping a single implementation here means the
 * two paths cannot silently diverge on nonce, AAD, or root-key derivation. Direct port of
 * the Java SDK's CryptoInternal via JVM interop (same stdlib primitives, same guarantees).
 */
internal object CryptoInternal {
    const val GCM_TAG_SIZE = 16
    private const val GCM_TAG_BITS = GCM_TAG_SIZE * 8
    private val ROOT_INFO = "UBC1 root authentication".toByteArray(StandardCharsets.US_ASCII)
    private const val NONCE_SIZE = 12

    fun rootKey(key: ByteArray, baseNonce: ByteArray): ByteArray {
        val prkMac = hmacSha256(baseNonce)
        val prk = prkMac.doFinal(key)
        val rootMac = hmacSha256(prk)
        rootMac.update(ROOT_INFO)
        return rootMac.doFinal(byteArrayOf(0x01))
    }

    fun chunkNonce(baseNonce: ByteArray, index: Long): ByteArray {
        val indexBytes = le96(index)
        val nonce = ByteArray(NONCE_SIZE)
        for (i in 0 until NONCE_SIZE) {
            nonce[i] = (baseNonce[i].toInt() xor indexBytes[i].toInt()).toByte()
        }
        return nonce
    }

    private fun le96(index: Long): ByteArray {
        val result = ByteArray(NONCE_SIZE)
        ByteBuffer.wrap(result, 0, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(index)
        return result
    }

    fun chunkAad(headerBytes: ByteArray, metadataDigest: ByteArray, index: Long): ByteArray {
        val buffer = ByteBuffer.allocate(headerBytes.size + metadataDigest.size + 8).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(headerBytes)
        buffer.put(metadataDigest)
        buffer.putLong(index)
        return buffer.array()
    }

    fun gcmEncrypt(key: ByteArray, nonce: ByteArray, data: ByteArray, offset: Int, length: Int, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(data, offset, length)
    }

    @Throws(AEADBadTagException::class)
    fun gcmDecrypt(key: ByteArray, nonce: ByteArray, data: ByteArray, offset: Int, length: Int, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(data, offset, length)
    }

    fun sha256(data: ByteArray): ByteArray = sha256Of(data, 0, data.size)

    fun sha256Of(data: ByteArray, offset: Int, length: Int): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(data, offset, length)
        return digest.digest()
    }

    fun sha256Digest(): MessageDigest = MessageDigest.getInstance("SHA-256")

    fun hmacSha256(key: ByteArray): Mac {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac
    }
}
