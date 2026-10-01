package dev.ubc

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.AEADBadTagException

/** One-shot AES-256-GCM encrypted UBC v1 encoding and decoding (SPEC.md sections 3-4). */
object Crypto {
    private const val KEY_SIZE = 32
    private const val NONCE_SIZE = 12
    private const val FOOTER_SIZE = 36
    private val FOOTER_MAGIC = byteArrayOf('U'.code.toByte(), 'B'.code.toByte(), 'C'.code.toByte(), 'E'.code.toByte())

    /** Encodes with a CSPRNG-generated base_nonce. Production callers MUST use this. */
    fun encodeEncrypted(data: ByteArray, key: ByteArray, entries: List<MetadataEntry>, chunkSize: Long): ByteArray {
        val baseNonce = ByteArray(NONCE_SIZE)
        SecureRandom().nextBytes(baseNonce)
        return encodeEncryptedWithFixedNonce(data, key, baseNonce, entries, chunkSize)
    }

    /** Deterministic encoding for conformance vectors/tests only — never reuse a base_nonce in production. */
    fun encodeEncryptedWithFixedNonce(
        data: ByteArray,
        key: ByteArray,
        baseNonce: ByteArray,
        entries: List<MetadataEntry>,
        chunkSize: Long,
    ): ByteArray {
        validateEncodeKey(key)
        if (baseNonce.size != NONCE_SIZE) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
        if (chunkSize <= 0 || chunkSize > 0xFFFF_FFEFL) {
            throw IllegalArgumentException("chunkSize must be a positive uint32 <= 0xffff_ffef when encrypted")
        }

        val metadata = Metadata.encode(entries)
        val dataLength = data.size.toLong()
        val chunkCount = if (dataLength == 0L) 0L else (dataLength + chunkSize - 1) / chunkSize

        val header = Header(
            flags = Header.FLAG_ENCRYPTED or (if (metadata.isNotEmpty()) Header.FLAG_HAS_METADATA else 0),
            hashAlgo = Header.HASH_HMAC_SHA256,
            aeadAlgo = Header.AEAD_AES_256_GCM,
            chunkSize = chunkSize,
            chunkCount = chunkCount,
            totalSize = dataLength,
            baseNonce = baseNonce,
        )
        val headerBytes = header.toBytes()
        val metadataDigest = CryptoInternal.sha256(metadata)

        val root = RootAccumulator.keyed(CryptoInternal.rootKey(key, baseNonce))
        root.update(headerBytes)
        root.update(metadata)

        val output = ByteArrayOutputStream()
        output.writeBytes(headerBytes)
        output.writeBytes(metadata)

        var offset = 0L
        var index = 0L
        while (offset < dataLength) {
            val length = minOf(chunkSize, dataLength - offset).toInt()
            val intOffset = offset.toInt()
            val aad = CryptoInternal.chunkAad(headerBytes, metadataDigest, index)
            val ciphertext = CryptoInternal.gcmEncrypt(key, CryptoInternal.chunkNonce(baseNonce, index), data, intOffset, length, aad)
            val clen = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(ciphertext.size)
            output.writeBytes(clen.array())
            output.writeBytes(ciphertext)
            root.update(CryptoInternal.sha256(ciphertext))
            offset += chunkSize
            index++
        }

        output.writeBytes(root.finish())
        output.writeBytes(FOOTER_MAGIC)
        return output.toByteArray()
    }

    fun decodeEncrypted(container: ByteArray, options: DecodeOptions? = null): DecodeResult {
        val opts = options ?: DecodeOptions()

        val header = Header.parse(container, 0)
        val headerBytes = container.copyOfRange(0, Header.SIZE)
        var offset = Header.SIZE

        var entries: List<MetadataEntry> = emptyList()
        var metadataRegion = ByteArray(0)
        if (header.hasMetadata) {
            val result = Metadata.parse(container, offset, boundedCap(opts.maxMetaBytes))
            entries = result.entries
            metadataRegion = container.copyOfRange(offset, offset + result.consumed)
            offset += result.consumed
        }

        val key = opts.key()
        if (!header.encrypted || key == null || key.size != KEY_SIZE) {
            throw UbcException(ErrorCode.ERR_MISSING_KEY)
        }
        if (header.chunkCount > opts.maxChunkCount || header.totalSize > opts.maxTotalSize) {
            throw UbcException(ErrorCode.ERR_TRUNCATED)
        }

        val metadataDigest = CryptoInternal.sha256(metadataRegion)
        val baseNonce = header.baseNonce()
        val root = RootAccumulator.keyed(CryptoInternal.rootKey(key, baseNonce))
        root.update(headerBytes)
        root.update(metadataRegion)

        val plaintext = ByteArrayOutputStream()
        var remaining = header.totalSize
        var i = 0L
        var index = 0L
        while (i < header.chunkCount) {
            if (container.size - offset < 4) {
                throw UbcException(ErrorCode.ERR_TRUNCATED)
            }
            val chunkLength = ByteBuffer.wrap(container, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFF_FFFFL
            offset += 4
            if (chunkLength > opts.maxChunkLen || chunkLength > (container.size - offset)) {
                throw UbcException(ErrorCode.ERR_TRUNCATED)
            }
            val chunkLengthInt = chunkLength.toInt()
            root.update(CryptoInternal.sha256Of(container, offset, chunkLengthInt))
            if (chunkLength < CryptoInternal.GCM_TAG_SIZE) {
                throw UbcException(ErrorCode.ERR_CHUNK_AUTH)
            }
            val plaintextChunk = try {
                CryptoInternal.gcmDecrypt(
                    key,
                    CryptoInternal.chunkNonce(baseNonce, index),
                    container,
                    offset,
                    chunkLengthInt,
                    CryptoInternal.chunkAad(headerBytes, metadataDigest, index),
                )
            } catch (e: AEADBadTagException) {
                throw UbcException(ErrorCode.ERR_CHUNK_AUTH)
            }
            offset += chunkLengthInt
            if (plaintextChunk.size.toLong() > remaining) {
                throw UbcException(ErrorCode.ERR_ROOT_MISMATCH)
            }
            plaintext.writeBytes(plaintextChunk)
            remaining -= plaintextChunk.size.toLong()
            i++
            index++
        }

        if (container.size - offset < FOOTER_SIZE) {
            throw UbcException(ErrorCode.ERR_TRUNCATED)
        }
        val footerRoot = container.copyOfRange(offset, offset + 32)
        val footerMagic = container.copyOfRange(offset + 32, offset + FOOTER_SIZE)
        if (!footerMagic.contentEquals(FOOTER_MAGIC)) {
            throw UbcException(ErrorCode.ERR_TRUNCATED)
        }
        val plaintextBytes = plaintext.toByteArray()
        if (plaintextBytes.size.toLong() != header.totalSize || !MessageDigest.isEqual(footerRoot, root.finish())) {
            throw UbcException(ErrorCode.ERR_ROOT_MISMATCH)
        }
        if (container.size != offset + FOOTER_SIZE) {
            throw UbcException(ErrorCode.ERR_TRAILING_DATA)
        }
        return DecodeResult(plaintextBytes, entries)
    }

    /** Package-private: exposed only so conformance tests can check this against the shared known-answer fixture. */
    internal fun rootKeyForTesting(key: ByteArray, baseNonce: ByteArray): ByteArray = CryptoInternal.rootKey(key, baseNonce)

    private fun validateEncodeKey(key: ByteArray) {
        if (key.size != KEY_SIZE) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
    }

    private fun boundedCap(cap: Long): Int = if (cap > Int.MAX_VALUE) Int.MAX_VALUE else cap.toInt()
}
