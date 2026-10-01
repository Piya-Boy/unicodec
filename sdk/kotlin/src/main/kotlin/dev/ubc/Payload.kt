package dev.ubc

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** One-shot plain (non-encrypted) UBC v1 encoding and decoding (SPEC.md sections 2-4). */
object Payload {
    const val DEFAULT_CHUNK_SIZE = 1L shl 20
    private const val FOOTER_SIZE = 36
    private val FOOTER_MAGIC = byteArrayOf('U'.code.toByte(), 'B'.code.toByte(), 'C'.code.toByte(), 'E'.code.toByte())

    fun encodePlain(data: ByteArray, entries: List<MetadataEntry>, chunkSize: Long): ByteArray {
        if (chunkSize <= 0 || chunkSize > 0xFFFF_FFFFL) {
            throw IllegalArgumentException("chunkSize must be a positive uint32")
        }
        val metadata = Metadata.encode(entries)
        val dataLength = data.size.toLong()
        val chunkCount = if (dataLength == 0L) 0L else (dataLength + chunkSize - 1) / chunkSize

        val header = Header(
            flags = if (metadata.isNotEmpty()) Header.FLAG_HAS_METADATA else 0,
            hashAlgo = Header.HASH_SHA256,
            aeadAlgo = Header.AEAD_NONE,
            chunkSize = chunkSize,
            chunkCount = chunkCount,
            totalSize = dataLength,
            baseNonce = ByteArray(12),
        )
        val headerBytes = header.toBytes()

        val output = ByteArrayOutputStream()
        output.writeBytes(headerBytes)
        output.writeBytes(metadata)

        val root = sha256()
        root.update(headerBytes)
        root.update(metadata)

        var offset = 0L
        while (offset < dataLength) {
            val length = minOf(chunkSize, dataLength - offset).toInt()
            val intOffset = offset.toInt()
            val chunk = data.copyOfRange(intOffset, intOffset + length)
            val clen = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(length)
            output.writeBytes(clen.array())
            output.writeBytes(chunk)
            root.update(sha256Of(chunk))
            offset += chunkSize
        }

        output.writeBytes(root.digest())
        output.writeBytes(FOOTER_MAGIC)
        return output.toByteArray()
    }

    fun decodePlain(container: ByteArray, options: DecodeOptions? = null): DecodeResult {
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

        if (header.encrypted) {
            throw UbcException(ErrorCode.ERR_MISSING_KEY)
        }
        if (header.chunkCount > opts.maxChunkCount || header.totalSize > opts.maxTotalSize) {
            throw UbcException(ErrorCode.ERR_TRUNCATED)
        }

        val root = sha256()
        root.update(headerBytes)
        root.update(metadataRegion)

        val plaintext = ByteArrayOutputStream()
        var remaining = header.totalSize
        var i = 0L
        while (i < header.chunkCount) {
            if (container.size - offset < 4) {
                throw UbcException(ErrorCode.ERR_TRUNCATED)
            }
            val chunkLength = ByteBuffer.wrap(container, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFF_FFFFL
            offset += 4
            if (chunkLength > opts.maxChunkLen || chunkLength > (container.size - offset)) {
                throw UbcException(ErrorCode.ERR_TRUNCATED)
            }
            if (chunkLength > remaining) {
                throw UbcException(ErrorCode.ERR_ROOT_MISMATCH)
            }
            val chunkLengthInt = chunkLength.toInt()
            val chunk = container.copyOfRange(offset, offset + chunkLengthInt)
            root.update(sha256Of(chunk))
            plaintext.writeBytes(chunk)
            offset += chunkLengthInt
            remaining -= chunkLength
            i++
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
        if (plaintextBytes.size.toLong() != header.totalSize || !MessageDigest.isEqual(footerRoot, root.digest())) {
            throw UbcException(ErrorCode.ERR_ROOT_MISMATCH)
        }
        if (container.size != offset + FOOTER_SIZE) {
            throw UbcException(ErrorCode.ERR_TRAILING_DATA)
        }
        return DecodeResult(plaintextBytes, entries)
    }

    private fun sha256(): MessageDigest = MessageDigest.getInstance("SHA-256")

    private fun sha256Of(data: ByteArray): ByteArray = sha256().digest(data)

    private fun boundedCap(cap: Long): Int = if (cap > Int.MAX_VALUE) Int.MAX_VALUE else cap.toInt()
}
