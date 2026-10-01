package dev.ubc

import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.AEADBadTagException

/**
 * A pull-based streaming UBC v1 decoder. Each encrypted chunk is authenticated (GCM tag
 * verified) before any of its plaintext is returned (SPEC.md section 3, verify-before-release).
 * Direct port of the Java SDK's Decoder, including the footer-preflight-before-final-chunk-
 * authentication fix a security review found there.
 */
class Decoder(private val source: InputStream, options: DecodeOptions? = null) : InputStream() {
    private companion object {
        const val FOOTER_SIZE = 36
        val FOOTER_MAGIC = byteArrayOf('U'.code.toByte(), 'B'.code.toByte(), 'C'.code.toByte(), 'E'.code.toByte())
    }

    private val options: DecodeOptions = options ?: DecodeOptions()
    private val header: Header
    private val headerBytes: ByteArray
    private val metadata: List<MetadataEntry>
    private val metadataDigest: ByteArray
    private val root: RootAccumulator
    private val baseNonce: ByteArray?

    private var chunkIndex = 0L
    private var plaintextSize = 0L
    private var pending: ByteArray? = null
    private var pendingOffset = 0
    private var prefetchedFooter: ByteArray? = null
    private var finished = false
    private var terminalError: UbcException? = null

    init {
        headerBytes = readExact(source, Header.SIZE)
        header = Header.parse(headerBytes, 0)

        var entries: List<MetadataEntry> = emptyList()
        var metadataRegion = ByteArray(0)
        if (header.hasMetadata) {
            metadataRegion = readMetadataRegion(source, this.options.maxMetaBytes)
            val result = Metadata.parse(metadataRegion, 0, boundedCap(this.options.maxMetaBytes))
            entries = result.entries
        }
        metadata = entries

        val key = this.options.key()
        if (header.encrypted && (key == null || key.size != 32)) {
            throw UbcException(ErrorCode.ERR_MISSING_KEY)
        }
        if (header.chunkCount > this.options.maxChunkCount || header.totalSize > this.options.maxTotalSize) {
            throw UbcException(ErrorCode.ERR_TRUNCATED)
        }

        metadataDigest = CryptoInternal.sha256(metadataRegion)
        baseNonce = if (header.encrypted) header.baseNonce() else null
        root = if (header.encrypted) {
            RootAccumulator.keyed(CryptoInternal.rootKey(key!!, baseNonce!!))
        } else {
            RootAccumulator.plain()
        }
        root.update(headerBytes)
        root.update(metadataRegion)
    }

    fun metadata(): List<MetadataEntry> = metadata

    override fun read(): Int {
        val single = ByteArray(1)
        val count = read(single, 0, 1)
        return if (count <= 0) -1 else single[0].toInt() and 0xFF
    }

    override fun read(data: ByteArray, offset: Int, length: Int): Int {
        terminalError?.let { throw it }
        if (length == 0) {
            return 0
        }
        try {
            while (pending == null && !finished) {
                loadNextChunk()
            }
        } catch (e: UbcException) {
            terminalError = e
            throw e
        }
        val currentPending = pending ?: return -1
        val available = currentPending.size - pendingOffset
        val toCopy = minOf(available, length)
        System.arraycopy(currentPending, pendingOffset, data, offset, toCopy)
        pendingOffset += toCopy
        if (pendingOffset == currentPending.size) {
            pending = null
            pendingOffset = 0
        }
        return toCopy
    }

    private fun loadNextChunk() {
        if (chunkIndex == header.chunkCount) {
            verifyFooter()
            return
        }
        val lengthValue = ByteBuffer.wrap(readExact(source, 4)).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFF_FFFFL
        if (lengthValue > options.maxChunkLen) {
            throw UbcException(ErrorCode.ERR_TRUNCATED)
        }
        val chunkLength = lengthValue.toInt()
        val body = readExact(source, chunkLength)
        root.update(CryptoInternal.sha256(body))

        val isLastChunk = chunkIndex + 1 == header.chunkCount
        if (header.encrypted && isLastChunk) {
            // Preflight the footer before authenticating the final chunk so a truncated
            // stream surfaces ERR_TRUNCATED rather than a misleading ERR_CHUNK_AUTH —
            // SPEC.md section 5's precedence requires truncation to win over chunk-auth
            // failure.
            prefetchedFooter = readExact(source, FOOTER_SIZE)
        }

        val plain: ByteArray
        if (header.encrypted) {
            if (body.size < CryptoInternal.GCM_TAG_SIZE) {
                throw UbcException(ErrorCode.ERR_CHUNK_AUTH)
            }
            plain = try {
                CryptoInternal.gcmDecrypt(
                    options.key()!!,
                    CryptoInternal.chunkNonce(baseNonce!!, chunkIndex),
                    body,
                    0,
                    body.size,
                    CryptoInternal.chunkAad(headerBytes, metadataDigest, chunkIndex),
                )
            } catch (e: AEADBadTagException) {
                throw UbcException(ErrorCode.ERR_CHUNK_AUTH)
            }
        } else {
            plain = body
        }

        if (plain.size.toLong() > header.totalSize - plaintextSize) {
            throw UbcException(ErrorCode.ERR_ROOT_MISMATCH)
        }
        plaintextSize += plain.size.toLong()
        chunkIndex++
        pending = if (plain.isEmpty()) null else plain
        pendingOffset = 0
    }

    private fun verifyFooter() {
        val footer = prefetchedFooter ?: readExact(source, FOOTER_SIZE)
        val footerRoot = footer.copyOfRange(0, 32)
        val footerMagic = footer.copyOfRange(32, FOOTER_SIZE)
        if (!footerMagic.contentEquals(FOOTER_MAGIC)) {
            throw UbcException(ErrorCode.ERR_TRUNCATED)
        }
        if (plaintextSize != header.totalSize || !MessageDigest.isEqual(footerRoot, root.finish())) {
            throw UbcException(ErrorCode.ERR_ROOT_MISMATCH)
        }
        if (source.read() != -1) {
            throw UbcException(ErrorCode.ERR_TRAILING_DATA)
        }
        finished = true
    }

    private fun readMetadataRegion(source: InputStream, maxMetaBytes: Long): ByteArray {
        val prefix = readExact(source, 4)
        val metadataLength = ByteBuffer.wrap(prefix).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFF_FFFFL
        if (metadataLength == 0L || metadataLength > maxMetaBytes) {
            throw UbcException(ErrorCode.ERR_META_MALFORMED)
        }
        val body = try {
            readExact(source, metadataLength.toInt())
        } catch (e: UbcException) {
            if (e.code == ErrorCode.ERR_TRUNCATED) {
                throw UbcException(ErrorCode.ERR_META_MALFORMED)
            }
            throw e
        }
        val region = ByteArray(4 + body.size)
        System.arraycopy(prefix, 0, region, 0, 4)
        System.arraycopy(body, 0, region, 4, body.size)
        return region
    }

    private fun readExact(source: InputStream, length: Int): ByteArray {
        val data = ByteArray(length)
        var total = 0
        while (total < length) {
            val count = try {
                source.read(data, total, length - total)
            } catch (e: java.io.IOException) {
                throw UbcException(ErrorCode.ERR_TRUNCATED)
            }
            if (count < 0) {
                throw UbcException(ErrorCode.ERR_TRUNCATED)
            }
            total += count
        }
        return data
    }

    private fun boundedCap(cap: Long): Int = if (cap > Int.MAX_VALUE) Int.MAX_VALUE else cap.toInt()
}
