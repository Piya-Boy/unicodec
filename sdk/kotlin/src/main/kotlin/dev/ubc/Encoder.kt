package dev.ubc

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.util.Arrays

/**
 * A write-then-close streaming UBC v1 encoder. Plaintext is spooled to a temp file until its
 * final size is known, because the v1 header precedes the payload and carries both size and
 * chunk count (SPEC.md section 2.1). Direct port of the Java SDK's Encoder, including its
 * owner-only-temp-file-permissions fix and deleteOnExit() safety net from a security review.
 */
class Encoder(sink: java.io.OutputStream, entries: List<MetadataEntry>, options: EncodeOptions? = null) :
    java.io.OutputStream() {
    private val sink: java.io.OutputStream = sink
    private val metadata: ByteArray = Metadata.encode(entries)
    private val options: EncodeOptions = options ?: EncodeOptions()
    private var spoolFile: File
    private var spool: RandomAccessFile
    private var totalSize: Long = 0
    private var finished = false
    private var closed = false

    init {
        spoolFile = createOwnerOnlyTempFile()
        spool = RandomAccessFile(spoolFile, "rw")
        spoolFile.deleteOnExit()
    }

    private fun createOwnerOnlyTempFile(): File {
        return try {
            val path = Files.createTempFile(
                "ubc-encoder-",
                ".spool",
                PosixFilePermissions.asFileAttribute(
                    setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                ),
            )
            path.toFile()
        } catch (notPosix: UnsupportedOperationException) {
            File.createTempFile("ubc-encoder-", ".spool")
        }
    }

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    override fun write(data: ByteArray, offset: Int, length: Int) {
        if (finished) {
            throw IllegalStateException("encoder is already finished")
        }
        spool.write(data, offset, length)
        totalSize += length
    }

    override fun close() {
        if (closed) {
            return
        }
        closed = true
        try {
            if (!finished) {
                finish()
            }
        } finally {
            purgeSpool()
        }
    }

    private fun finish() {
        finished = true
        val chunkSize = options.chunkSize
        val encrypted = options.key != null
        if (encrypted && chunkSize > 0xFFFF_FFEFL) {
            throw UbcException(ErrorCode.ERR_RESERVED_BITS)
        }
        val chunkCount = if (totalSize == 0L) 0L else (totalSize + chunkSize - 1) / chunkSize
        val baseNonce: ByteArray = if (encrypted) {
            options.baseNonce ?: ByteArray(12).also { SecureRandom().nextBytes(it) }
        } else {
            ByteArray(12)
        }

        val header = Header(
            flags = (if (encrypted) Header.FLAG_ENCRYPTED else 0) or (if (metadata.isNotEmpty()) Header.FLAG_HAS_METADATA else 0),
            hashAlgo = if (encrypted) Header.HASH_HMAC_SHA256 else Header.HASH_SHA256,
            aeadAlgo = if (encrypted) Header.AEAD_AES_256_GCM else Header.AEAD_NONE,
            chunkSize = chunkSize,
            chunkCount = chunkCount,
            totalSize = totalSize,
            baseNonce = baseNonce,
        )
        val headerBytes = header.toBytes()
        sink.write(headerBytes)
        sink.write(metadata)

        val metadataDigest = CryptoInternal.sha256(metadata)
        val root = if (encrypted) {
            RootAccumulator.keyed(CryptoInternal.rootKey(options.key!!, baseNonce))
        } else {
            RootAccumulator.plain()
        }
        root.update(headerBytes)
        root.update(metadata)

        spool.seek(0)
        val bufferLength = minOf(totalSize, chunkSize).toInt()
        val buffer = ByteArray(bufferLength)
        var index = 0L
        var written = 0L
        while (written < totalSize) {
            val length = minOf(chunkSize, totalSize - written).toInt()
            spool.readFully(buffer, 0, length)
            val body: ByteArray = if (encrypted) {
                val aad = CryptoInternal.chunkAad(headerBytes, metadataDigest, index)
                CryptoInternal.gcmEncrypt(options.key!!, CryptoInternal.chunkNonce(baseNonce, index), buffer, 0, length, aad)
            } else {
                Arrays.copyOf(buffer, length)
            }
            val clen = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(body.size)
            sink.write(clen.array())
            sink.write(body)
            root.update(CryptoInternal.sha256(body))
            written += chunkSize
            index++
        }

        sink.write(root.finish())
        sink.write(byteArrayOf('U'.code.toByte(), 'B'.code.toByte(), 'C'.code.toByte(), 'E'.code.toByte()))
    }

    private fun purgeSpool() {
        try {
            spool.close()
        } catch (ignored: java.io.IOException) {
            // best-effort close; the file delete below still runs
        }
        try {
            Files.deleteIfExists(spoolFile.toPath())
        } catch (ignored: java.io.IOException) {
            spoolFile.deleteOnExit()
        }
    }
}
