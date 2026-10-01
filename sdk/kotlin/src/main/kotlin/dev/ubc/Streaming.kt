package dev.ubc

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Factory, verify, and inspect entry points over Encoder/Decoder. */
object Streaming {
    private const val READ_BLOCK_SIZE = 32 shl 10

    fun newEncoder(sink: OutputStream, entries: List<MetadataEntry>, options: EncodeOptions? = null): Encoder =
        Encoder(sink, entries, options)

    fun newDecoder(source: InputStream, options: DecodeOptions? = null): Decoder = Decoder(source, options)

    /** Fully decodes and discards the plaintext, reporting whether the container is valid. */
    fun verify(source: InputStream, options: DecodeOptions? = null): VerifyReport {
        return try {
            val decoder = Decoder(source, options)
            val buffer = ByteArray(READ_BLOCK_SIZE)
            while (decoder.read(buffer, 0, buffer.size) != -1) {
                // discard; verification is in read()'s side effects (auth + root check)
            }
            VerifyReport(true, null)
        } catch (e: UbcException) {
            VerifyReport(false, e.code)
        } catch (e: java.io.IOException) {
            VerifyReport(false, ErrorCode.ERR_TRUNCATED)
        }
    }

    /** Reads only the header and metadata — never touches payload or footer. */
    fun inspect(source: InputStream, options: DecodeOptions? = null): ContainerInfo {
        val opts = options ?: DecodeOptions()
        val headerBytes = readExact(source, Header.SIZE)
        val header = Header.parse(headerBytes, 0)
        var entries: List<MetadataEntry> = emptyList()
        if (header.hasMetadata) {
            val prefix = readExact(source, 4)
            val metadataLength = ByteBuffer.wrap(prefix).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFF_FFFFL
            if (metadataLength == 0L || metadataLength > opts.maxMetaBytes) {
                throw UbcException(ErrorCode.ERR_META_MALFORMED)
            }
            val body = try {
                readExact(source, metadataLength.toInt())
            } catch (e: UbcException) {
                if (e.code == ErrorCode.ERR_TRUNCATED) throw UbcException(ErrorCode.ERR_META_MALFORMED) else throw e
            }
            val region = ByteArray(4 + body.size)
            System.arraycopy(prefix, 0, region, 0, 4)
            System.arraycopy(body, 0, region, 4, body.size)
            val result = Metadata.parse(region, 0, boundedCap(opts.maxMetaBytes))
            entries = result.entries
        }
        return ContainerInfo(
            version = Header.VERSION,
            encrypted = header.encrypted,
            hasMetadata = header.hasMetadata,
            hashAlgo = header.hashAlgo,
            aeadAlgo = header.aeadAlgo,
            chunkSize = header.chunkSize,
            chunkCount = header.chunkCount,
            totalSize = header.totalSize,
            metadata = entries,
        )
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
