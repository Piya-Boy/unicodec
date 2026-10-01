package dev.ubc

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** UBC metadata TLV block encoding and parsing (SPEC.md section 2.2). */
object Metadata {
    const val TAG_FILENAME = 0x0001
    const val TAG_MIME_TYPE = 0x0002
    const val TAG_CREATED_AT = 0x0003

    /** Result of [parse]: the decoded entries and total bytes consumed from the input. */
    class ParseResult(val entries: List<MetadataEntry>, val consumed: Int)

    fun encode(entries: List<MetadataEntry>): ByteArray {
        val ordered = entries.sortedBy { it.tag.toLong() and 0xFFFFL }
        if (ordered.isEmpty()) {
            return ByteArray(0)
        }

        val body = ByteArrayOutputStream()
        var previousTag = -1
        var havePrevious = false
        for (entry in ordered) {
            validateEntry(entry)
            if (havePrevious && previousTag == entry.tag) {
                throw UbcException(ErrorCode.ERR_META_MALFORMED)
            }
            previousTag = entry.tag
            havePrevious = true
            if (entry.value.size.toLong() and 0xFFFFFFFFL > 0xFFFF_FFFFL ||
                body.size().toLong() + 6 + entry.value.size > 0xFFFF_FFFFL
            ) {
                throw UbcException(ErrorCode.ERR_META_MALFORMED)
            }
            val entryHeader = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
            entryHeader.putShort(entry.tag.toShort())
            entryHeader.putInt(entry.value.size)
            body.writeBytes(entryHeader.array())
            body.writeBytes(entry.value)
        }
        val bodyBytes = body.toByteArray()
        val result = ByteBuffer.allocate(4 + bodyBytes.size).order(ByteOrder.LITTLE_ENDIAN)
        result.putInt(bodyBytes.size)
        result.put(bodyBytes)
        return result.array()
    }

    fun parse(data: ByteArray, offset: Int = 0, maxBytes: Int? = null): ParseResult {
        if (data.size - offset < 4) {
            throw UbcException(ErrorCode.ERR_META_MALFORMED)
        }
        val lengthBuffer = ByteBuffer.wrap(data, offset, 4).order(ByteOrder.LITTLE_ENDIAN)
        val metadataLength = lengthBuffer.int.toLong() and 0xFFFF_FFFFL
        val available = data.size - offset - 4L
        if (metadataLength == 0L ||
            (maxBytes != null && metadataLength > (maxBytes.toLong() and 0xFFFF_FFFFL)) ||
            metadataLength > available
        ) {
            throw UbcException(ErrorCode.ERR_META_MALFORMED)
        }

        val end = offset + 4 + metadataLength.toInt()
        val entries = mutableListOf<MetadataEntry>()
        var cursor = offset + 4
        var previousTag = -1
        var havePrevious = false
        while (cursor < end) {
            if (end - cursor < 6) {
                throw UbcException(ErrorCode.ERR_META_MALFORMED)
            }
            val entryHeader = ByteBuffer.wrap(data, cursor, 6).order(ByteOrder.LITTLE_ENDIAN)
            val tag = entryHeader.short.toInt() and 0xFFFF
            val valueLength = entryHeader.int.toLong() and 0xFFFF_FFFFL
            cursor += 6
            if (valueLength > (end - cursor).toLong() || (havePrevious && tag <= previousTag)) {
                throw UbcException(ErrorCode.ERR_META_MALFORMED)
            }
            val value = data.copyOfRange(cursor, cursor + valueLength.toInt())
            val entry = MetadataEntry(tag, value)
            validateEntry(entry)
            entries.add(entry)
            previousTag = tag
            havePrevious = true
            cursor += valueLength.toInt()
        }
        return ParseResult(entries, end - offset)
    }

    private fun validateEntry(entry: MetadataEntry) {
        if (entry.tag < 0 || entry.tag > 0xFFFF) {
            throw UbcException(ErrorCode.ERR_META_MALFORMED)
        }
        when (entry.tag) {
            TAG_FILENAME -> {
                if (startsWithBom(entry.value) || containsNul(entry.value)) {
                    throw UbcException(ErrorCode.ERR_META_MALFORMED)
                }
                if (!isValidUtf8(entry.value)) {
                    throw UbcException(ErrorCode.ERR_META_MALFORMED)
                }
            }
            TAG_MIME_TYPE -> {
                for (b in entry.value) {
                    val unsigned = b.toInt() and 0xFF
                    if (unsigned == 0 || unsigned > 0x7F) {
                        throw UbcException(ErrorCode.ERR_META_MALFORMED)
                    }
                }
            }
            TAG_CREATED_AT -> {
                if (entry.value.size != 8) {
                    throw UbcException(ErrorCode.ERR_META_MALFORMED)
                }
            }
        }
    }

    private fun startsWithBom(value: ByteArray): Boolean =
        value.size >= 3 &&
            (value[0].toInt() and 0xFF) == 0xEF &&
            (value[1].toInt() and 0xFF) == 0xBB &&
            (value[2].toInt() and 0xFF) == 0xBF

    private fun containsNul(value: ByteArray): Boolean = value.any { it == 0.toByte() }

    private fun isValidUtf8(value: ByteArray): Boolean {
        val decoder = StandardCharsets.UTF_8.newDecoder()
        decoder.onMalformedInput(CodingErrorAction.REPORT)
        decoder.onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(value))
            true
        } catch (e: CharacterCodingException) {
            false
        }
    }
}
