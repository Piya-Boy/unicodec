package dev.ubc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** UBC metadata TLV block encoding and parsing (SPEC.md section 2.2). */
public final class Metadata {
    public static final int TAG_FILENAME = 0x0001;
    public static final int TAG_MIME_TYPE = 0x0002;
    public static final int TAG_CREATED_AT = 0x0003;

    private Metadata() {
    }

    /** Result of {@link #parse}: the decoded entries and total bytes consumed from the input. */
    public static final class ParseResult {
        public final List<MetadataEntry> entries;
        public final int consumed;

        public ParseResult(List<MetadataEntry> entries, int consumed) {
            this.entries = entries;
            this.consumed = consumed;
        }
    }

    public static byte[] encode(List<MetadataEntry> entries) {
        List<MetadataEntry> ordered = new ArrayList<>(entries);
        ordered.sort((a, b) -> Integer.compareUnsigned(a.tag, b.tag));
        if (ordered.isEmpty()) {
            return new byte[0];
        }

        java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        int previousTag = -1;
        boolean havePrevious = false;
        for (MetadataEntry entry : ordered) {
            validateEntry(entry);
            if (havePrevious && previousTag == entry.tag) {
                throw new UbcException(ErrorCode.ERR_META_MALFORMED);
            }
            previousTag = entry.tag;
            havePrevious = true;
            if (Integer.toUnsignedLong(entry.value.length) > 0xFFFF_FFFFL
                    || (long) body.size() + 6 + entry.value.length > 0xFFFF_FFFFL) {
                throw new UbcException(ErrorCode.ERR_META_MALFORMED);
            }
            ByteBuffer entryHeader = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN);
            entryHeader.putShort((short) entry.tag);
            entryHeader.putInt(entry.value.length);
            body.writeBytes(entryHeader.array());
            body.writeBytes(entry.value);
        }
        byte[] bodyBytes = body.toByteArray();
        ByteBuffer result = ByteBuffer.allocate(4 + bodyBytes.length).order(ByteOrder.LITTLE_ENDIAN);
        result.putInt(bodyBytes.length);
        result.put(bodyBytes);
        return result.array();
    }

    public static ParseResult parse(byte[] data, int offset, Integer maxBytes) {
        if (data.length - offset < 4) {
            throw new UbcException(ErrorCode.ERR_META_MALFORMED);
        }
        ByteBuffer lengthBuffer = ByteBuffer.wrap(data, offset, 4).order(ByteOrder.LITTLE_ENDIAN);
        long metadataLength = Integer.toUnsignedLong(lengthBuffer.getInt());
        long available = data.length - offset - 4L;
        if (metadataLength == 0 || (maxBytes != null && metadataLength > Integer.toUnsignedLong(maxBytes))
                || metadataLength > available) {
            throw new UbcException(ErrorCode.ERR_META_MALFORMED);
        }

        int end = offset + 4 + (int) metadataLength;
        List<MetadataEntry> entries = new ArrayList<>();
        int cursor = offset + 4;
        int previousTag = -1;
        boolean havePrevious = false;
        while (cursor < end) {
            if (end - cursor < 6) {
                throw new UbcException(ErrorCode.ERR_META_MALFORMED);
            }
            ByteBuffer entryHeader = ByteBuffer.wrap(data, cursor, 6).order(ByteOrder.LITTLE_ENDIAN);
            int tag = Short.toUnsignedInt(entryHeader.getShort());
            long valueLength = Integer.toUnsignedLong(entryHeader.getInt());
            cursor += 6;
            if (valueLength > (long) (end - cursor) || (havePrevious && tag <= previousTag)) {
                throw new UbcException(ErrorCode.ERR_META_MALFORMED);
            }
            byte[] value = new byte[(int) valueLength];
            System.arraycopy(data, cursor, value, 0, (int) valueLength);
            MetadataEntry entry = new MetadataEntry(tag, value);
            validateEntry(entry);
            entries.add(entry);
            previousTag = tag;
            havePrevious = true;
            cursor += (int) valueLength;
        }
        return new ParseResult(entries, end - offset);
    }

    private static void validateEntry(MetadataEntry entry) {
        if (entry.tag < 0 || entry.tag > 0xFFFF) {
            throw new UbcException(ErrorCode.ERR_META_MALFORMED);
        }
        if (entry.value == null) {
            throw new UbcException(ErrorCode.ERR_META_MALFORMED);
        }
        if (entry.tag == TAG_FILENAME) {
            if (startsWithBom(entry.value) || containsNul(entry.value)) {
                throw new UbcException(ErrorCode.ERR_META_MALFORMED);
            }
            if (!isValidUtf8(entry.value)) {
                throw new UbcException(ErrorCode.ERR_META_MALFORMED);
            }
        } else if (entry.tag == TAG_MIME_TYPE) {
            for (byte b : entry.value) {
                int unsigned = Byte.toUnsignedInt(b);
                if (unsigned == 0 || unsigned > 0x7F) {
                    throw new UbcException(ErrorCode.ERR_META_MALFORMED);
                }
            }
        } else if (entry.tag == TAG_CREATED_AT) {
            if (entry.value.length != 8) {
                throw new UbcException(ErrorCode.ERR_META_MALFORMED);
            }
        }
    }

    private static boolean startsWithBom(byte[] value) {
        return value.length >= 3 && (value[0] & 0xFF) == 0xEF && (value[1] & 0xFF) == 0xBB
                && (value[2] & 0xFF) == 0xBF;
    }

    private static boolean containsNul(byte[] value) {
        for (byte b : value) {
            if (b == 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean isValidUtf8(byte[] value) {
        java.nio.charset.CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
        decoder.onMalformedInput(java.nio.charset.CodingErrorAction.REPORT);
        decoder.onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT);
        try {
            decoder.decode(ByteBuffer.wrap(value));
            return true;
        } catch (java.nio.charset.CharacterCodingException e) {
            return false;
        }
    }
}
