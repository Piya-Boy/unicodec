package dev.ubc;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/** One-shot plain (non-encrypted) UBC v1 encoding and decoding (SPEC.md sections 2-4). */
public final class Payload {
    public static final int DEFAULT_CHUNK_SIZE = 1 << 20;
    private static final int FOOTER_SIZE = 36;
    private static final byte[] FOOTER_MAGIC = {'U', 'B', 'C', 'E'};

    private Payload() {
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on every JDK", e);
        }
    }

    public static byte[] encodePlain(byte[] data, List<MetadataEntry> entries, long chunkSize) {
        if (chunkSize <= 0 || chunkSize > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("chunkSize must be a positive uint32");
        }
        byte[] metadata = Metadata.encode(entries);
        // chunkSize can exceed Integer.MAX_VALUE (plain mode allows up to uint32 max); compute
        // chunk count and loop stride with long arithmetic and only narrow per-slice lengths,
        // which are always <= data.length and therefore safely int-representable.
        long dataLength = data.length;
        long chunkCount = dataLength == 0 ? 0 : (dataLength + chunkSize - 1) / chunkSize;

        Header header = new Header(
                metadata.length > 0 ? Header.FLAG_HAS_METADATA : 0,
                Header.HASH_SHA256,
                Header.AEAD_NONE,
                chunkSize,
                chunkCount,
                data.length,
                new byte[12]);
        byte[] headerBytes = header.toBytes();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(headerBytes);
        output.writeBytes(metadata);

        MessageDigest root = sha256();
        root.update(headerBytes);
        root.update(metadata);

        for (long offset = 0; offset < dataLength; offset += chunkSize) {
            int intOffset = (int) offset;
            int length = (int) Math.min(chunkSize, dataLength - offset);
            ByteBuffer clen = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(length);
            output.writeBytes(clen.array());
            output.write(data, intOffset, length);
            root.update(sha256Of(data, intOffset, length));
        }

        output.writeBytes(root.digest());
        output.writeBytes(FOOTER_MAGIC);
        return output.toByteArray();
    }

    public static DecodeResult decodePlain(byte[] container, DecodeOptions options) {
        DecodeOptions opts = options == null ? new DecodeOptions() : options;

        Header header = Header.parse(container, 0);
        byte[] headerBytes = java.util.Arrays.copyOfRange(container, 0, Header.SIZE);
        int offset = Header.SIZE;

        List<MetadataEntry> entries = List.of();
        byte[] metadataRegion = new byte[0];
        if (header.hasMetadata()) {
            Metadata.ParseResult result = Metadata.parse(container, offset, boundedIntCap(opts.maxMetaBytes));
            entries = result.entries;
            metadataRegion = java.util.Arrays.copyOfRange(container, offset, offset + result.consumed);
            offset += result.consumed;
        }

        if (header.encrypted()) {
            throw new UbcException(ErrorCode.ERR_MISSING_KEY);
        }
        if (Long.compareUnsigned(header.chunkCount, opts.maxChunkCount) > 0
                || Long.compareUnsigned(header.totalSize, opts.maxTotalSize) > 0) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }

        MessageDigest root = sha256();
        root.update(headerBytes);
        root.update(metadataRegion);

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        long remaining = header.totalSize;
        for (long i = 0; Long.compareUnsigned(i, header.chunkCount) < 0; i++) {
            if (container.length - offset < 4) {
                throw new UbcException(ErrorCode.ERR_TRUNCATED);
            }
            long chunkLength = Integer.toUnsignedLong(
                    ByteBuffer.wrap(container, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
            offset += 4;
            if (Long.compareUnsigned(chunkLength, opts.maxChunkLen) > 0
                    || chunkLength > container.length - offset) {
                throw new UbcException(ErrorCode.ERR_TRUNCATED);
            }
            if (Long.compareUnsigned(chunkLength, remaining) > 0) {
                throw new UbcException(ErrorCode.ERR_ROOT_MISMATCH);
            }
            int chunkLengthInt = (int) chunkLength;
            root.update(sha256Of(container, offset, chunkLengthInt));
            plaintext.write(container, offset, chunkLengthInt);
            offset += chunkLengthInt;
            remaining -= chunkLength;
        }

        if (container.length - offset < FOOTER_SIZE) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }
        byte[] footerRoot = java.util.Arrays.copyOfRange(container, offset, offset + 32);
        byte[] footerMagic = java.util.Arrays.copyOfRange(container, offset + 32, offset + FOOTER_SIZE);
        if (!java.util.Arrays.equals(footerMagic, FOOTER_MAGIC)) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }
        byte[] plaintextBytes = plaintext.toByteArray();
        if (Integer.toUnsignedLong(plaintextBytes.length) != header.totalSize
                || !MessageDigest.isEqual(footerRoot, root.digest())) {
            throw new UbcException(ErrorCode.ERR_ROOT_MISMATCH);
        }
        if (container.length != offset + FOOTER_SIZE) {
            throw new UbcException(ErrorCode.ERR_TRAILING_DATA);
        }
        return new DecodeResult(plaintextBytes, entries);
    }

    private static byte[] sha256Of(byte[] data, int offset, int length) {
        MessageDigest digest = sha256();
        digest.update(data, offset, length);
        return digest.digest();
    }

    private static Integer boundedIntCap(long cap) {
        return cap > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) cap;
    }
}
