package dev.ubc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.crypto.AEADBadTagException;

/**
 * A pull-based streaming UBC v1 decoder. Each encrypted chunk is authenticated (GCM tag
 * verified) before any of its plaintext is returned (SPEC.md section 3, verify-before-release).
 */
public final class Decoder extends InputStream {
    private static final int FOOTER_SIZE = 36;
    private static final byte[] FOOTER_MAGIC = {'U', 'B', 'C', 'E'};

    private final InputStream source;
    private final DecodeOptions options;
    private final Header header;
    private final byte[] headerBytes;
    private final List<MetadataEntry> metadata;
    private final byte[] metadataDigest;
    private final RootAccumulator root;
    private final byte[] baseNonce;

    private long chunkIndex;
    private long plaintextSize;
    private byte[] pending;
    private int pendingOffset;
    private byte[] prefetchedFooter;
    private boolean finished;
    private UbcException terminalError;

    public Decoder(InputStream source, DecodeOptions options) {
        this.source = source;
        this.options = options == null ? new DecodeOptions() : options;

        this.headerBytes = readExact(source, Header.SIZE);
        this.header = Header.parse(headerBytes, 0);

        List<MetadataEntry> entries = List.of();
        byte[] metadataRegion = new byte[0];
        if (header.hasMetadata()) {
            metadataRegion = readMetadataRegion(source, this.options.maxMetaBytes);
            Metadata.ParseResult result = Metadata.parse(metadataRegion, 0, boundedIntCap(this.options.maxMetaBytes));
            entries = result.entries;
        }
        this.metadata = entries;

        if (header.encrypted() && (this.options.key == null || this.options.key.length != 32)) {
            throw new UbcException(ErrorCode.ERR_MISSING_KEY);
        }
        if (Long.compareUnsigned(header.chunkCount, this.options.maxChunkCount) > 0
                || Long.compareUnsigned(header.totalSize, this.options.maxTotalSize) > 0) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }

        this.metadataDigest = CryptoInternal.sha256(metadataRegion);
        this.baseNonce = header.encrypted() ? header.baseNonce() : null;
        this.root = header.encrypted()
                ? RootAccumulator.keyed(CryptoInternal.rootKey(this.options.key, this.baseNonce))
                : RootAccumulator.plain();
        this.root.update(headerBytes);
        this.root.update(metadataRegion);
    }

    /** A defensive copy of the decoded metadata entries. */
    public List<MetadataEntry> metadata() {
        return Collections.unmodifiableList(new ArrayList<>(metadata));
    }

    @Override
    public int read() throws IOException {
        byte[] single = new byte[1];
        int count = read(single, 0, 1);
        return count <= 0 ? -1 : single[0] & 0xFF;
    }

    @Override
    public int read(byte[] data, int offset, int length) throws IOException {
        if (terminalError != null) {
            throw terminalError;
        }
        if (length == 0) {
            return 0;
        }
        try {
            while (pending == null && !finished) {
                loadNextChunk();
            }
        } catch (UbcException e) {
            terminalError = e;
            throw e;
        }
        if (pending == null) {
            return -1;
        }
        int available = pending.length - pendingOffset;
        int toCopy = Math.min(available, length);
        System.arraycopy(pending, pendingOffset, data, offset, toCopy);
        pendingOffset += toCopy;
        if (pendingOffset == pending.length) {
            pending = null;
            pendingOffset = 0;
        }
        return toCopy;
    }

    private void loadNextChunk() throws IOException {
        if (Long.compareUnsigned(chunkIndex, header.chunkCount) == 0) {
            verifyFooter();
            return;
        }
        long lengthValue = Integer.toUnsignedLong(
                ByteBuffer.wrap(readExact(source, 4)).order(ByteOrder.LITTLE_ENDIAN).getInt());
        if (Long.compareUnsigned(lengthValue, options.maxChunkLen) > 0) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }
        int chunkLength = (int) lengthValue;
        byte[] body = readExact(source, chunkLength);
        root.update(CryptoInternal.sha256(body));

        boolean isLastChunk = chunkIndex + 1 == header.chunkCount;
        if (header.encrypted() && isLastChunk) {
            // Preflight the footer before authenticating the final chunk so a truncated
            // stream surfaces ERR_TRUNCATED rather than a misleading ERR_CHUNK_AUTH — SPEC.md
            // section 5's precedence requires truncation to win over chunk-auth failure.
            prefetchedFooter = readExact(source, FOOTER_SIZE);
        }

        byte[] plain;
        if (header.encrypted()) {
            if (body.length < CryptoInternal.GCM_TAG_SIZE) {
                throw new UbcException(ErrorCode.ERR_CHUNK_AUTH);
            }
            try {
                plain = CryptoInternal.gcmDecrypt(options.key, CryptoInternal.chunkNonce(baseNonce, chunkIndex), body,
                        0, body.length, CryptoInternal.chunkAad(headerBytes, metadataDigest, chunkIndex));
            } catch (AEADBadTagException e) {
                throw new UbcException(ErrorCode.ERR_CHUNK_AUTH);
            }
        } else {
            plain = body;
        }

        if (Long.compareUnsigned(plain.length, header.totalSize - plaintextSize) > 0) {
            throw new UbcException(ErrorCode.ERR_ROOT_MISMATCH);
        }
        plaintextSize += plain.length;
        chunkIndex++;
        pending = plain.length == 0 ? null : plain;
        pendingOffset = 0;
    }

    private void verifyFooter() throws IOException {
        byte[] footer = prefetchedFooter != null ? prefetchedFooter : readExact(source, FOOTER_SIZE);
        byte[] footerRoot = java.util.Arrays.copyOfRange(footer, 0, 32);
        byte[] footerMagic = java.util.Arrays.copyOfRange(footer, 32, FOOTER_SIZE);
        if (!java.util.Arrays.equals(footerMagic, FOOTER_MAGIC)) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }
        if (plaintextSize != header.totalSize || !MessageDigest.isEqual(footerRoot, root.finish())) {
            throw new UbcException(ErrorCode.ERR_ROOT_MISMATCH);
        }
        if (source.read() != -1) {
            throw new UbcException(ErrorCode.ERR_TRAILING_DATA);
        }
        finished = true;
    }

    private static byte[] readMetadataRegion(InputStream source, long maxMetaBytes) {
        byte[] prefix = readExact(source, 4);
        long metadataLength = Integer.toUnsignedLong(
                ByteBuffer.wrap(prefix).order(ByteOrder.LITTLE_ENDIAN).getInt());
        if (metadataLength == 0 || Long.compareUnsigned(metadataLength, maxMetaBytes) > 0) {
            throw new UbcException(ErrorCode.ERR_META_MALFORMED);
        }
        byte[] body;
        try {
            body = readExact(source, (int) metadataLength);
        } catch (UbcException e) {
            if (e.code() == ErrorCode.ERR_TRUNCATED) {
                throw new UbcException(ErrorCode.ERR_META_MALFORMED);
            }
            throw e;
        }
        byte[] region = new byte[4 + body.length];
        System.arraycopy(prefix, 0, region, 0, 4);
        System.arraycopy(body, 0, region, 4, body.length);
        return region;
    }

    private static byte[] readExact(InputStream source, int length) {
        byte[] data = new byte[length];
        int total = 0;
        while (total < length) {
            int count;
            try {
                count = source.read(data, total, length - total);
            } catch (IOException e) {
                throw new UbcException(ErrorCode.ERR_TRUNCATED);
            }
            if (count < 0) {
                throw new UbcException(ErrorCode.ERR_TRUNCATED);
            }
            total += count;
        }
        return data;
    }

    private static Integer boundedIntCap(long cap) {
        return cap > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) cap;
    }
}
