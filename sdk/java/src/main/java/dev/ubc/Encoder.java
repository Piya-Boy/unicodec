package dev.ubc;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;

/**
 * A write-then-close streaming UBC v1 encoder. Plaintext is spooled to a temp file until its
 * final size is known, because the v1 header precedes the payload and carries both size and
 * chunk count (SPEC.md section 2.1).
 */
public final class Encoder extends OutputStream {
    private final OutputStream sink;
    private final byte[] metadata;
    private final EncodeOptions options;
    private File spoolFile;
    private RandomAccessFile spool;
    private long totalSize;
    private boolean finished;
    private boolean closed;

    public Encoder(OutputStream sink, List<MetadataEntry> entries, EncodeOptions options) {
        this.sink = sink;
        this.options = options == null ? new EncodeOptions() : options;
        this.metadata = Metadata.encode(entries);
        try {
            this.spoolFile = createOwnerOnlyTempFile();
            this.spool = new RandomAccessFile(spoolFile, "rw");
        } catch (IOException e) {
            throw new UbcException(ErrorCode.ERR_TRUNCATED);
        }
        // Best-effort safety net: if the caller never calls close()/finish(), the plaintext
        // spool is still removed at JVM exit rather than leaking on disk indefinitely.
        spoolFile.deleteOnExit();
    }

    private static File createOwnerOnlyTempFile() throws IOException {
        try {
            Path path = Files.createTempFile("ubc-encoder-", ".spool",
                    PosixFilePermissions.asFileAttribute(
                            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
            return path.toFile();
        } catch (UnsupportedOperationException notPosix) {
            // Non-POSIX filesystem (e.g. Windows): fall back to the platform default, which
            // is already restricted to the owning user account under NTFS ACLs.
            return File.createTempFile("ubc-encoder-", ".spool");
        }
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] data, int offset, int length) throws IOException {
        if (finished) {
            throw new IllegalStateException("encoder is already finished");
        }
        spool.write(data, offset, length);
        totalSize += length;
    }

    /** Writes the header, payload, authenticated root, and footer to the sink, then closes it. */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (!finished) {
                finish();
            }
        } finally {
            purgeSpool();
        }
    }

    private void finish() throws IOException {
        finished = true;
        long chunkSize = options.chunkSize;
        boolean encrypted = options.key != null;
        if (encrypted && chunkSize > 0xFFFF_FFEFL) {
            throw new UbcException(ErrorCode.ERR_RESERVED_BITS);
        }
        long chunkCount = totalSize == 0 ? 0 : (totalSize + chunkSize - 1) / chunkSize;
        byte[] baseNonce;
        if (encrypted) {
            if (options.baseNonce != null) {
                baseNonce = options.baseNonce;
            } else {
                baseNonce = new byte[12];
                new SecureRandom().nextBytes(baseNonce);
            }
        } else {
            baseNonce = new byte[12];
        }

        Header header = new Header(
                (encrypted ? Header.FLAG_ENCRYPTED : 0) | (metadata.length > 0 ? Header.FLAG_HAS_METADATA : 0),
                encrypted ? Header.HASH_HMAC_SHA256 : Header.HASH_SHA256,
                encrypted ? Header.AEAD_AES_256_GCM : Header.AEAD_NONE,
                chunkSize,
                chunkCount,
                totalSize,
                baseNonce);
        byte[] headerBytes = header.toBytes();
        sink.write(headerBytes);
        sink.write(metadata);

        byte[] metadataDigest = CryptoInternal.sha256(metadata);
        RootAccumulator root = encrypted
                ? RootAccumulator.keyed(CryptoInternal.rootKey(options.key, baseNonce))
                : RootAccumulator.plain();
        root.update(headerBytes);
        root.update(metadata);

        spool.seek(0);
        int bufferLength = (int) Math.min(totalSize, chunkSize);
        byte[] buffer = new byte[bufferLength];
        long index = 0;
        for (long written = 0; written < totalSize; written += chunkSize, index++) {
            int length = (int) Math.min(chunkSize, totalSize - written);
            spool.readFully(buffer, 0, length);
            byte[] body;
            if (encrypted) {
                byte[] aad = CryptoInternal.chunkAad(headerBytes, metadataDigest, index);
                body = CryptoInternal.gcmEncrypt(options.key, CryptoInternal.chunkNonce(baseNonce, index), buffer, 0,
                        length, aad);
            } else {
                body = java.util.Arrays.copyOf(buffer, length);
            }
            ByteBuffer clen = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(body.length);
            sink.write(clen.array());
            sink.write(body);
            root.update(CryptoInternal.sha256(body));
        }

        sink.write(root.finish());
        sink.write(new byte[] {'U', 'B', 'C', 'E'});
    }

    private void purgeSpool() {
        try {
            if (spool != null) {
                spool.close();
            }
        } catch (IOException ignored) {
            // best-effort close; the file delete below still runs
        }
        if (spoolFile != null) {
            try {
                Files.deleteIfExists(spoolFile.toPath());
            } catch (IOException ignored) {
                spoolFile.deleteOnExit();
            }
        }
    }
}
