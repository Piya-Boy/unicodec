package dev.ubc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/** Factory, verify, and inspect entry points over {@link Encoder}/{@link Decoder}. */
public final class Streaming {
    private static final int READ_BLOCK_SIZE = 32 << 10;

    private Streaming() {
    }

    public static Encoder newEncoder(OutputStream sink, List<MetadataEntry> entries, EncodeOptions options) {
        return new Encoder(sink, entries, options);
    }

    public static Decoder newDecoder(InputStream source, DecodeOptions options) {
        return new Decoder(source, options);
    }

    /** Fully decodes and discards the plaintext, reporting whether the container is valid. */
    public static VerifyReport verify(InputStream source, DecodeOptions options) {
        try {
            Decoder decoder = new Decoder(source, options);
            byte[] buffer = new byte[READ_BLOCK_SIZE];
            while (decoder.read(buffer, 0, buffer.length) != -1) {
                // discard; verification is in the read() side effects (auth + root check)
            }
        } catch (UbcException e) {
            return new VerifyReport(false, e.code());
        } catch (IOException e) {
            return new VerifyReport(false, ErrorCode.ERR_TRUNCATED);
        }
        return new VerifyReport(true, null);
    }

    /** Reads only the header and metadata — never touches payload or footer. */
    public static ContainerInfo inspect(InputStream source, DecodeOptions options) {
        DecodeOptions opts = options == null ? new DecodeOptions() : options;
        byte[] headerBytes = readExact(source, Header.SIZE);
        Header header = Header.parse(headerBytes, 0);
        List<MetadataEntry> entries = new ArrayList<>();
        if (header.hasMetadata()) {
            byte[] prefix = readExact(source, 4);
            long metadataLength = Integer.toUnsignedLong(
                    ByteBuffer.wrap(prefix).order(ByteOrder.LITTLE_ENDIAN).getInt());
            if (metadataLength == 0 || Long.compareUnsigned(metadataLength, opts.maxMetaBytes) > 0) {
                throw new UbcException(ErrorCode.ERR_META_MALFORMED);
            }
            byte[] body;
            try {
                body = readExact(source, (int) metadataLength);
            } catch (UbcException e) {
                throw e.code() == ErrorCode.ERR_TRUNCATED ? new UbcException(ErrorCode.ERR_META_MALFORMED) : e;
            }
            byte[] region = new byte[4 + body.length];
            System.arraycopy(prefix, 0, region, 0, 4);
            System.arraycopy(body, 0, region, 4, body.length);
            Metadata.ParseResult result = Metadata.parse(region, 0, boundedIntCap(opts.maxMetaBytes));
            entries = new ArrayList<>(result.entries);
        }
        return new ContainerInfo(
                Header.VERSION,
                header.encrypted(),
                header.hasMetadata(),
                header.hashAlgo,
                header.aeadAlgo,
                header.chunkSize,
                header.chunkCount,
                header.totalSize,
                entries);
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
