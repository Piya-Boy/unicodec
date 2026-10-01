package dev.ubc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Streaming Encoder/Decoder + verify/inspect against the shared vectors and targeted edge cases. */
final class StreamingTest {

    private static final byte[] KEY =
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] BASE_NONCE = hex("f0e0d0c0b0a0908070605040");

    private static Path vectorRoot() {
        return Path.of(System.getProperty("user.dir"), "..", "..", "spec", "vectors").normalize();
    }

    private static byte[] readVector(String relative) throws IOException {
        return Files.readAllBytes(vectorRoot().resolve(relative));
    }

    @Test
    void streamedPlainOutputIsByteExactAndFragmentedDecodeRoundTrips() throws IOException {
        byte[] input = readVector("inputs/multi-3m.bin");
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (Encoder encoder = new Encoder(sink, List.of(), new EncodeOptions().withChunkSize(1 << 20))) {
            encoder.write(input, 0, input.length / 3);
            encoder.write(input, input.length / 3, input.length - input.length / 3);
        }
        byte[] streamed = sink.toByteArray();
        assertArrayEquals(readVector("expected/plain-multi-3m.ubc"), streamed);

        // Decode through a stream that only ever hands back 1 byte at a time.
        Decoder decoder = new Decoder(new OneByteAtATimeStream(streamed), null);
        ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        byte[] buffer = new byte[1];
        int count;
        while ((count = decoder.read(buffer, 0, 1)) != -1) {
            decoded.write(buffer, 0, count);
        }
        assertArrayEquals(input, decoded.toByteArray());
    }

    @Test
    void streamedEncryptedOutputIsByteExactAndAuthenticatesBeforeRelease() throws IOException {
        byte[] input = readVector("inputs/chunk-1m-plus-one.bin");
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        EncodeOptions options = new EncodeOptions(1 << 20, KEY, BASE_NONCE);
        try (Encoder encoder = new Encoder(sink, List.of(), options)) {
            encoder.write(input, 0, input.length);
        }
        assertArrayEquals(readVector("expected/encrypted-chunk-1m-plus-one.ubc"), sink.toByteArray());

        Decoder decoder = new Decoder(
                new ByteArrayInputStream(sink.toByteArray()), new DecodeOptions().withKey(KEY));
        ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = decoder.read(buffer, 0, buffer.length)) != -1) {
            decoded.write(buffer, 0, count);
        }
        assertArrayEquals(input, decoded.toByteArray());
    }

    @Test
    void streamedPlainDecoderWithholdsOutputUntilRootVerifies() throws IOException {
        byte[] container = readVector("expected/plain-chunk-1m.ubc").clone();
        container[container.length - 1] ^= 0x01; // corrupt footer magic's last byte
        Decoder decoder = new Decoder(new ByteArrayInputStream(container), null);
        byte[] buffer = new byte[4096];
        UbcException exception = assertThrows(UbcException.class, () -> {
            int count;
            while ((count = decoder.read(buffer, 0, buffer.length)) != -1) {
                // drain
            }
        });
        assertEquals(ErrorCode.ERR_TRUNCATED, exception.code());
    }

    @Test
    void streamedPlainDecoderWithholdsOutputUntilTrailingDataIsChecked() throws IOException {
        byte[] container = readVector("expected/plain-chunk-1m.ubc");
        byte[] withTrailingByte = java.util.Arrays.copyOf(container, container.length + 1);
        Decoder decoder = new Decoder(new ByteArrayInputStream(withTrailingByte), null);
        byte[] buffer = new byte[4096];
        UbcException exception = assertThrows(UbcException.class, () -> {
            int count;
            while ((count = decoder.read(buffer, 0, buffer.length)) != -1) {
                // drain
            }
        });
        assertEquals(ErrorCode.ERR_TRAILING_DATA, exception.code());
    }

    @Test
    void truncatedEncryptedFooterPrecedesFinalChunkAuthentication() throws IOException {
        // Corrupt both the final chunk's GCM tag AND truncate the footer. SPEC.md section 5
        // requires truncation (stage 4) to win over chunk-auth failure (stage 5).
        byte[] container = readVector("expected/encrypted-one-byte.ubc").clone();
        int footerStart = container.length - 36;
        container[footerStart - 1] ^= 0x01; // flip the last byte of the only chunk's GCM tag
        byte[] truncated = java.util.Arrays.copyOf(container, container.length - 10);

        Decoder decoder = new Decoder(new ByteArrayInputStream(truncated), new DecodeOptions().withKey(KEY));
        byte[] buffer = new byte[4096];
        UbcException exception = assertThrows(UbcException.class, () -> {
            int count;
            while ((count = decoder.read(buffer, 0, buffer.length)) != -1) {
                // drain
            }
        });
        assertEquals(ErrorCode.ERR_TRUNCATED, exception.code());
    }

    @Test
    void streamedEncoderWithLargeChunkSizeOnlyBuffersWrittenInput() throws IOException {
        // A chunk_size far larger than the actual input must not cause the encoder to
        // allocate a chunk_size-sized buffer (the historical Rust OOM bug this guards against).
        byte[] input = {1, 2, 3};
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        EncodeOptions options = new EncodeOptions().withChunkSize(1 << 28); // 256 MiB
        try (Encoder encoder = new Encoder(sink, List.of(), options)) {
            encoder.write(input, 0, input.length);
        }
        DecodeResult result = Payload.decodePlain(sink.toByteArray(), null);
        assertArrayEquals(input, result.data);
    }

    @Test
    void streamedDecoderEnforcesCapsBeforeAllocatingChunkData() throws IOException {
        byte[] container = readVector("expected/plain-chunk-1m.ubc");
        DecodeOptions tight = new DecodeOptions(16L << 20, 4, 1L << 20, 1L << 30, null);
        Decoder decoder = new Decoder(new ByteArrayInputStream(container), tight);
        byte[] buffer = new byte[4096];
        UbcException exception =
                assertThrows(UbcException.class, () -> decoder.read(buffer, 0, buffer.length));
        assertEquals(ErrorCode.ERR_TRUNCATED, exception.code());
    }

    @Test
    void verifyAndInspectHaveTheirDocumentedReadScopes() throws IOException {
        byte[] container = readVector("expected/plain-metadata.ubc");
        VerifyReport ok = Streaming.verify(new ByteArrayInputStream(container), null);
        assertTrue(ok.ok);

        byte[] corrupted = container.clone();
        corrupted[Header.SIZE + 4] ^= 0x01;
        VerifyReport bad = Streaming.verify(new ByteArrayInputStream(corrupted), null);
        assertFalse(bad.ok);
        assertEquals(ErrorCode.ERR_ROOT_MISMATCH, bad.error);

        // inspect only reads header + metadata; it must not touch (or require) the payload or
        // footer at all, so handing it a stream with the footer deliberately mangled still works.
        byte[] mangledFooter = container.clone();
        mangledFooter[mangledFooter.length - 1] ^= 0x01;
        ContainerInfo info = Streaming.inspect(new ByteArrayInputStream(mangledFooter), null);
        assertTrue(info.hasMetadata);
        assertFalse(info.encrypted);
        assertEquals(4, info.metadata.size());
    }

    private static final class OneByteAtATimeStream extends InputStream {
        private final InputStream delegate;

        OneByteAtATimeStream(byte[] data) {
            this.delegate = new ByteArrayInputStream(data);
        }

        @Override
        public int read() throws IOException {
            return delegate.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            int single = delegate.read();
            if (single < 0) {
                return -1;
            }
            b[off] = (byte) single;
            return 1;
        }
    }

    private static byte[] hex(String value) {
        int length = value.length();
        byte[] result = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            result[i / 2] = (byte) Integer.parseInt(value.substring(i, i + 2), 16);
        }
        return result;
    }
}
