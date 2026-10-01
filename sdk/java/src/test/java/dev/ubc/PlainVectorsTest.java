package dev.ubc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Plain-mode one-shot encode/decode against the shared positive and negative vectors. */
final class PlainVectorsTest {

    private static Path vectorRoot() {
        return Path.of(System.getProperty("user.dir"), "..", "..", "spec", "vectors").normalize();
    }

    private static byte[] readVector(String relative) throws IOException {
        return Files.readAllBytes(vectorRoot().resolve(relative));
    }

    @Test
    void encodesEveryPlainVectorByteExactly() throws IOException {
        byte[] empty = readVector("inputs/empty.bin");
        assertArrayEquals(readVector("expected/plain-empty.ubc"), Payload.encodePlain(empty, List.of(), 1 << 20));

        byte[] oneByte = readVector("inputs/one-byte.bin");
        assertArrayEquals(
                readVector("expected/plain-one-byte.ubc"), Payload.encodePlain(oneByte, List.of(), 1 << 20));

        byte[] chunk1m = readVector("inputs/chunk-1m.bin");
        assertArrayEquals(
                readVector("expected/plain-chunk-1m.ubc"), Payload.encodePlain(chunk1m, List.of(), 1 << 20));

        byte[] chunk1mPlusOne = readVector("inputs/chunk-1m-plus-one.bin");
        assertArrayEquals(
                readVector("expected/plain-chunk-1m-plus-one.ubc"),
                Payload.encodePlain(chunk1mPlusOne, List.of(), 1 << 20));

        byte[] multi3m = readVector("inputs/multi-3m.bin");
        assertArrayEquals(
                readVector("expected/plain-multi-3m.ubc"), Payload.encodePlain(multi3m, List.of(), 1 << 20));

        List<MetadataEntry> entries = List.of(
                new MetadataEntry(0x0001, hex("e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874")),
                new MetadataEntry(0x0002, hex("746578742f706c61696e")),
                new MetadataEntry(0x0003, hex("00a8da769b010000")),
                new MetadataEntry(0x1000, hex("00ff7f")));
        byte[] metaInput = readVector("inputs/one-byte.bin");
        assertArrayEquals(
                readVector("expected/plain-metadata.ubc"), Payload.encodePlain(metaInput, entries, 1 << 20));
    }

    @Test
    void decodesEveryPlainVector() throws IOException {
        decodeMatchesInput("expected/plain-empty.ubc", "inputs/empty.bin");
        decodeMatchesInput("expected/plain-one-byte.ubc", "inputs/one-byte.bin");
        decodeMatchesInput("expected/plain-chunk-1m.ubc", "inputs/chunk-1m.bin");
        decodeMatchesInput("expected/plain-chunk-1m-plus-one.ubc", "inputs/chunk-1m-plus-one.bin");
        decodeMatchesInput("expected/plain-multi-3m.ubc", "inputs/multi-3m.bin");
        decodeMatchesInput("expected/plain-metadata.ubc", "inputs/one-byte.bin");
    }

    private void decodeMatchesInput(String container, String input) throws IOException {
        DecodeResult result = Payload.decodePlain(readVector(container), null);
        assertArrayEquals(readVector(input), result.data, container);
    }

    @Test
    void flippedPlainPayloadReturnsRootMismatch() throws IOException {
        byte[] container = readVector("expected/plain-chunk-1m.ubc").clone();
        container[Header.SIZE + 4] ^= 0x01;
        UbcException exception = assertThrows(UbcException.class, () -> Payload.decodePlain(container, null));
        assertEquals(ErrorCode.ERR_ROOT_MISMATCH, exception.code());
    }

    @Test
    void negativeVectorsUseStableErrorCodes() throws IOException {
        Object[][] cases = {
            {"negative-truncated.ubc", ErrorCode.ERR_TRUNCATED},
            {"negative-root-mismatch.ubc", ErrorCode.ERR_ROOT_MISMATCH},
            {"negative-trailing-data.ubc", ErrorCode.ERR_TRAILING_DATA},
            {"negative-oversized-clen.ubc", ErrorCode.ERR_TRUNCATED},
        };
        for (Object[] testCase : cases) {
            String name = (String) testCase[0];
            ErrorCode expected = (ErrorCode) testCase[1];
            byte[] container = readVector("expected/" + name);
            UbcException exception =
                    assertThrows(UbcException.class, () -> Payload.decodePlain(container, null), name);
            assertEquals(expected, exception.code(), name);
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
