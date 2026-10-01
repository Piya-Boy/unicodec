package dev.ubc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Header + metadata round-trip and negative checks against spec/vectors shared fixtures. */
final class HeaderMetadataVectorsTest {

    private static Path vectorRoot() {
        return Path.of(System.getProperty("user.dir"), "..", "..", "spec", "vectors").normalize();
    }

    private static byte[] vector(String name) throws IOException {
        return Files.readAllBytes(vectorRoot().resolve("expected").resolve(name));
    }

    @Test
    void allPositiveVectorHeadersRoundTripByteExactly() throws IOException {
        Path expectedDir = vectorRoot().resolve("expected");
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(expectedDir, "*.ubc")) {
            for (Path path : stream) {
                files.add(path);
            }
        }
        assertTrue(!files.isEmpty(), "vector directory must contain .ubc files");
        for (Path path : files) {
            String name = path.getFileName().toString();
            if (name.startsWith("negative-")) {
                continue;
            }
            byte[] container = Files.readAllBytes(path);
            Header header = Header.parse(container, 0);
            byte[] expectedHeader = Arrays.copyOfRange(container, 0, Header.SIZE);
            assertArrayEquals(expectedHeader, header.toBytes(), name);
        }
    }

    @Test
    void vectorMetadataRoundTripsByteExactly() throws IOException {
        byte[] container = vector("plain-metadata.ubc");
        Header header = Header.parse(container, 0);
        assertTrue(header.hasMetadata());

        Metadata.ParseResult result = Metadata.parse(container, Header.SIZE, null);
        byte[] reencoded = Metadata.encode(result.entries);
        byte[] expected = Arrays.copyOfRange(container, Header.SIZE, Header.SIZE + result.consumed);
        assertArrayEquals(expected, reencoded);
    }

    @Test
    void headerNegativeVectorsUseStableErrorCodes() throws IOException {
        Object[][] cases = {
            {"negative-bad-magic.ubc", ErrorCode.ERR_BAD_MAGIC},
            {"negative-version-two.ubc", ErrorCode.ERR_UNSUPPORTED_VER},
            {"negative-hash-algo.ubc", ErrorCode.ERR_UNSUPPORTED_ALGO},
            {"negative-aead-algo.ubc", ErrorCode.ERR_UNSUPPORTED_ALGO},
            {"negative-reserved-flag.ubc", ErrorCode.ERR_RESERVED_BITS},
            {"negative-inconsistent-encryption.ubc", ErrorCode.ERR_RESERVED_BITS},
            {"negative-zero-chunk-size.ubc", ErrorCode.ERR_RESERVED_BITS},
            {"negative-encrypted-zero-chunk-size.ubc", ErrorCode.ERR_RESERVED_BITS},
            {"negative-encrypted-oversized-chunk-size.ubc", ErrorCode.ERR_RESERVED_BITS},
        };
        for (Object[] testCase : cases) {
            String name = (String) testCase[0];
            ErrorCode expected = (ErrorCode) testCase[1];
            byte[] container = vector(name);
            UbcException exception = assertThrows(UbcException.class, () -> Header.parse(container, 0), name);
            assertEquals(expected, exception.code(), name);
        }
    }

    @Test
    void metadataNegativeVectorsUseStableErrorCodes() throws IOException {
        String[] names = {
            "negative-meta-out-of-order.ubc",
            "negative-meta-duplicate.ubc",
            "negative-meta-overrun.ubc",
            "negative-empty-metadata.ubc",
            "negative-encrypted-reserved-metadata.ubc",
            "negative-reserved-metadata.ubc",
        };
        for (String name : names) {
            byte[] container = vector(name);
            UbcException exception = assertThrows(
                    UbcException.class, () -> Metadata.parse(container, Header.SIZE, null), name);
            assertEquals(ErrorCode.ERR_META_MALFORMED, exception.code(), name);
        }
    }

    @Test
    void metadataEncoderSortsTagsAndRejectsDuplicates() {
        List<MetadataEntry> entries = List.of(
                new MetadataEntry(0x1000, new byte[] {1}),
                new MetadataEntry(0x0001, "example.txt".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        byte[] encoded = Metadata.encode(entries);
        Metadata.ParseResult result = Metadata.parse(encoded, 0, null);
        assertEquals(0x0001, result.entries.get(0).tag);
        assertEquals(0x1000, result.entries.get(1).tag);

        List<MetadataEntry> duplicates = List.of(
                new MetadataEntry(1, new byte[0]),
                new MetadataEntry(1, new byte[0]));
        UbcException exception = assertThrows(UbcException.class, () -> Metadata.encode(duplicates));
        assertEquals(ErrorCode.ERR_META_MALFORMED, exception.code());
    }

    @Test
    void metadataLengthCapIsCheckedBeforeCopyingEntries() {
        byte[] oversized = new byte[] {
            (byte) 0x01, 0x00, 0x00, 0x01
        }; // declares a length larger than DEFAULT_MAX_METADATA_BYTES (16 MiB)
        UbcException exception = assertThrows(
                UbcException.class, () -> Metadata.parse(oversized, 0, 16 << 20));
        assertEquals(ErrorCode.ERR_META_MALFORMED, exception.code());

        byte[] metadata = Metadata.encode(List.of(new MetadataEntry(0x1000, new byte[] {1})));
        UbcException capped = assertThrows(
                UbcException.class, () -> Metadata.parse(metadata, 0, 6));
        assertEquals(ErrorCode.ERR_META_MALFORMED, capped.code());
    }
}
