package dev.ubc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** AES-256-GCM encrypted-mode encode/decode against the shared fixed-nonce vectors. */
final class EncryptedVectorsTest {

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
    void encodesEveryEncryptedVectorByteExactly() throws IOException {
        assertArrayEquals(
                readVector("expected/encrypted-empty.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(
                        readVector("inputs/empty.bin"), KEY, BASE_NONCE, List.of(), 1 << 20));
        assertArrayEquals(
                readVector("expected/encrypted-one-byte.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(
                        readVector("inputs/one-byte.bin"), KEY, BASE_NONCE, List.of(), 1 << 20));
        assertArrayEquals(
                readVector("expected/encrypted-chunk-1m.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(
                        readVector("inputs/chunk-1m.bin"), KEY, BASE_NONCE, List.of(), 1 << 20));
        assertArrayEquals(
                readVector("expected/encrypted-chunk-1m-plus-one.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(
                        readVector("inputs/chunk-1m-plus-one.bin"), KEY, BASE_NONCE, List.of(), 1 << 20));
        assertArrayEquals(
                readVector("expected/encrypted-multi-3m.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(
                        readVector("inputs/multi-3m.bin"), KEY, BASE_NONCE, List.of(), 1 << 20));

        List<MetadataEntry> entries = List.of(
                new MetadataEntry(0x0001, hex("e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874")),
                new MetadataEntry(0x0002, hex("746578742f706c61696e")),
                new MetadataEntry(0x0003, hex("00a8da769b010000")),
                new MetadataEntry(0x1000, hex("00ff7f")));
        assertArrayEquals(
                readVector("expected/encrypted-metadata.ubc"),
                Crypto.encodeEncryptedWithFixedNonce(
                        readVector("inputs/one-byte.bin"), KEY, BASE_NONCE, entries, 1 << 20));
    }

    @Test
    void decodesEveryEncryptedVector() throws IOException {
        decodeMatchesInput("expected/encrypted-empty.ubc", "inputs/empty.bin");
        decodeMatchesInput("expected/encrypted-one-byte.ubc", "inputs/one-byte.bin");
        decodeMatchesInput("expected/encrypted-chunk-1m.ubc", "inputs/chunk-1m.bin");
        decodeMatchesInput("expected/encrypted-chunk-1m-plus-one.ubc", "inputs/chunk-1m-plus-one.bin");
        decodeMatchesInput("expected/encrypted-multi-3m.ubc", "inputs/multi-3m.bin");
        decodeMatchesInput("expected/encrypted-metadata.ubc", "inputs/one-byte.bin");
    }

    private void decodeMatchesInput(String container, String input) throws IOException {
        DecodeOptions options = new DecodeOptions().withKey(KEY);
        DecodeResult result = Crypto.decodeEncrypted(readVector(container), options);
        assertArrayEquals(readVector(input), result.data, container);
    }

    @Test
    void wrongKeyReturnsChunkAuthOnNonEmptyCiphertext() throws IOException {
        byte[] container = readVector("expected/encrypted-one-byte.ubc");
        byte[] wrongKey = KEY.clone();
        wrongKey[0] ^= 0x01;
        DecodeOptions options = new DecodeOptions().withKey(wrongKey);
        UbcException exception = assertThrows(UbcException.class, () -> Crypto.decodeEncrypted(container, options));
        assertEquals(ErrorCode.ERR_CHUNK_AUTH, exception.code());
    }

    @Test
    void missingKeyReturnsMissingKey() throws IOException {
        byte[] container = readVector("expected/encrypted-one-byte.ubc");
        UbcException exception =
                assertThrows(UbcException.class, () -> Crypto.decodeEncrypted(container, new DecodeOptions()));
        assertEquals(ErrorCode.ERR_MISSING_KEY, exception.code());
    }

    @Test
    void negativeVectorsUseStableErrorCodes() throws IOException {
        Object[][] cases = {
            {"negative-chunk-auth.ubc", ErrorCode.ERR_CHUNK_AUTH, true},
            {"negative-encrypted-short-clen.ubc", ErrorCode.ERR_CHUNK_AUTH, true},
            {"negative-encrypted-metadata-tamper.ubc", ErrorCode.ERR_CHUNK_AUTH, true},
            {"negative-missing-key.ubc", ErrorCode.ERR_MISSING_KEY, false},
            {"negative-encrypted-cap-missing-key.ubc", ErrorCode.ERR_MISSING_KEY, false},
        };
        for (Object[] testCase : cases) {
            String name = (String) testCase[0];
            ErrorCode expected = (ErrorCode) testCase[1];
            boolean suppliesKey = (boolean) testCase[2];
            byte[] container = readVector("expected/" + name);
            DecodeOptions options = suppliesKey ? new DecodeOptions().withKey(KEY) : new DecodeOptions();
            UbcException exception =
                    assertThrows(UbcException.class, () -> Crypto.decodeEncrypted(container, options), name);
            assertEquals(expected, exception.code(), name);
        }
    }

    @Test
    void encryptedEmptyWrongKeyReturnsRootMismatch() throws IOException {
        // The container was encoded with KEY; this vector's own options.key is a different,
        // deliberately wrong key, so decoding with it must fail the keyed HMAC root check.
        byte[] container = readVector("expected/negative-encrypted-empty-wrong-key.ubc");
        byte[] wrongKey = hex("ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        DecodeOptions options = new DecodeOptions().withKey(wrongKey);
        UbcException exception = assertThrows(UbcException.class, () -> Crypto.decodeEncrypted(container, options));
        assertEquals(ErrorCode.ERR_ROOT_MISMATCH, exception.code());
    }

    @Test
    void rootKeyMatchesSharedKnownAnswer() throws IOException {
        // spec/vectors/vectors.json's top-level "cryptoKnownAnswers"[0]: a fixed key/baseNonce
        // pair with its expected HKDF-derived root_key, independent of any container vector.
        byte[] key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] baseNonce = hex("f0e0d0c0b0a0908070605040");
        byte[] expectedRootKey = hex("52c04b400d73df15d8a0db6ba58919f46fe822fff200fb50d8dee097af3c688c");
        assertArrayEquals(expectedRootKey, Crypto.rootKey(key, baseNonce));
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
