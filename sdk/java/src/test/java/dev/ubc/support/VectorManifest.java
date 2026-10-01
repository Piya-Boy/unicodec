package dev.ubc.support;

import dev.ubc.Crypto;
import dev.ubc.ErrorCode;
import dev.ubc.MetadataEntry;
import dev.ubc.Payload;
import dev.ubc.UbcException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Reads spec/vectors/vectors.json and encodes/decodes vectors through the Java SDK. */
public final class VectorManifest {
    public final List<Vector> vectors;

    private VectorManifest(List<Vector> vectors) {
        this.vectors = vectors;
    }

    public static Path vectorsRoot() {
        return Path.of(System.getProperty("user.dir"), "..", "..", "spec", "vectors").normalize();
    }

    public static VectorManifest read(Path vectorsRoot) throws IOException {
        byte[] bytes = Files.readAllBytes(vectorsRoot.resolve("vectors.json"));
        Map<String, Object> root = MiniJson.object(MiniJson.parse(bytes));
        List<Object> rawVectors = MiniJson.array(root.get("vectors"));
        List<Vector> vectors = new ArrayList<>();
        for (Object rawVector : rawVectors) {
            vectors.add(Vector.from(MiniJson.object(rawVector)));
        }
        return new VectorManifest(vectors);
    }

    /** The key shared by every encrypted positive vector, used to decode negative vectors that omit options. */
    public byte[] canonicalKey() {
        for (Vector vector : vectors) {
            if (vector.expectError == null && vector.options != null && vector.options.key != null) {
                return vector.options.key;
            }
        }
        throw new IllegalStateException("manifest has no encrypted positive vector");
    }

    public static final class Vector {
        public final String id;
        public final String input;
        public final Options options;
        public final String expected;
        public final byte[] expectedSha256;
        public final String expectError;

        private Vector(String id, String input, Options options, String expected, byte[] expectedSha256,
                String expectError) {
            this.id = id;
            this.input = input;
            this.options = options;
            this.expected = expected;
            this.expectedSha256 = expectedSha256;
            this.expectError = expectError;
        }

        private static Vector from(Map<String, Object> raw) {
            String id = MiniJson.string(raw.get("id"));
            Object inputValue = raw.get("input");
            String input = inputValue == null ? null : MiniJson.string(inputValue);
            Object optionsValue = raw.get("options");
            Options options = optionsValue == null ? null : Options.from(MiniJson.object(optionsValue));
            String expected = MiniJson.string(raw.get("expected"));
            byte[] expectedSha256 = hex(MiniJson.string(raw.get("expectedSha256")));
            Object expectErrorValue = raw.get("expectError");
            String expectError = expectErrorValue == null ? null : MiniJson.string(expectErrorValue);
            return new Vector(id, input, options, expected, expectedSha256, expectError);
        }

        /** Encodes this vector's input through the Java SDK using its declared options. */
        public byte[] encode(byte[] inputBytes) {
            if (options == null) {
                throw new IllegalStateException(id + ": positive vector has no options");
            }
            if (options.key != null && options.baseNonce != null) {
                return Crypto.encodeEncryptedWithFixedNonce(
                        inputBytes, options.key, options.baseNonce, options.metadata, options.chunkSize);
            }
            if (options.key == null && options.baseNonce == null) {
                return Payload.encodePlain(inputBytes, options.metadata, options.chunkSize);
            }
            throw new IllegalStateException(id + ": key and baseNonce must be paired");
        }

        /**
         * Decodes a container, auto-detecting plain vs encrypted from the header itself
         * (mirrors Go's single DecodeBytes entry point) rather than trusting the caller's
         * guess — a malformed/negative-vector header may not match what the vector's own
         * options imply, and the two one-shot decoders dispatch on different field sets.
         * {@code key} is used only if the container turns out to be encrypted.
         */
        public DecodedVector decode(byte[] container, byte[] key) {
            try {
                boolean encrypted = dev.ubc.Header.parse(container, 0).encrypted();
                if (encrypted) {
                    var result = Crypto.decodeEncrypted(container, new dev.ubc.DecodeOptions().withKey(key));
                    return new DecodedVector(result.data, result.metadata, null);
                }
                var result = Payload.decodePlain(container, null);
                return new DecodedVector(result.data, result.metadata, null);
            } catch (UbcException e) {
                return new DecodedVector(null, null, e.code());
            }
        }
    }

    public static final class Options {
        public final long chunkSize;
        public final byte[] key;
        public final byte[] baseNonce;
        public final List<MetadataEntry> metadata;

        private Options(long chunkSize, byte[] key, byte[] baseNonce, List<MetadataEntry> metadata) {
            this.chunkSize = chunkSize;
            this.key = key;
            this.baseNonce = baseNonce;
            this.metadata = metadata;
        }

        private static Options from(Map<String, Object> raw) {
            long chunkSize = MiniJson.number(raw.get("chunkSize"));
            Object keyValue = raw.get("key");
            byte[] key = keyValue == null ? null : hex(MiniJson.string(keyValue));
            Object nonceValue = raw.get("baseNonce");
            byte[] baseNonce = nonceValue == null ? null : hex(MiniJson.string(nonceValue));
            List<MetadataEntry> metadata = new ArrayList<>();
            Object metadataValue = raw.get("metadata");
            if (metadataValue != null) {
                for (Object rawEntry : MiniJson.array(metadataValue)) {
                    Map<String, Object> entry = MiniJson.object(rawEntry);
                    String tagHex = MiniJson.string(entry.get("tag"));
                    int tag = Integer.parseInt(tagHex.substring(2), 16);
                    byte[] value = hex(MiniJson.string(entry.get("valueHex")));
                    metadata.add(new MetadataEntry(tag, value));
                }
            }
            return new Options(chunkSize, key, baseNonce, metadata);
        }
    }

    public static final class DecodedVector {
        public final byte[] data;
        public final List<MetadataEntry> metadata;
        public final ErrorCode error;

        private DecodedVector(byte[] data, List<MetadataEntry> metadata, ErrorCode error) {
            this.data = data;
            this.metadata = metadata;
            this.error = error;
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
