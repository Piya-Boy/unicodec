package dev.ubc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.ubc.support.VectorManifest;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Drives every vector in spec/vectors/vectors.json through the Java SDK — the manifest is the contract. */
final class ConformanceTest {

    @Test
    void everyShareManifestVectorConforms() throws IOException, NoSuchAlgorithmException {
        var root = VectorManifest.vectorsRoot();
        var manifest = VectorManifest.read(root);
        byte[] canonicalKey = manifest.canonicalKey();
        int positiveCount = 0;
        int negativeCount = 0;
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        for (VectorManifest.Vector vector : manifest.vectors) {
            byte[] expected = Files.readAllBytes(root.resolve(vector.expected));
            sha256.reset();
            assertArrayEquals(vector.expectedSha256, sha256.digest(expected),
                    vector.id + ": expected artifact SHA-256 differs from vectors.json");

            if (vector.expectError != null) {
                negativeCount++;
                byte[] vectorKey = vector.options != null ? vector.options.key : null;
                byte[] decodeKey = requiresKey(vector) ? (vectorKey != null ? vectorKey : canonicalKey) : null;
                VectorManifest.DecodedVector decoded = vector.decode(expected, decodeKey);
                assertTrue(decoded.error != null, vector.id + ": negative vector must not decode successfully");
                assertEquals(vector.expectError, decoded.error.name(), vector.id + ": stable error id differs");
                continue;
            }

            positiveCount++;
            byte[] input = Files.readAllBytes(root.resolve(vector.input));
            byte[] encoded = vector.encode(input);
            assertArrayEquals(expected, encoded, vector.id + ": encoded container differs from vectors.json artifact");

            byte[] key = vector.options.key;
            VectorManifest.DecodedVector decoded = vector.decode(expected, key);
            assertTrue(decoded.error == null, vector.id + ": decode failed with " + decoded.error);
            assertArrayEquals(input, decoded.data, vector.id + ": decoded plaintext differs");
            List<MetadataEntry> expectedMetadata = vector.options.metadata;
            assertEquals(expectedMetadata.size(), decoded.metadata.size(), vector.id + ": decoded metadata count differs");
            for (int i = 0; i < expectedMetadata.size(); i++) {
                assertEquals(expectedMetadata.get(i).tag, decoded.metadata.get(i).tag, vector.id + ": metadata tag " + i);
                assertArrayEquals(expectedMetadata.get(i).value, decoded.metadata.get(i).value,
                        vector.id + ": metadata value " + i);
            }
        }

        assertTrue(positiveCount > 0, "manifest must contain positive vectors");
        assertTrue(negativeCount > 0, "manifest must contain negative vectors");
    }

    // Negative vectors whose own point is "decoded without a key" must actually be decoded
    // without one; every other negative vector decodes with the canonical/vector-supplied key
    // so a missing-key short-circuit doesn't mask the error the vector is meant to exercise.
    private static boolean requiresKey(VectorManifest.Vector vector) {
        return !vector.id.equals("negative-missing-key") && !vector.id.equals("negative-encrypted-cap-missing-key");
    }
}
