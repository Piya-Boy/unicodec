package dev.ubc.support;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Cross-decode CLI matching the Rust example's contract: {@code --vectors DIR --work DIR
 * --cases a,b,c [--write | --verify]}. Invoked by scripts/cross-decode.mjs via {@code mvn
 * -q exec:java} so Java participates in the Go/Node/Python/Rust/Java cross-decode matrix.
 */
public final class CrossDecodeCli {
    private CrossDecodeCli() {
    }

    public static void main(String[] args) {
        try {
            run(args);
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    private static void run(String[] args) throws IOException, NoSuchAlgorithmException {
        Arguments arguments = parseArguments(args);
        VectorManifest manifest = VectorManifest.read(arguments.vectorsRoot);
        byte[] canonicalKey = manifest.canonicalKey();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        for (String id : arguments.caseIds) {
            VectorManifest.Vector vector = find(manifest, id);
            if (vector.expectError != null) {
                throw new IllegalStateException("negative cross-decode case is not allowed: " + id);
            }
            if (vector.input == null) {
                throw new IllegalStateException(id + ": positive vector has no input");
            }
            byte[] input = Files.readAllBytes(safeChild(arguments.vectorsRoot, vector.input));
            byte[] expected = Files.readAllBytes(safeChild(arguments.vectorsRoot, vector.expected));
            sha256.reset();
            if (!MessageDigest.isEqual(sha256.digest(expected), vector.expectedSha256)) {
                throw new IllegalStateException(id + ": expected artifact SHA-256 differs from vectors.json");
            }

            if (arguments.write) {
                byte[] container = vector.encode(input);
                if (!java.util.Arrays.equals(container, expected)) {
                    throw new IllegalStateException(id + ": Java encode differs from shared artifact");
                }
                Path outPath = safeChild(arguments.workDir, id + ".java.ubc");
                Files.write(outPath, container);
            } else {
                byte[] key = vector.options != null && vector.options.key != null ? vector.options.key : canonicalKey;
                for (String producer : List.of("go", "node", "python", "rust", "java")) {
                    Path containerPath = safeChild(arguments.workDir, id + "." + producer + ".ubc");
                    byte[] container = Files.readAllBytes(containerPath);
                    VectorManifest.DecodedVector decoded = vector.decode(container, key);
                    if (decoded.error != null) {
                        throw new IllegalStateException(
                                id + ": Java rejected " + producer + " container with " + decoded.error);
                    }
                    if (!java.util.Arrays.equals(decoded.data, input)) {
                        throw new IllegalStateException(
                                id + ": Java-decoded " + producer + " plaintext differs from manifest input");
                    }
                    List<dev.ubc.MetadataEntry> expectedMetadata =
                            vector.options != null ? vector.options.metadata : List.of();
                    if (!metadataEquals(decoded.metadata, expectedMetadata)) {
                        throw new IllegalStateException(id + ": Java-decoded " + producer + " metadata differs from manifest");
                    }
                    byte[] reencoded = vector.encode(decoded.data);
                    if (!java.util.Arrays.equals(reencoded, expected)) {
                        throw new IllegalStateException(id + ": " + producer + "-to-Java re-encode is not byte-identical");
                    }
                    if (!java.util.Arrays.equals(container, expected)) {
                        throw new IllegalStateException(
                                id + ": fresh " + producer + " container differs from shared artifact");
                    }
                }
            }
        }
    }

    private static boolean metadataEquals(List<dev.ubc.MetadataEntry> actual, List<dev.ubc.MetadataEntry> expected) {
        if (actual.size() != expected.size()) {
            return false;
        }
        for (int i = 0; i < actual.size(); i++) {
            if (actual.get(i).tag != expected.get(i).tag
                    || !java.util.Arrays.equals(actual.get(i).value, expected.get(i).value)) {
                return false;
            }
        }
        return true;
    }

    private static VectorManifest.Vector find(VectorManifest manifest, String id) {
        for (VectorManifest.Vector vector : manifest.vectors) {
            if (vector.id.equals(id)) {
                return vector;
            }
        }
        throw new IllegalStateException("manifest vector is missing: " + id);
    }

    private static Path safeChild(Path root, String child) {
        if (child == null || child.isEmpty()) {
            throw new IllegalArgumentException("manifest path must be a non-empty relative path");
        }
        Path target = root.resolve(child).normalize();
        if (!target.startsWith(root)) {
            throw new IllegalArgumentException("manifest path escapes vectors root: " + child);
        }
        return target;
    }

    private record Arguments(Path vectorsRoot, Path workDir, List<String> caseIds, boolean write) {
    }

    private static Arguments parseArguments(String[] args) throws IOException {
        Path vectorsRoot = null;
        Path workDir = null;
        String cases = null;
        Boolean write = null;
        int i = 0;
        while (i < args.length) {
            String argument = args[i];
            switch (argument) {
                case "--vectors" -> vectorsRoot = Path.of(args[++i]);
                case "--work" -> workDir = Path.of(args[++i]);
                case "--cases" -> cases = args[++i];
                case "--write" -> {
                    if (write != null) {
                        throw new IllegalArgumentException("--write/--verify specified more than once");
                    }
                    write = true;
                }
                case "--verify" -> {
                    if (write != null) {
                        throw new IllegalArgumentException("--write/--verify specified more than once");
                    }
                    write = false;
                }
                default -> throw new IllegalArgumentException("unexpected argument: " + argument);
            }
            i++;
        }
        vectorsRoot = existingDirectory(vectorsRoot, "vectors");
        workDir = existingDirectory(workDir, "work");
        if (cases == null) {
            throw new IllegalArgumentException("--cases is required");
        }
        if (write == null) {
            throw new IllegalArgumentException("exactly one of --write or --verify is required");
        }
        Set<String> seen = new LinkedHashSet<>();
        List<String> caseIds = new ArrayList<>();
        for (String id : cases.split(",", -1)) {
            if (!safeId(id) || !seen.add(id)) {
                throw new IllegalArgumentException("unsafe or duplicate case id: " + id);
            }
            caseIds.add(id);
        }
        if (caseIds.isEmpty()) {
            throw new IllegalArgumentException("--cases must not be empty");
        }
        return new Arguments(vectorsRoot, workDir, caseIds, write);
    }

    private static boolean safeId(String id) {
        return id != null && id.matches("[a-z0-9]+(-[a-z0-9]+)*");
    }

    private static Path existingDirectory(Path path, String label) throws IOException {
        if (path == null) {
            throw new IllegalArgumentException("--" + label + " is required");
        }
        Path resolved = path.toRealPath();
        if (!Files.isDirectory(resolved)) {
            throw new IllegalArgumentException(label + " path is not a directory");
        }
        return resolved;
    }
}
