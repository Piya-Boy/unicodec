package dev.ubc.tools

import dev.ubc.support.VectorManifest
import dev.ubc.support.hex
import java.io.File
import java.security.MessageDigest
import kotlin.system.exitProcess

/**
 * Cross-decode CLI matching the other SDKs' CLIs' contract: --vectors DIR --work DIR
 * --cases a,b,c [--write | --verify]. Invoked by scripts/cross-decode.mjs so Kotlin
 * participates in the full cross-decode matrix. Compiled alongside the test sources
 * (plain kotlinc, no build tool) so it can reuse VectorManifest/MiniJson instead of
 * duplicating them — same category of workaround as every other SDK's CLI needed for its
 * own lack of a project-reference mechanism.
 */
fun main(args: Array<String>) {
    try {
        run(args)
        exitProcess(0)
    } catch (e: Exception) {
        System.err.println(e.message)
        exitProcess(1)
    }
}

private fun run(args: Array<String>) {
    val arguments = parseArguments(args)
    val manifest = VectorManifest.read(arguments.vectorsRoot)
    val canonicalKey = manifest.canonicalKey()
    val sha256 = MessageDigest.getInstance("SHA-256")

    for (id in arguments.caseIds) {
        val vector = manifest.find(id)
        if (vector.expectError != null) {
            throw IllegalStateException("negative cross-decode case is not allowed: $id")
        }
        val inputPath = vector.input ?: throw IllegalStateException("$id: positive vector has no input")
        val input = safeChild(arguments.vectorsRoot, inputPath).readBytes()
        val expected = safeChild(arguments.vectorsRoot, vector.expected).readBytes()
        sha256.reset()
        if (!MessageDigest.isEqual(sha256.digest(expected), vector.expectedSha256)) {
            throw IllegalStateException("$id: expected artifact SHA-256 differs from vectors.json")
        }

        if (arguments.write) {
            val container = vector.encode(input)
            if (!container.contentEquals(expected)) {
                throw IllegalStateException("$id: Kotlin encode differs from shared artifact")
            }
            safeChild(arguments.workDir, "$id.kotlin.ubc").writeBytes(container)
        } else {
            val key = vector.options?.key ?: canonicalKey
            for (producer in listOf("go", "node", "python", "rust", "java", "dotnet", "php", "dart", "kotlin")) {
                val container = safeChild(arguments.workDir, "$id.$producer.ubc").readBytes()
                val decoded = vector.decode(container, key)
                if (decoded.error != null) {
                    throw IllegalStateException("$id: Kotlin rejected $producer container with ${decoded.error.stableId}")
                }
                if (!decoded.data!!.contentEquals(input)) {
                    throw IllegalStateException("$id: Kotlin-decoded $producer plaintext differs from manifest input")
                }
                val expectedMetadata = vector.options?.metadata ?: emptyList()
                if (!metadataEquals(decoded.metadata!!, expectedMetadata)) {
                    throw IllegalStateException("$id: Kotlin-decoded $producer metadata differs from manifest")
                }
                val reencoded = vector.encode(decoded.data)
                if (!reencoded.contentEquals(expected)) {
                    throw IllegalStateException("$id: $producer-to-Kotlin re-encode is not byte-identical")
                }
                if (!container.contentEquals(expected)) {
                    throw IllegalStateException("$id: fresh $producer container differs from shared artifact")
                }
            }
        }
    }
}

private fun metadataEquals(actual: List<dev.ubc.MetadataEntry>, expected: List<dev.ubc.MetadataEntry>): Boolean {
    if (actual.size != expected.size) return false
    for (i in actual.indices) {
        if (actual[i].tag != expected[i].tag || !actual[i].value.contentEquals(expected[i].value)) return false
    }
    return true
}

private fun safeChild(root: File, child: String): File {
    if (child.isEmpty()) {
        throw IllegalArgumentException("manifest path must be a non-empty relative path")
    }
    val target = File(root, child).canonicalFile
    val normalizedRoot = root.canonicalFile.path + File.separator
    if (!target.path.startsWith(normalizedRoot)) {
        throw IllegalArgumentException("manifest path escapes vectors root: $child")
    }
    return target
}

private fun safeId(id: String): Boolean = Regex("^[a-z0-9]+(-[a-z0-9]+)*$").matches(id)

private fun existingDirectory(path: String?, label: String): File {
    if (path.isNullOrEmpty()) {
        throw IllegalArgumentException("--$label is required")
    }
    val resolved = File(path).canonicalFile
    if (!resolved.isDirectory) {
        throw IllegalArgumentException("$label path is not a directory")
    }
    return resolved
}

private class Arguments(val vectorsRoot: File, val workDir: File, val caseIds: List<String>, val write: Boolean)

private fun parseArguments(args: Array<String>): Arguments {
    var vectorsRoot: String? = null
    var workDir: String? = null
    var cases: String? = null
    var write: Boolean? = null
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--vectors" -> vectorsRoot = args[++i]
            "--work" -> workDir = args[++i]
            "--cases" -> cases = args[++i]
            "--write" -> {
                if (write != null) throw IllegalArgumentException("--write/--verify specified more than once")
                write = true
            }
            "--verify" -> {
                if (write != null) throw IllegalArgumentException("--write/--verify specified more than once")
                write = false
            }
            else -> throw IllegalArgumentException("unexpected argument: ${args[i]}")
        }
        i++
    }
    val resolvedVectorsRoot = existingDirectory(vectorsRoot, "vectors")
    val resolvedWorkDir = existingDirectory(workDir, "work")
    if (cases == null) throw IllegalArgumentException("--cases is required")
    if (write == null) throw IllegalArgumentException("exactly one of --write or --verify is required")
    val seen = mutableSetOf<String>()
    val caseIds = mutableListOf<String>()
    for (id in cases.split(",")) {
        if (!safeId(id) || !seen.add(id)) {
            throw IllegalArgumentException("unsafe or duplicate case id: $id")
        }
        caseIds.add(id)
    }
    if (caseIds.isEmpty()) throw IllegalArgumentException("--cases must not be empty")
    return Arguments(resolvedVectorsRoot, resolvedWorkDir, caseIds, write)
}
