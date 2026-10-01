package dev.ubc

/** Header and metadata summary returned by Streaming.inspect. */
class ContainerInfo(
    val version: Int,
    val encrypted: Boolean,
    val hasMetadata: Boolean,
    val hashAlgo: Int,
    val aeadAlgo: Int,
    val chunkSize: Long,
    val chunkCount: Long,
    val totalSize: Long,
    val metadata: List<MetadataEntry>,
)
