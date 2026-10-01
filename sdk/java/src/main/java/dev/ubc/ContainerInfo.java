package dev.ubc;

import java.util.List;

/** Header and metadata summary returned by {@link Streaming#inspect}. */
public final class ContainerInfo {
    public final int version;
    public final boolean encrypted;
    public final boolean hasMetadata;
    public final int hashAlgo;
    public final int aeadAlgo;
    public final long chunkSize;
    public final long chunkCount;
    public final long totalSize;
    public final List<MetadataEntry> metadata;

    public ContainerInfo(int version, boolean encrypted, boolean hasMetadata, int hashAlgo, int aeadAlgo,
            long chunkSize, long chunkCount, long totalSize, List<MetadataEntry> metadata) {
        this.version = version;
        this.encrypted = encrypted;
        this.hasMetadata = hasMetadata;
        this.hashAlgo = hashAlgo;
        this.aeadAlgo = aeadAlgo;
        this.chunkSize = chunkSize;
        this.chunkCount = chunkCount;
        this.totalSize = totalSize;
        this.metadata = metadata;
    }
}
