namespace Ubc;

/// <summary>Header and metadata summary returned by Streaming.Inspect.</summary>
public sealed class ContainerInfo
{
    public int Version { get; }
    public bool Encrypted { get; }
    public bool HasMetadata { get; }
    public byte HashAlgo { get; }
    public byte AeadAlgo { get; }
    public ulong ChunkSize { get; }
    public ulong ChunkCount { get; }
    public ulong TotalSize { get; }
    public List<MetadataEntry> Metadata { get; }

    public ContainerInfo(int version, bool encrypted, bool hasMetadata, byte hashAlgo, byte aeadAlgo,
        ulong chunkSize, ulong chunkCount, ulong totalSize, List<MetadataEntry> metadata)
    {
        Version = version;
        Encrypted = encrypted;
        HasMetadata = hasMetadata;
        HashAlgo = hashAlgo;
        AeadAlgo = aeadAlgo;
        ChunkSize = chunkSize;
        ChunkCount = chunkCount;
        TotalSize = totalSize;
        Metadata = metadata;
    }
}
