namespace Ubc;

/// <summary>Resource limits applied while decoding untrusted containers.</summary>
public sealed class DecodeOptions
{
    public const ulong DefaultMaxMetaBytes = 16UL << 20;
    public const ulong DefaultMaxChunkLen = 64UL << 20;
    public const ulong DefaultMaxChunkCount = 1UL << 20;
    public const ulong DefaultMaxTotalSize = 1UL << 30;

    public ulong MaxMetaBytes { get; }
    public ulong MaxChunkLen { get; }
    public ulong MaxChunkCount { get; }
    public ulong MaxTotalSize { get; }
    private readonly byte[]? _key;

    public DecodeOptions()
        : this(DefaultMaxMetaBytes, DefaultMaxChunkLen, DefaultMaxChunkCount, DefaultMaxTotalSize, null)
    {
    }

    public DecodeOptions(ulong maxMetaBytes, ulong maxChunkLen, ulong maxChunkCount, ulong maxTotalSize, byte[]? key)
    {
        MaxMetaBytes = maxMetaBytes;
        MaxChunkLen = maxChunkLen;
        MaxChunkCount = maxChunkCount;
        MaxTotalSize = maxTotalSize;
        _key = key is null ? null : (byte[])key.Clone();
    }

    public DecodeOptions WithKey(byte[]? key) => new(MaxMetaBytes, MaxChunkLen, MaxChunkCount, MaxTotalSize, key);

    public byte[]? Key() => _key is null ? null : (byte[])_key.Clone();
}
