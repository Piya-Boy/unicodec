namespace Ubc;

/// <summary>
/// Options for a streaming Encoder. <see cref="BaseNonce"/> exists only for deterministic
/// conformance tests; production callers must leave it null so a CSPRNG nonce is generated.
/// </summary>
public sealed class EncodeOptions
{
    public ulong ChunkSize { get; }
    public byte[]? Key { get; }
    public byte[]? BaseNonce { get; }

    public EncodeOptions()
        : this(Payload.DefaultChunkSize, null, null)
    {
    }

    public EncodeOptions(ulong chunkSize, byte[]? key, byte[]? baseNonce)
    {
        if (chunkSize == 0 || chunkSize > uint.MaxValue)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
        if (key is not null && key.Length != 32)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
        if (baseNonce is not null && baseNonce.Length != 12)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
        if (key is null && baseNonce is not null)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
        ChunkSize = chunkSize;
        Key = key is null ? null : (byte[])key.Clone();
        BaseNonce = baseNonce is null ? null : (byte[])baseNonce.Clone();
    }

    public EncodeOptions WithKey(byte[]? key) => new(ChunkSize, key, BaseNonce);

    public EncodeOptions WithChunkSize(ulong chunkSize) => new(chunkSize, Key, BaseNonce);
}
