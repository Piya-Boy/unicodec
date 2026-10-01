using System.Buffers.Binary;

namespace Ubc;

/// <summary>UBC v1 fixed 40-byte header (SPEC.md section 2.1).</summary>
public sealed class Header
{
    public const int Size = 40;
    public const int Version = 1;

    public const byte HashSha256 = 0;
    public const byte HashHmacSha256 = 1;
    public const byte AeadNone = 0;
    public const byte AeadAes256Gcm = 1;

    public const byte FlagEncrypted = 1;
    public const byte FlagHasMetadata = 1 << 1;

    private static readonly byte[] Magic = { (byte)'U', (byte)'B', (byte)'C', (byte)'1' };
    private const byte AllowedFlags = FlagEncrypted | FlagHasMetadata;
    private const uint MaxEncryptedChunkSize = 0xFFFF_FFEF;

    public byte Flags { get; }
    public byte HashAlgo { get; }
    public byte AeadAlgo { get; }
    public ulong ChunkSize { get; }
    public ulong ChunkCount { get; }
    public ulong TotalSize { get; }
    private readonly byte[] _baseNonce;

    public Header(byte flags, byte hashAlgo, byte aeadAlgo, ulong chunkSize, ulong chunkCount, ulong totalSize,
        ReadOnlySpan<byte> baseNonce)
    {
        Flags = flags;
        HashAlgo = hashAlgo;
        AeadAlgo = aeadAlgo;
        ChunkSize = chunkSize;
        ChunkCount = chunkCount;
        TotalSize = totalSize;
        _baseNonce = baseNonce.ToArray();
        Validate();
    }

    /// <summary>A defensive copy; mutating the result cannot affect this header's invariants.</summary>
    public byte[] BaseNonce() => (byte[])_baseNonce.Clone();

    public bool Encrypted => (Flags & FlagEncrypted) != 0;
    public bool HasMetadata => (Flags & FlagHasMetadata) != 0;

    public byte[] ToBytes()
    {
        var buffer = new byte[Size];
        Magic.CopyTo(buffer, 0);
        buffer[4] = Version;
        buffer[5] = Flags;
        buffer[6] = HashAlgo;
        buffer[7] = AeadAlgo;
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(8, 4), (uint)ChunkSize);
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(12, 8), ChunkCount);
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(20, 8), TotalSize);
        _baseNonce.CopyTo(buffer, 28);
        return buffer;
    }

    public static Header Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < Size)
        {
            throw new UbcException(ErrorCode.ErrTruncated);
        }
        if (!data[..4].SequenceEqual(Magic))
        {
            throw new UbcException(ErrorCode.ErrBadMagic);
        }

        byte version = data[4];
        byte flags = data[5];
        byte hashAlgo = data[6];
        byte aeadAlgo = data[7];
        uint chunkSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8, 4));
        ulong chunkCount = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(12, 8));
        ulong totalSize = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(20, 8));
        ReadOnlySpan<byte> baseNonce = data.Slice(28, 12);

        if (version != Version)
        {
            throw new UbcException(ErrorCode.ErrUnsupportedVer);
        }
        return new Header(flags, hashAlgo, aeadAlgo, chunkSize, chunkCount, totalSize, baseNonce);
    }

    private void Validate()
    {
        if (HashAlgo != HashSha256 && HashAlgo != HashHmacSha256)
        {
            throw new UbcException(ErrorCode.ErrUnsupportedAlgo);
        }
        if (AeadAlgo != AeadNone && AeadAlgo != AeadAes256Gcm)
        {
            throw new UbcException(ErrorCode.ErrUnsupportedAlgo);
        }
        if ((Flags & ~AllowedFlags) != 0)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
        if (ChunkSize > uint.MaxValue)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
        // ChunkCount and TotalSize are true uint64 (ulong in .NET, which is natively unsigned —
        // unlike Java's signed long, no special-cased comparisons are needed here).
        if (_baseNonce.Length != 12)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }

        if (Encrypted)
        {
            if (AeadAlgo != AeadAes256Gcm || HashAlgo != HashHmacSha256 || ChunkSize == 0
                || ChunkSize > MaxEncryptedChunkSize)
            {
                throw new UbcException(ErrorCode.ErrReservedBits);
            }
            return;
        }
        Span<byte> zeroNonce = stackalloc byte[12];
        if (AeadAlgo != AeadNone || HashAlgo != HashSha256 || ChunkSize == 0 || !_baseNonce.AsSpan().SequenceEqual(zeroNonce))
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
    }
}
