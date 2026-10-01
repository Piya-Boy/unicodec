using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Ubc;

/// <summary>One-shot plain (non-encrypted) UBC v1 encoding and decoding (SPEC.md sections 2-4).</summary>
public static class Payload
{
    public const uint DefaultChunkSize = 1 << 20;
    private const int FooterSize = 36;
    private static readonly byte[] FooterMagic = { (byte)'U', (byte)'B', (byte)'C', (byte)'E' };

    public static byte[] EncodePlain(ReadOnlySpan<byte> data, IReadOnlyList<MetadataEntry> entries, ulong chunkSize)
    {
        if (chunkSize == 0 || chunkSize > uint.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "chunkSize must be a positive uint32");
        }
        byte[] metadata = Metadata.Encode(entries);
        ulong dataLength = (ulong)data.Length;
        ulong chunkCount = dataLength == 0 ? 0 : (dataLength + chunkSize - 1) / chunkSize;

        var header = new Header(
            (byte)(metadata.Length > 0 ? Header.FlagHasMetadata : 0),
            Header.HashSha256,
            Header.AeadNone,
            chunkSize,
            chunkCount,
            dataLength,
            stackalloc byte[12]);
        byte[] headerBytes = header.ToBytes();

        using var output = new MemoryStream();
        output.Write(headerBytes);
        output.Write(metadata);

        using var root = SHA256.Create();
        root.TransformBlock(headerBytes, 0, headerBytes.Length, null, 0);
        root.TransformBlock(metadata, 0, metadata.Length, null, 0);

        Span<byte> clenBuffer = stackalloc byte[4];
        for (ulong offset = 0; offset < dataLength; offset += chunkSize)
        {
            int intOffset = (int)offset;
            int length = (int)Math.Min(chunkSize, dataLength - offset);
            var chunk = data.Slice(intOffset, length);
            BinaryPrimitives.WriteUInt32LittleEndian(clenBuffer, (uint)length);
            output.Write(clenBuffer);
            output.Write(chunk);
            byte[] chunkHash = SHA256.HashData(chunk);
            root.TransformBlock(chunkHash, 0, chunkHash.Length, null, 0);
        }

        root.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        output.Write(root.Hash!);
        output.Write(FooterMagic);
        return output.ToArray();
    }

    public static DecodeResult DecodePlain(ReadOnlySpan<byte> container, DecodeOptions? options)
    {
        var opts = options ?? new DecodeOptions();

        var header = Header.Parse(container);
        ReadOnlySpan<byte> headerBytes = container[..Header.Size];
        int offset = Header.Size;

        List<MetadataEntry> entries = new();
        ReadOnlySpan<byte> metadataRegion = ReadOnlySpan<byte>.Empty;
        if (header.HasMetadata)
        {
            var result = Metadata.Parse(container[offset..], BoundedCap(opts.MaxMetaBytes));
            entries = result.Entries;
            metadataRegion = container.Slice(offset, result.Consumed);
            offset += result.Consumed;
        }

        if (header.Encrypted)
        {
            throw new UbcException(ErrorCode.ErrMissingKey);
        }
        if (header.ChunkCount > opts.MaxChunkCount || header.TotalSize > opts.MaxTotalSize)
        {
            throw new UbcException(ErrorCode.ErrTruncated);
        }

        using var root = SHA256.Create();
        root.TransformBlock(headerBytes.ToArray(), 0, headerBytes.Length, null, 0);
        byte[] metadataRegionArray = metadataRegion.ToArray();
        root.TransformBlock(metadataRegionArray, 0, metadataRegionArray.Length, null, 0);

        using var plaintext = new MemoryStream();
        ulong remaining = header.TotalSize;
        for (ulong i = 0; i < header.ChunkCount; i++)
        {
            if ((ulong)(container.Length - offset) < 4)
            {
                throw new UbcException(ErrorCode.ErrTruncated);
            }
            uint chunkLength = BinaryPrimitives.ReadUInt32LittleEndian(container.Slice(offset, 4));
            offset += 4;
            if (chunkLength > opts.MaxChunkLen || chunkLength > (ulong)(container.Length - offset))
            {
                throw new UbcException(ErrorCode.ErrTruncated);
            }
            if (chunkLength > remaining)
            {
                throw new UbcException(ErrorCode.ErrRootMismatch);
            }
            var chunk = container.Slice(offset, (int)chunkLength);
            byte[] chunkHash = SHA256.HashData(chunk);
            root.TransformBlock(chunkHash, 0, chunkHash.Length, null, 0);
            plaintext.Write(chunk);
            offset += (int)chunkLength;
            remaining -= chunkLength;
        }

        if ((ulong)(container.Length - offset) < FooterSize)
        {
            throw new UbcException(ErrorCode.ErrTruncated);
        }
        var footerRoot = container.Slice(offset, 32);
        var footerMagic = container.Slice(offset + 32, 4);
        if (!footerMagic.SequenceEqual(FooterMagic))
        {
            throw new UbcException(ErrorCode.ErrTruncated);
        }
        root.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        byte[] plaintextBytes = plaintext.ToArray();
        if ((ulong)plaintextBytes.Length != header.TotalSize || !CryptographicOperations.FixedTimeEquals(footerRoot, root.Hash!))
        {
            throw new UbcException(ErrorCode.ErrRootMismatch);
        }
        if (container.Length != offset + FooterSize)
        {
            throw new UbcException(ErrorCode.ErrTrailingData);
        }
        return new DecodeResult(plaintextBytes, entries);
    }

    private static uint? BoundedCap(ulong cap) => cap > uint.MaxValue ? uint.MaxValue : (uint)cap;
}
