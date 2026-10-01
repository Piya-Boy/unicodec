using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Ubc;

/// <summary>One-shot AES-256-GCM encrypted UBC v1 encoding and decoding (SPEC.md sections 3-4).</summary>
public static class Crypto
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int FooterSize = 36;
    private static readonly byte[] FooterMagic = { (byte)'U', (byte)'B', (byte)'C', (byte)'E' };

    /// <summary>Encodes with a CSPRNG-generated base_nonce. Production callers MUST use this.</summary>
    public static byte[] EncodeEncrypted(ReadOnlySpan<byte> data, byte[] key, IReadOnlyList<MetadataEntry> entries, ulong chunkSize)
    {
        var baseNonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(baseNonce);
        return EncodeEncryptedWithFixedNonce(data, key, baseNonce, entries, chunkSize);
    }

    /// <summary>Deterministic encoding for conformance vectors/tests only — never reuse a base_nonce in production.</summary>
    public static byte[] EncodeEncryptedWithFixedNonce(
        ReadOnlySpan<byte> data, byte[] key, byte[] baseNonce, IReadOnlyList<MetadataEntry> entries, ulong chunkSize)
    {
        ValidateEncodeKey(key);
        if (baseNonce is null || baseNonce.Length != NonceSize)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
        if (chunkSize == 0 || chunkSize > 0xFFFF_FFEF)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "chunkSize must be a positive uint32 <= 0xffff_ffef when encrypted");
        }

        byte[] metadata = Metadata.Encode(entries);
        ulong dataLength = (ulong)data.Length;
        ulong chunkCount = dataLength == 0 ? 0 : (dataLength + chunkSize - 1) / chunkSize;

        var header = new Header(
            (byte)(Header.FlagEncrypted | (metadata.Length > 0 ? Header.FlagHasMetadata : 0)),
            Header.HashHmacSha256,
            Header.AeadAes256Gcm,
            chunkSize,
            chunkCount,
            dataLength,
            baseNonce);
        byte[] headerBytes = header.ToBytes();
        byte[] metadataDigest = CryptoInternal.Sha256(metadata);

        using var root = RootAccumulator.Keyed(CryptoInternal.RootKey(key, baseNonce));
        root.Update(headerBytes);
        root.Update(metadata);

        using var output = new MemoryStream();
        output.Write(headerBytes);
        output.Write(metadata);

        Span<byte> clenBuffer = stackalloc byte[4];
        ulong index = 0;
        for (ulong offset = 0; offset < dataLength; offset += chunkSize, index++)
        {
            int intOffset = (int)offset;
            int length = (int)Math.Min(chunkSize, dataLength - offset);
            byte[] aad = CryptoInternal.ChunkAad(headerBytes, metadataDigest, index);
            byte[] ciphertext = CryptoInternal.GcmEncrypt(key, CryptoInternal.ChunkNonce(baseNonce, index), data.Slice(intOffset, length), aad);
            BinaryPrimitives.WriteUInt32LittleEndian(clenBuffer, (uint)ciphertext.Length);
            output.Write(clenBuffer);
            output.Write(ciphertext);
            root.Update(CryptoInternal.Sha256(ciphertext));
        }

        output.Write(root.Finish());
        output.Write(FooterMagic);
        return output.ToArray();
    }

    public static DecodeResult DecodeEncrypted(ReadOnlySpan<byte> container, DecodeOptions? options)
    {
        var opts = options ?? new DecodeOptions();
        byte[]? key = opts.Key();

        var header = Header.Parse(container);
        byte[] headerBytes = container[..Header.Size].ToArray();
        int offset = Header.Size;

        List<MetadataEntry> entries = new();
        byte[] metadataRegion = Array.Empty<byte>();
        if (header.HasMetadata)
        {
            var result = Metadata.Parse(container[offset..], BoundedCap(opts.MaxMetaBytes));
            entries = result.Entries;
            metadataRegion = container.Slice(offset, result.Consumed).ToArray();
            offset += result.Consumed;
        }

        if (!header.Encrypted || key is null || key.Length != KeySize)
        {
            throw new UbcException(ErrorCode.ErrMissingKey);
        }
        if (header.ChunkCount > opts.MaxChunkCount || header.TotalSize > opts.MaxTotalSize)
        {
            throw new UbcException(ErrorCode.ErrTruncated);
        }

        byte[] metadataDigest = CryptoInternal.Sha256(metadataRegion);
        byte[] baseNonce = header.BaseNonce();
        using var root = RootAccumulator.Keyed(CryptoInternal.RootKey(key, baseNonce));
        root.Update(headerBytes);
        root.Update(metadataRegion);

        using var plaintext = new MemoryStream();
        ulong remaining = header.TotalSize;
        ulong index = 0;
        for (ulong i = 0; i < header.ChunkCount; i++, index++)
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
            var body = container.Slice(offset, (int)chunkLength);
            root.Update(CryptoInternal.Sha256(body));
            if (chunkLength < CryptoInternal.GcmTagSize)
            {
                throw new UbcException(ErrorCode.ErrChunkAuth);
            }
            byte[] plaintextChunk;
            try
            {
                plaintextChunk = CryptoInternal.GcmDecrypt(key, CryptoInternal.ChunkNonce(baseNonce, index), body,
                    CryptoInternal.ChunkAad(headerBytes, metadataDigest, index));
            }
            catch (AuthenticationTagMismatchException)
            {
                throw new UbcException(ErrorCode.ErrChunkAuth);
            }
            offset += (int)chunkLength;
            if ((ulong)plaintextChunk.Length > remaining)
            {
                throw new UbcException(ErrorCode.ErrRootMismatch);
            }
            plaintext.Write(plaintextChunk);
            remaining -= (ulong)plaintextChunk.Length;
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
        byte[] plaintextBytes = plaintext.ToArray();
        if ((ulong)plaintextBytes.Length != header.TotalSize || !CryptographicOperations.FixedTimeEquals(footerRoot, root.Finish()))
        {
            throw new UbcException(ErrorCode.ErrRootMismatch);
        }
        if (container.Length != offset + FooterSize)
        {
            throw new UbcException(ErrorCode.ErrTrailingData);
        }
        return new DecodeResult(plaintextBytes, entries);
    }

    /// <summary>Internal: exposed only so conformance tests can check this against the shared known-answer fixture.</summary>
    internal static byte[] RootKeyForTesting(byte[] key, byte[] baseNonce) => CryptoInternal.RootKey(key, baseNonce);

    private static void ValidateEncodeKey(byte[] key)
    {
        if (key is null || key.Length != KeySize)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
    }

    private static uint? BoundedCap(ulong cap) => cap > uint.MaxValue ? uint.MaxValue : (uint)cap;
}
