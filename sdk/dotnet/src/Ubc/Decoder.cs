using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Ubc;

/// <summary>
/// A pull-based streaming UBC v1 decoder. Each encrypted chunk is authenticated (GCM tag
/// verified) before any of its plaintext is returned (SPEC.md section 3, verify-before-release).
/// </summary>
public sealed class Decoder : Stream
{
    private const int FooterSize = 36;
    private static readonly byte[] FooterMagic = { (byte)'U', (byte)'B', (byte)'C', (byte)'E' };

    private readonly Stream _source;
    private readonly DecodeOptions _options;
    private readonly Header _header;
    private readonly byte[] _headerBytes;
    private readonly byte[] _metadataDigest;
    private readonly RootAccumulator _root;
    private readonly byte[]? _baseNonce;

    private ulong _chunkIndex;
    private ulong _plaintextSize;
    private byte[]? _pending;
    private int _pendingOffset;
    private byte[]? _prefetchedFooter;
    private bool _finished;
    private UbcException? _terminalError;

    public List<MetadataEntry> Metadata { get; }

    public Decoder(Stream source, DecodeOptions? options)
    {
        _source = source;
        _options = options ?? new DecodeOptions();

        _headerBytes = ReadExact(source, Header.Size);
        _header = Header.Parse(_headerBytes);

        List<MetadataEntry> entries = new();
        byte[] metadataRegion = Array.Empty<byte>();
        if (_header.HasMetadata)
        {
            metadataRegion = ReadMetadataRegion(source, _options.MaxMetaBytes);
            var result = Ubc.Metadata.Parse(metadataRegion, BoundedCap(_options.MaxMetaBytes));
            entries = result.Entries;
        }
        Metadata = entries;

        byte[]? key = _options.Key();
        if (_header.Encrypted && (key is null || key.Length != 32))
        {
            throw new UbcException(ErrorCode.ErrMissingKey);
        }
        if (_header.ChunkCount > _options.MaxChunkCount || _header.TotalSize > _options.MaxTotalSize)
        {
            throw new UbcException(ErrorCode.ErrTruncated);
        }

        _metadataDigest = CryptoInternal.Sha256(metadataRegion);
        _baseNonce = _header.Encrypted ? _header.BaseNonce() : null;
        _root = _header.Encrypted
            ? RootAccumulator.Keyed(CryptoInternal.RootKey(key!, _baseNonce!))
            : RootAccumulator.Plain();
        _root.Update(_headerBytes);
        _root.Update(metadataRegion);
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _root.Dispose();
        }
        base.Dispose(disposing);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (_terminalError is not null)
        {
            throw _terminalError;
        }
        if (buffer.Length == 0)
        {
            return 0;
        }
        try
        {
            while (_pending is null && !_finished)
            {
                LoadNextChunk();
            }
        }
        catch (UbcException e)
        {
            _terminalError = e;
            throw;
        }
        if (_pending is null)
        {
            return 0;
        }
        int available = _pending.Length - _pendingOffset;
        int toCopy = Math.Min(available, buffer.Length);
        _pending.AsSpan(_pendingOffset, toCopy).CopyTo(buffer);
        _pendingOffset += toCopy;
        if (_pendingOffset == _pending.Length)
        {
            _pending = null;
            _pendingOffset = 0;
        }
        return toCopy;
    }

    private void LoadNextChunk()
    {
        if (_chunkIndex == _header.ChunkCount)
        {
            VerifyFooter();
            return;
        }
        uint lengthValue = BinaryPrimitives.ReadUInt32LittleEndian(ReadExact(_source, 4));
        if (lengthValue > _options.MaxChunkLen)
        {
            throw new UbcException(ErrorCode.ErrTruncated);
        }
        int chunkLength = (int)lengthValue;
        byte[] body = ReadExact(_source, chunkLength);
        _root.Update(CryptoInternal.Sha256(body));

        bool isLastChunk = _chunkIndex + 1 == _header.ChunkCount;
        if (_header.Encrypted && isLastChunk)
        {
            // Preflight the footer before authenticating the final chunk so a truncated
            // stream surfaces ERR_TRUNCATED rather than a misleading ERR_CHUNK_AUTH —
            // SPEC.md section 5's precedence requires truncation to win over chunk-auth
            // failure.
            _prefetchedFooter = ReadExact(_source, FooterSize);
        }

        byte[] plain;
        if (_header.Encrypted)
        {
            if (body.Length < CryptoInternal.GcmTagSize)
            {
                throw new UbcException(ErrorCode.ErrChunkAuth);
            }
            try
            {
                plain = CryptoInternal.GcmDecrypt(_options.Key()!, CryptoInternal.ChunkNonce(_baseNonce!, _chunkIndex), body,
                    CryptoInternal.ChunkAad(_headerBytes, _metadataDigest, _chunkIndex));
            }
            catch (AuthenticationTagMismatchException)
            {
                throw new UbcException(ErrorCode.ErrChunkAuth);
            }
        }
        else
        {
            plain = body;
        }

        if ((ulong)plain.Length > _header.TotalSize - _plaintextSize)
        {
            throw new UbcException(ErrorCode.ErrRootMismatch);
        }
        _plaintextSize += (ulong)plain.Length;
        _chunkIndex++;
        _pending = plain.Length == 0 ? null : plain;
        _pendingOffset = 0;
    }

    private void VerifyFooter()
    {
        byte[] footer = _prefetchedFooter ?? ReadExact(_source, FooterSize);
        var footerRoot = footer.AsSpan(0, 32);
        var footerMagic = footer.AsSpan(32, 4);
        if (!footerMagic.SequenceEqual(FooterMagic))
        {
            throw new UbcException(ErrorCode.ErrTruncated);
        }
        if (_plaintextSize != _header.TotalSize || !CryptographicOperations.FixedTimeEquals(footerRoot, _root.Finish()))
        {
            throw new UbcException(ErrorCode.ErrRootMismatch);
        }
        if (_source.ReadByte() != -1)
        {
            throw new UbcException(ErrorCode.ErrTrailingData);
        }
        _finished = true;
    }

    private static byte[] ReadMetadataRegion(Stream source, ulong maxMetaBytes)
    {
        byte[] prefix = ReadExact(source, 4);
        uint metadataLength = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
        if (metadataLength == 0 || metadataLength > maxMetaBytes)
        {
            throw new UbcException(ErrorCode.ErrMetaMalformed);
        }
        byte[] body;
        try
        {
            body = ReadExact(source, (int)metadataLength);
        }
        catch (UbcException e) when (e.Code == ErrorCode.ErrTruncated)
        {
            throw new UbcException(ErrorCode.ErrMetaMalformed);
        }
        var region = new byte[4 + body.Length];
        prefix.CopyTo(region, 0);
        body.CopyTo(region, 4);
        return region;
    }

    private static byte[] ReadExact(Stream source, int length)
    {
        var data = new byte[length];
        int total = 0;
        while (total < length)
        {
            int count = source.Read(data, total, length - total);
            if (count <= 0)
            {
                throw new UbcException(ErrorCode.ErrTruncated);
            }
            total += count;
        }
        return data;
    }

    private static uint? BoundedCap(ulong cap) => cap > uint.MaxValue ? uint.MaxValue : (uint)cap;
}
