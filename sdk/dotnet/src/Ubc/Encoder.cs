using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Ubc;

/// <summary>
/// A write-then-close streaming UBC v1 encoder. Plaintext is spooled to a temp file until its
/// final size is known, because the v1 header precedes the payload and carries both size and
/// chunk count (SPEC.md section 2.1).
/// </summary>
public sealed class Encoder : Stream
{
    private readonly Stream _sink;
    private readonly byte[] _metadata;
    private readonly EncodeOptions _options;
    private readonly string _spoolPath;
    private FileStream _spool;
    private ulong _totalSize;
    private bool _finished;
    private bool _disposed;

    public Encoder(Stream sink, IReadOnlyList<MetadataEntry> entries, EncodeOptions? options)
    {
        _sink = sink;
        _options = options ?? new EncodeOptions();
        _metadata = Metadata.Encode(entries);
        _spoolPath = Path.Combine(Path.GetTempPath(), "ubc-encoder-" + Guid.NewGuid().ToString("N") + ".spool");
        var streamOptions = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
        };
        if (!OperatingSystem.IsWindows())
        {
            // UnixCreateMode sets owner-only permissions atomically at creation (no window
            // where the file briefly has default permissions). The property setter itself is
            // unsupported on Windows, so it's set only on the non-Windows path; Windows'
            // per-user temp directory ACL already restricts access to the owning account.
            streamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        _spool = new FileStream(_spoolPath, streamOptions);
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => !_finished;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (_finished)
        {
            throw new InvalidOperationException("encoder is already finished");
        }
        _spool.Write(buffer);
        _totalSize += (ulong)buffer.Length;
    }

    public override void Flush()
    {
        if (!_finished)
        {
            _spool.Flush();
        }
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>Writes the header, payload, authenticated root, and footer to the sink.</summary>
    public void Finish()
    {
        if (_finished)
        {
            return;
        }
        _finished = true;

        ulong chunkSize = _options.ChunkSize;
        bool encrypted = _options.Key is not null;
        if (encrypted && chunkSize > 0xFFFF_FFEF)
        {
            throw new UbcException(ErrorCode.ErrReservedBits);
        }
        ulong chunkCount = _totalSize == 0 ? 0 : (_totalSize + chunkSize - 1) / chunkSize;
        byte[] baseNonce;
        if (encrypted)
        {
            baseNonce = _options.BaseNonce ?? RandomBaseNonce();
        }
        else
        {
            baseNonce = new byte[12];
        }

        var header = new Header(
            (byte)((encrypted ? Header.FlagEncrypted : 0) | (_metadata.Length > 0 ? Header.FlagHasMetadata : 0)),
            encrypted ? Header.HashHmacSha256 : Header.HashSha256,
            encrypted ? Header.AeadAes256Gcm : Header.AeadNone,
            chunkSize,
            chunkCount,
            _totalSize,
            baseNonce);
        byte[] headerBytes = header.ToBytes();
        _sink.Write(headerBytes);
        _sink.Write(_metadata);

        byte[] metadataDigest = CryptoInternal.Sha256(_metadata);
        using var root = encrypted
            ? RootAccumulator.Keyed(CryptoInternal.RootKey(_options.Key!, baseNonce))
            : RootAccumulator.Plain();
        root.Update(headerBytes);
        root.Update(_metadata);

        _spool.Seek(0, SeekOrigin.Begin);
        int bufferLength = (int)Math.Min(_totalSize, chunkSize);
        byte[] buffer = new byte[bufferLength];
        Span<byte> clenBuffer = stackalloc byte[4];
        ulong index = 0;
        for (ulong written = 0; written < _totalSize; written += chunkSize, index++)
        {
            int length = (int)Math.Min(chunkSize, _totalSize - written);
            ReadExact(_spool, buffer.AsSpan(0, length));
            byte[] body;
            if (encrypted)
            {
                byte[] aad = CryptoInternal.ChunkAad(headerBytes, metadataDigest, index);
                body = CryptoInternal.GcmEncrypt(_options.Key!, CryptoInternal.ChunkNonce(baseNonce, index), buffer.AsSpan(0, length), aad);
            }
            else
            {
                body = buffer.AsSpan(0, length).ToArray();
            }
            BinaryPrimitives.WriteUInt32LittleEndian(clenBuffer, (uint)body.Length);
            _sink.Write(clenBuffer);
            _sink.Write(body);
            root.Update(CryptoInternal.Sha256(body));
        }

        _sink.Write(root.Finish());
        _sink.Write(new byte[] { (byte)'U', (byte)'B', (byte)'C', (byte)'E' });
    }

    private static byte[] RandomBaseNonce()
    {
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        return nonce;
    }

    private static void ReadExact(Stream source, Span<byte> destination)
    {
        int total = 0;
        while (total < destination.Length)
        {
            int read = source.Read(destination[total..]);
            if (read == 0)
            {
                throw new EndOfStreamException("unexpected end of spool file");
            }
            total += read;
        }
    }

    // Best-effort safety net: if a caller never disposes the encoder, the finalizer still
    // attempts to remove the plaintext spool file (mirrors the intent of Java's
    // File.deleteOnExit(), since .NET has no process-exit hook to register against here).
    ~Encoder()
    {
        TryDeleteSpoolFile();
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            base.Dispose(disposing);
            return;
        }
        _disposed = true;
        if (disposing)
        {
            try
            {
                if (!_finished)
                {
                    Finish();
                }
            }
            finally
            {
                PurgeSpool();
            }
            GC.SuppressFinalize(this);
        }
        base.Dispose(disposing);
    }

    private void TryDeleteSpoolFile()
    {
        try
        {
            File.Delete(_spoolPath);
        }
        catch (IOException)
        {
            // best-effort; nothing further to do from a finalizer
        }
    }

    private void PurgeSpool()
    {
        try
        {
            _spool.Dispose();
        }
        catch (IOException)
        {
            // best-effort close; the file delete below still runs
        }
        TryDeleteSpoolFile();
    }
}
