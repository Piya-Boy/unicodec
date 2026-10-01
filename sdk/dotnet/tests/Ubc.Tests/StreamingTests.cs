using Ubc;
using Xunit;

namespace Ubc.Tests;

public class StreamingTests
{
    private static readonly byte[] Key = Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] BaseNonce = Hex("f0e0d0c0b0a0908070605040");

    private static string VectorRoot() =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", "..", "spec", "vectors"));

    private static byte[] ReadVector(string relative) => File.ReadAllBytes(Path.Combine(VectorRoot(), relative));

    [Fact]
    public void StreamedPlainOutputIsByteExactAndFragmentedDecodeRoundTrips()
    {
        var input = ReadVector("inputs/multi-3m.bin");
        using var sink = new MemoryStream();
        using (var encoder = new Encoder(sink, Array.Empty<MetadataEntry>(), new EncodeOptions().WithChunkSize(1 << 20)))
        {
            encoder.Write(input, 0, input.Length / 3);
            encoder.Write(input, input.Length / 3, input.Length - input.Length / 3);
        }
        var streamed = sink.ToArray();
        Assert.Equal(ReadVector("expected/plain-multi-3m.ubc"), streamed);

        using var decoder = new Decoder(new OneByteAtATimeStream(streamed), null);
        using var decoded = new MemoryStream();
        var buffer = new byte[1];
        int count;
        while ((count = decoder.Read(buffer, 0, 1)) != 0)
        {
            decoded.Write(buffer, 0, count);
        }
        Assert.Equal(input, decoded.ToArray());
    }

    [Fact]
    public void StreamedEncryptedOutputIsByteExactAndAuthenticatesBeforeRelease()
    {
        var input = ReadVector("inputs/chunk-1m-plus-one.bin");
        using var sink = new MemoryStream();
        var options = new EncodeOptions(1 << 20, Key, BaseNonce);
        using (var encoder = new Encoder(sink, Array.Empty<MetadataEntry>(), options))
        {
            encoder.Write(input, 0, input.Length);
        }
        Assert.Equal(ReadVector("expected/encrypted-chunk-1m-plus-one.ubc"), sink.ToArray());

        using var decoder = new Decoder(new MemoryStream(sink.ToArray()), new DecodeOptions().WithKey(Key));
        using var decoded = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = decoder.Read(buffer, 0, buffer.Length)) != 0)
        {
            decoded.Write(buffer, 0, count);
        }
        Assert.Equal(input, decoded.ToArray());
    }

    [Fact]
    public void StreamedPlainDecoderWithholdsOutputUntilRootVerifies()
    {
        var container = (byte[])ReadVector("expected/plain-chunk-1m.ubc").Clone();
        container[^1] ^= 0x01; // corrupt footer magic's last byte
        using var decoder = new Decoder(new MemoryStream(container), null);
        var buffer = new byte[4096];
        var exception = Assert.Throws<UbcException>(() =>
        {
            int count;
            while ((count = decoder.Read(buffer, 0, buffer.Length)) != 0)
            {
                // drain
            }
        });
        Assert.Equal(ErrorCode.ErrTruncated, exception.Code);
    }

    [Fact]
    public void StreamedPlainDecoderWithholdsOutputUntilTrailingDataIsChecked()
    {
        var container = ReadVector("expected/plain-chunk-1m.ubc");
        var withTrailingByte = new byte[container.Length + 1];
        container.CopyTo(withTrailingByte, 0);
        using var decoder = new Decoder(new MemoryStream(withTrailingByte), null);
        var buffer = new byte[4096];
        var exception = Assert.Throws<UbcException>(() =>
        {
            int count;
            while ((count = decoder.Read(buffer, 0, buffer.Length)) != 0)
            {
                // drain
            }
        });
        Assert.Equal(ErrorCode.ErrTrailingData, exception.Code);
    }

    [Fact]
    public void TruncatedEncryptedFooterPrecedesFinalChunkAuthentication()
    {
        // Corrupt both the final chunk's GCM tag AND truncate the footer. SPEC.md section 5
        // requires truncation (stage 4) to win over chunk-auth failure (stage 5).
        var container = (byte[])ReadVector("expected/encrypted-one-byte.ubc").Clone();
        int footerStart = container.Length - 36;
        container[footerStart - 1] ^= 0x01; // flip the last byte of the only chunk's GCM tag
        var truncated = container[..(container.Length - 10)];

        using var decoder = new Decoder(new MemoryStream(truncated), new DecodeOptions().WithKey(Key));
        var buffer = new byte[4096];
        var exception = Assert.Throws<UbcException>(() =>
        {
            int count;
            while ((count = decoder.Read(buffer, 0, buffer.Length)) != 0)
            {
                // drain
            }
        });
        Assert.Equal(ErrorCode.ErrTruncated, exception.Code);
    }

    [Fact]
    public void StreamedEncoderWithLargeChunkSizeOnlyBuffersWrittenInput()
    {
        // A chunk_size far larger than the actual input must not cause the encoder to
        // allocate a chunk_size-sized buffer (the historical Rust OOM bug this guards against).
        byte[] input = { 1, 2, 3 };
        using var sink = new MemoryStream();
        var options = new EncodeOptions().WithChunkSize(1 << 28); // 256 MiB
        using (var encoder = new Encoder(sink, Array.Empty<MetadataEntry>(), options))
        {
            encoder.Write(input, 0, input.Length);
        }
        var result = Payload.DecodePlain(sink.ToArray(), null);
        Assert.Equal(input, result.Data);
    }

    [Fact]
    public void StreamedDecoderEnforcesCapsBeforeAllocatingChunkData()
    {
        var container = ReadVector("expected/plain-chunk-1m.ubc");
        var tight = new DecodeOptions(16UL << 20, 4, 1UL << 20, 1UL << 30, null);
        using var decoder = new Decoder(new MemoryStream(container), tight);
        var buffer = new byte[4096];
        var exception = Assert.Throws<UbcException>(() => decoder.Read(buffer, 0, buffer.Length));
        Assert.Equal(ErrorCode.ErrTruncated, exception.Code);
    }

    [Fact]
    public void VerifyAndInspectHaveTheirDocumentedReadScopes()
    {
        var container = ReadVector("expected/plain-metadata.ubc");
        var ok = Streaming.Verify(new MemoryStream(container), null);
        Assert.True(ok.Ok);

        var corrupted = (byte[])container.Clone();
        corrupted[Header.Size + 4] ^= 0x01;
        var bad = Streaming.Verify(new MemoryStream(corrupted), null);
        Assert.False(bad.Ok);
        Assert.Equal(ErrorCode.ErrRootMismatch, bad.Error);

        // inspect only reads header + metadata; it must not touch (or require) the payload
        // or footer at all, so a stream with the footer deliberately mangled still works.
        var mangledFooter = (byte[])container.Clone();
        mangledFooter[^1] ^= 0x01;
        var info = Streaming.Inspect(new MemoryStream(mangledFooter), null);
        Assert.True(info.HasMetadata);
        Assert.False(info.Encrypted);
        Assert.Equal(4, info.Metadata.Count);
    }

    private sealed class OneByteAtATimeStream : Stream
    {
        private readonly MemoryStream _delegate;

        public OneByteAtATimeStream(byte[] data) => _delegate = new MemoryStream(data);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (count == 0)
            {
                return 0;
            }
            int single = _delegate.ReadByte();
            if (single < 0)
            {
                return 0;
            }
            buffer[offset] = (byte)single;
            return 1;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static byte[] Hex(string value)
    {
        var result = new byte[value.Length / 2];
        for (int i = 0; i < value.Length; i += 2)
        {
            result[i / 2] = Convert.ToByte(value.Substring(i, 2), 16);
        }
        return result;
    }
}
