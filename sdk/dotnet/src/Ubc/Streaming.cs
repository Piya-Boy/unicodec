using System.Buffers.Binary;

namespace Ubc;

/// <summary>Factory, verify, and inspect entry points over Encoder/Decoder.</summary>
public static class Streaming
{
    private const int ReadBlockSize = 32 << 10;

    public static Encoder NewEncoder(Stream sink, IReadOnlyList<MetadataEntry> entries, EncodeOptions? options) =>
        new(sink, entries, options);

    public static Decoder NewDecoder(Stream source, DecodeOptions? options) => new(source, options);

    /// <summary>Fully decodes and discards the plaintext, reporting whether the container is valid.</summary>
    public static VerifyReport Verify(Stream source, DecodeOptions? options)
    {
        try
        {
            using var decoder = new Decoder(source, options);
            var buffer = new byte[ReadBlockSize];
            while (decoder.Read(buffer, 0, buffer.Length) != 0)
            {
                // discard; verification is in Read()'s side effects (auth + root check)
            }
        }
        catch (UbcException e)
        {
            return new VerifyReport(false, e.Code);
        }
        catch (IOException)
        {
            return new VerifyReport(false, ErrorCode.ErrTruncated);
        }
        return new VerifyReport(true, null);
    }

    /// <summary>Reads only the header and metadata — never touches payload or footer.</summary>
    public static ContainerInfo Inspect(Stream source, DecodeOptions? options)
    {
        var opts = options ?? new DecodeOptions();
        byte[] headerBytes = ReadExact(source, Header.Size);
        var header = Header.Parse(headerBytes);
        List<MetadataEntry> entries = new();
        if (header.HasMetadata)
        {
            byte[] prefix = ReadExact(source, 4);
            uint metadataLength = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
            if (metadataLength == 0 || metadataLength > opts.MaxMetaBytes)
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
            var result = Metadata.Parse(region, BoundedCap(opts.MaxMetaBytes));
            entries = result.Entries;
        }
        return new ContainerInfo(
            Header.Version,
            header.Encrypted,
            header.HasMetadata,
            header.HashAlgo,
            header.AeadAlgo,
            header.ChunkSize,
            header.ChunkCount,
            header.TotalSize,
            entries);
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
