using System.Buffers.Binary;
using System.Text;

namespace Ubc;

/// <summary>UBC metadata TLV block encoding and parsing (SPEC.md section 2.2).</summary>
public static class Metadata
{
    public const ushort TagFilename = 0x0001;
    public const ushort TagMimeType = 0x0002;
    public const ushort TagCreatedAt = 0x0003;

    public readonly struct ParseResult
    {
        public List<MetadataEntry> Entries { get; }
        public int Consumed { get; }

        public ParseResult(List<MetadataEntry> entries, int consumed)
        {
            Entries = entries;
            Consumed = consumed;
        }
    }

    public static byte[] Encode(IReadOnlyList<MetadataEntry> entries)
    {
        var ordered = entries.OrderBy(entry => entry.Tag).ToList();
        if (ordered.Count == 0)
        {
            return Array.Empty<byte>();
        }

        using var body = new MemoryStream();
        Span<byte> entryHeader = stackalloc byte[6];
        int? previousTag = null;
        foreach (var entry in ordered)
        {
            ValidateEntry(entry);
            if (previousTag == entry.Tag)
            {
                throw new UbcException(ErrorCode.ErrMetaMalformed);
            }
            previousTag = entry.Tag;
            if ((long)body.Length + 6 + entry.Value.Length > uint.MaxValue)
            {
                throw new UbcException(ErrorCode.ErrMetaMalformed);
            }
            BinaryPrimitives.WriteUInt16LittleEndian(entryHeader[..2], entry.Tag);
            BinaryPrimitives.WriteUInt32LittleEndian(entryHeader[2..], (uint)entry.Value.Length);
            body.Write(entryHeader);
            body.Write(entry.Value);
        }

        byte[] bodyBytes = body.ToArray();
        var result = new byte[4 + bodyBytes.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(0, 4), (uint)bodyBytes.Length);
        bodyBytes.CopyTo(result, 4);
        return result;
    }

    public static ParseResult Parse(ReadOnlySpan<byte> data, uint? maxBytes)
    {
        if (data.Length < 4)
        {
            throw new UbcException(ErrorCode.ErrMetaMalformed);
        }
        uint metadataLength = BinaryPrimitives.ReadUInt32LittleEndian(data[..4]);
        long available = data.Length - 4;
        if (metadataLength == 0 || (maxBytes is not null && metadataLength > maxBytes.Value) || metadataLength > available)
        {
            throw new UbcException(ErrorCode.ErrMetaMalformed);
        }

        int end = 4 + (int)metadataLength;
        var entries = new List<MetadataEntry>();
        int cursor = 4;
        int? previousTag = null;
        while (cursor < end)
        {
            if (end - cursor < 6)
            {
                throw new UbcException(ErrorCode.ErrMetaMalformed);
            }
            ushort tag = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(cursor, 2));
            uint valueLength = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(cursor + 2, 4));
            cursor += 6;
            if (valueLength > (uint)(end - cursor) || (previousTag is not null && tag <= previousTag))
            {
                throw new UbcException(ErrorCode.ErrMetaMalformed);
            }
            byte[] value = data.Slice(cursor, (int)valueLength).ToArray();
            var entry = new MetadataEntry(tag, value);
            ValidateEntry(entry);
            entries.Add(entry);
            previousTag = tag;
            cursor += (int)valueLength;
        }
        return new ParseResult(entries, end);
    }

    private static void ValidateEntry(MetadataEntry entry)
    {
        if (entry.Tag == TagFilename)
        {
            if (StartsWithBom(entry.Value) || ContainsNul(entry.Value))
            {
                throw new UbcException(ErrorCode.ErrMetaMalformed);
            }
            if (!IsValidUtf8(entry.Value))
            {
                throw new UbcException(ErrorCode.ErrMetaMalformed);
            }
        }
        else if (entry.Tag == TagMimeType)
        {
            foreach (byte b in entry.Value)
            {
                if (b == 0 || b > 0x7F)
                {
                    throw new UbcException(ErrorCode.ErrMetaMalformed);
                }
            }
        }
        else if (entry.Tag == TagCreatedAt)
        {
            if (entry.Value.Length != 8)
            {
                throw new UbcException(ErrorCode.ErrMetaMalformed);
            }
        }
    }

    private static bool StartsWithBom(byte[] value) =>
        value.Length >= 3 && value[0] == 0xEF && value[1] == 0xBB && value[2] == 0xBF;

    private static bool ContainsNul(byte[] value) => Array.IndexOf(value, (byte)0) >= 0;

    private static bool IsValidUtf8(byte[] value)
    {
        try
        {
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(value);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
