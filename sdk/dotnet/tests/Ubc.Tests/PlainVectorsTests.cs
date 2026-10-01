using Ubc;
using Xunit;

namespace Ubc.Tests;

public class PlainVectorsTests
{
    private static string VectorRoot() =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", "..", "spec", "vectors"));

    private static byte[] ReadVector(string relative) => File.ReadAllBytes(Path.Combine(VectorRoot(), relative));

    [Fact]
    public void EncodesEveryPlainVectorByteExactly()
    {
        var empty = ReadVector("inputs/empty.bin");
        Assert.Equal(ReadVector("expected/plain-empty.ubc"), Payload.EncodePlain(empty, new List<MetadataEntry>(), 1 << 20));

        var oneByte = ReadVector("inputs/one-byte.bin");
        Assert.Equal(ReadVector("expected/plain-one-byte.ubc"), Payload.EncodePlain(oneByte, new List<MetadataEntry>(), 1 << 20));

        var chunk1m = ReadVector("inputs/chunk-1m.bin");
        Assert.Equal(ReadVector("expected/plain-chunk-1m.ubc"), Payload.EncodePlain(chunk1m, new List<MetadataEntry>(), 1 << 20));

        var chunk1mPlusOne = ReadVector("inputs/chunk-1m-plus-one.bin");
        Assert.Equal(
            ReadVector("expected/plain-chunk-1m-plus-one.ubc"),
            Payload.EncodePlain(chunk1mPlusOne, new List<MetadataEntry>(), 1 << 20));

        var multi3m = ReadVector("inputs/multi-3m.bin");
        Assert.Equal(ReadVector("expected/plain-multi-3m.ubc"), Payload.EncodePlain(multi3m, new List<MetadataEntry>(), 1 << 20));

        var entries = new List<MetadataEntry>
        {
            new(0x0001, Hex("e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874")),
            new(0x0002, Hex("746578742f706c61696e")),
            new(0x0003, Hex("00a8da769b010000")),
            new(0x1000, Hex("00ff7f")),
        };
        var metaInput = ReadVector("inputs/one-byte.bin");
        Assert.Equal(ReadVector("expected/plain-metadata.ubc"), Payload.EncodePlain(metaInput, entries, 1 << 20));
    }

    [Fact]
    public void DecodesEveryPlainVector()
    {
        DecodeMatchesInput("expected/plain-empty.ubc", "inputs/empty.bin");
        DecodeMatchesInput("expected/plain-one-byte.ubc", "inputs/one-byte.bin");
        DecodeMatchesInput("expected/plain-chunk-1m.ubc", "inputs/chunk-1m.bin");
        DecodeMatchesInput("expected/plain-chunk-1m-plus-one.ubc", "inputs/chunk-1m-plus-one.bin");
        DecodeMatchesInput("expected/plain-multi-3m.ubc", "inputs/multi-3m.bin");
        DecodeMatchesInput("expected/plain-metadata.ubc", "inputs/one-byte.bin");
    }

    private void DecodeMatchesInput(string container, string input)
    {
        var result = Payload.DecodePlain(ReadVector(container), null);
        Assert.Equal(ReadVector(input), result.Data);
    }

    [Fact]
    public void FlippedPlainPayloadReturnsRootMismatch()
    {
        var container = (byte[])ReadVector("expected/plain-chunk-1m.ubc").Clone();
        container[Header.Size + 4] ^= 0x01;
        var exception = Assert.Throws<UbcException>(() => Payload.DecodePlain(container, null));
        Assert.Equal(ErrorCode.ErrRootMismatch, exception.Code);
    }

    [Theory]
    [InlineData("negative-truncated.ubc", ErrorCode.ErrTruncated)]
    [InlineData("negative-root-mismatch.ubc", ErrorCode.ErrRootMismatch)]
    [InlineData("negative-trailing-data.ubc", ErrorCode.ErrTrailingData)]
    [InlineData("negative-oversized-clen.ubc", ErrorCode.ErrTruncated)]
    public void NegativeVectorsUseStableErrorCodes(string name, ErrorCode expected)
    {
        var container = ReadVector("expected/" + name);
        var exception = Assert.Throws<UbcException>(() => Payload.DecodePlain(container, null));
        Assert.Equal(expected, exception.Code);
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
