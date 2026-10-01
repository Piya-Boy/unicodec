using Ubc;
using Xunit;

namespace Ubc.Tests;

public class HeaderMetadataVectorsTests
{
    private static string VectorRoot() =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", "..", "spec", "vectors"));

    private static byte[] Vector(string name) => File.ReadAllBytes(Path.Combine(VectorRoot(), "expected", name));

    [Fact]
    public void AllPositiveVectorHeadersRoundTripByteExactly()
    {
        var expectedDir = Path.Combine(VectorRoot(), "expected");
        var files = Directory.GetFiles(expectedDir, "*.ubc");
        Assert.NotEmpty(files);
        foreach (var path in files)
        {
            var name = Path.GetFileName(path);
            if (name.StartsWith("negative-", StringComparison.Ordinal))
            {
                continue;
            }
            var container = File.ReadAllBytes(path);
            var header = Header.Parse(container);
            Assert.Equal(container[..Header.Size], header.ToBytes());
        }
    }

    [Fact]
    public void VectorMetadataRoundTripsByteExactly()
    {
        var container = Vector("plain-metadata.ubc");
        var header = Header.Parse(container);
        Assert.True(header.HasMetadata);

        var result = Metadata.Parse(container.AsSpan(Header.Size), null);
        var reencoded = Metadata.Encode(result.Entries);
        var expected = container[Header.Size..(Header.Size + result.Consumed)];
        Assert.Equal(expected, reencoded);
    }

    [Theory]
    [InlineData("negative-bad-magic.ubc", ErrorCode.ErrBadMagic)]
    [InlineData("negative-version-two.ubc", ErrorCode.ErrUnsupportedVer)]
    [InlineData("negative-hash-algo.ubc", ErrorCode.ErrUnsupportedAlgo)]
    [InlineData("negative-aead-algo.ubc", ErrorCode.ErrUnsupportedAlgo)]
    [InlineData("negative-reserved-flag.ubc", ErrorCode.ErrReservedBits)]
    [InlineData("negative-inconsistent-encryption.ubc", ErrorCode.ErrReservedBits)]
    [InlineData("negative-zero-chunk-size.ubc", ErrorCode.ErrReservedBits)]
    [InlineData("negative-encrypted-zero-chunk-size.ubc", ErrorCode.ErrReservedBits)]
    [InlineData("negative-encrypted-oversized-chunk-size.ubc", ErrorCode.ErrReservedBits)]
    public void HeaderNegativeVectorsUseStableErrorCodes(string name, ErrorCode expected)
    {
        var container = Vector(name);
        var exception = Assert.Throws<UbcException>(() => Header.Parse(container));
        Assert.Equal(expected, exception.Code);
    }

    [Theory]
    [InlineData("negative-meta-out-of-order.ubc")]
    [InlineData("negative-meta-duplicate.ubc")]
    [InlineData("negative-meta-overrun.ubc")]
    [InlineData("negative-empty-metadata.ubc")]
    [InlineData("negative-encrypted-reserved-metadata.ubc")]
    [InlineData("negative-reserved-metadata.ubc")]
    public void MetadataNegativeVectorsUseStableErrorCodes(string name)
    {
        var container = Vector(name);
        var exception = Assert.Throws<UbcException>(() => Metadata.Parse(container.AsSpan(Header.Size), null));
        Assert.Equal(ErrorCode.ErrMetaMalformed, exception.Code);
    }

    [Fact]
    public void MetadataEncoderSortsTagsAndRejectsDuplicates()
    {
        var entries = new List<MetadataEntry>
        {
            new(0x1000, new byte[] { 1 }),
            new(0x0001, "example.txt"u8.ToArray()),
        };
        var encoded = Metadata.Encode(entries);
        var result = Metadata.Parse(encoded, null);
        Assert.Equal(0x0001, result.Entries[0].Tag);
        Assert.Equal(0x1000, result.Entries[1].Tag);

        var duplicates = new List<MetadataEntry> { new(1, Array.Empty<byte>()), new(1, Array.Empty<byte>()) };
        var exception = Assert.Throws<UbcException>(() => Metadata.Encode(duplicates));
        Assert.Equal(ErrorCode.ErrMetaMalformed, exception.Code);
    }

    [Fact]
    public void MetadataLengthCapIsCheckedBeforeCopyingEntries()
    {
        byte[] oversized = { 0x01, 0x00, 0x00, 0x01 }; // declares a length larger than 16 MiB
        var exception = Assert.Throws<UbcException>(() => Metadata.Parse(oversized, 16 << 20));
        Assert.Equal(ErrorCode.ErrMetaMalformed, exception.Code);

        var metadata = Metadata.Encode(new List<MetadataEntry> { new(0x1000, new byte[] { 1 }) });
        var capped = Assert.Throws<UbcException>(() => Metadata.Parse(metadata, 6));
        Assert.Equal(ErrorCode.ErrMetaMalformed, capped.Code);
    }
}
