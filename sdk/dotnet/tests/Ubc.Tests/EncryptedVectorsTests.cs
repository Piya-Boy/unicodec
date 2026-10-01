using Ubc;
using Xunit;

namespace Ubc.Tests;

public class EncryptedVectorsTests
{
    private static readonly byte[] Key = Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static readonly byte[] BaseNonce = Hex("f0e0d0c0b0a0908070605040");

    private static string VectorRoot() =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", "..", "spec", "vectors"));

    private static byte[] ReadVector(string relative) => File.ReadAllBytes(Path.Combine(VectorRoot(), relative));

    [Fact]
    public void EncodesEveryEncryptedVectorByteExactly()
    {
        Assert.Equal(
            ReadVector("expected/encrypted-empty.ubc"),
            Crypto.EncodeEncryptedWithFixedNonce(ReadVector("inputs/empty.bin"), Key, BaseNonce, new List<MetadataEntry>(), 1 << 20));
        Assert.Equal(
            ReadVector("expected/encrypted-one-byte.ubc"),
            Crypto.EncodeEncryptedWithFixedNonce(ReadVector("inputs/one-byte.bin"), Key, BaseNonce, new List<MetadataEntry>(), 1 << 20));
        Assert.Equal(
            ReadVector("expected/encrypted-chunk-1m.ubc"),
            Crypto.EncodeEncryptedWithFixedNonce(ReadVector("inputs/chunk-1m.bin"), Key, BaseNonce, new List<MetadataEntry>(), 1 << 20));
        Assert.Equal(
            ReadVector("expected/encrypted-chunk-1m-plus-one.ubc"),
            Crypto.EncodeEncryptedWithFixedNonce(ReadVector("inputs/chunk-1m-plus-one.bin"), Key, BaseNonce, new List<MetadataEntry>(), 1 << 20));
        Assert.Equal(
            ReadVector("expected/encrypted-multi-3m.ubc"),
            Crypto.EncodeEncryptedWithFixedNonce(ReadVector("inputs/multi-3m.bin"), Key, BaseNonce, new List<MetadataEntry>(), 1 << 20));

        var entries = new List<MetadataEntry>
        {
            new(0x0001, Hex("e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874")),
            new(0x0002, Hex("746578742f706c61696e")),
            new(0x0003, Hex("00a8da769b010000")),
            new(0x1000, Hex("00ff7f")),
        };
        Assert.Equal(
            ReadVector("expected/encrypted-metadata.ubc"),
            Crypto.EncodeEncryptedWithFixedNonce(ReadVector("inputs/one-byte.bin"), Key, BaseNonce, entries, 1 << 20));
    }

    [Fact]
    public void DecodesEveryEncryptedVector()
    {
        DecodeMatchesInput("expected/encrypted-empty.ubc", "inputs/empty.bin");
        DecodeMatchesInput("expected/encrypted-one-byte.ubc", "inputs/one-byte.bin");
        DecodeMatchesInput("expected/encrypted-chunk-1m.ubc", "inputs/chunk-1m.bin");
        DecodeMatchesInput("expected/encrypted-chunk-1m-plus-one.ubc", "inputs/chunk-1m-plus-one.bin");
        DecodeMatchesInput("expected/encrypted-multi-3m.ubc", "inputs/multi-3m.bin");
        DecodeMatchesInput("expected/encrypted-metadata.ubc", "inputs/one-byte.bin");
    }

    private void DecodeMatchesInput(string container, string input)
    {
        var options = new DecodeOptions().WithKey(Key);
        var result = Crypto.DecodeEncrypted(ReadVector(container), options);
        Assert.Equal(ReadVector(input), result.Data);
    }

    [Fact]
    public void WrongKeyReturnsChunkAuthOnNonEmptyCiphertext()
    {
        var container = ReadVector("expected/encrypted-one-byte.ubc");
        var wrongKey = (byte[])Key.Clone();
        wrongKey[0] ^= 0x01;
        var options = new DecodeOptions().WithKey(wrongKey);
        var exception = Assert.Throws<UbcException>(() => Crypto.DecodeEncrypted(container, options));
        Assert.Equal(ErrorCode.ErrChunkAuth, exception.Code);
    }

    [Fact]
    public void MissingKeyReturnsMissingKey()
    {
        var container = ReadVector("expected/encrypted-one-byte.ubc");
        var exception = Assert.Throws<UbcException>(() => Crypto.DecodeEncrypted(container, new DecodeOptions()));
        Assert.Equal(ErrorCode.ErrMissingKey, exception.Code);
    }

    [Theory]
    [InlineData("negative-chunk-auth.ubc", ErrorCode.ErrChunkAuth, true)]
    [InlineData("negative-encrypted-short-clen.ubc", ErrorCode.ErrChunkAuth, true)]
    [InlineData("negative-encrypted-metadata-tamper.ubc", ErrorCode.ErrChunkAuth, true)]
    [InlineData("negative-missing-key.ubc", ErrorCode.ErrMissingKey, false)]
    [InlineData("negative-encrypted-cap-missing-key.ubc", ErrorCode.ErrMissingKey, false)]
    public void NegativeVectorsUseStableErrorCodes(string name, ErrorCode expected, bool suppliesKey)
    {
        var container = ReadVector("expected/" + name);
        var options = suppliesKey ? new DecodeOptions().WithKey(Key) : new DecodeOptions();
        var exception = Assert.Throws<UbcException>(() => Crypto.DecodeEncrypted(container, options));
        Assert.Equal(expected, exception.Code);
    }

    [Fact]
    public void EncryptedEmptyWrongKeyReturnsRootMismatch()
    {
        var container = ReadVector("expected/negative-encrypted-empty-wrong-key.ubc");
        var wrongKey = Hex("ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var options = new DecodeOptions().WithKey(wrongKey);
        var exception = Assert.Throws<UbcException>(() => Crypto.DecodeEncrypted(container, options));
        Assert.Equal(ErrorCode.ErrRootMismatch, exception.Code);
    }

    [Fact]
    public void RootKeyMatchesSharedKnownAnswer()
    {
        var key = Hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        var baseNonce = Hex("f0e0d0c0b0a0908070605040");
        var expectedRootKey = Hex("52c04b400d73df15d8a0db6ba58919f46fe822fff200fb50d8dee097af3c688c");
        Assert.Equal(expectedRootKey, Crypto.RootKeyForTesting(key, baseNonce));
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
