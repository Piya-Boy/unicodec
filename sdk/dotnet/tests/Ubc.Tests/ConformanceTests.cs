using System.Security.Cryptography;
using Ubc.Tests.Support;
using Xunit;

namespace Ubc.Tests;

/// <summary>Drives every vector in spec/vectors/vectors.json through the .NET SDK — the manifest is the contract.</summary>
public class ConformanceTests
{
    [Fact]
    public void EveryShareManifestVectorConforms()
    {
        string root = VectorManifest.VectorsRoot();
        var manifest = VectorManifest.Read(root);
        byte[] canonicalKey = manifest.CanonicalKey();
        int positiveCount = 0;
        int negativeCount = 0;

        foreach (var vector in manifest.Vectors)
        {
            byte[] expected = File.ReadAllBytes(Path.Combine(root, vector.Expected));
            Assert.Equal(vector.ExpectedSha256, SHA256.HashData(expected));

            if (vector.ExpectError is not null)
            {
                negativeCount++;
                byte[]? vectorKey = vector.Options?.Key;
                byte[]? decodeKey = RequiresKey(vector.Id) ? (vectorKey ?? canonicalKey) : null;
                var decoded = vector.Decode(expected, decodeKey);
                Assert.True(decoded.Error is not null, vector.Id + ": negative vector must not decode successfully");
                Assert.Equal(vector.ExpectError, decoded.Error!.Value.ToStableId());
                continue;
            }

            positiveCount++;
            byte[] input = File.ReadAllBytes(Path.Combine(root, vector.Input!));
            byte[] encoded = vector.Encode(input);
            Assert.Equal(expected, encoded);

            var result = vector.Decode(expected, vector.Options!.Key);
            Assert.True(result.Error is null, vector.Id + ": decode failed with " + result.Error);
            Assert.Equal(input, result.Data);
            var expectedMetadata = vector.Options.Metadata;
            Assert.Equal(expectedMetadata.Count, result.Metadata!.Count);
            for (int i = 0; i < expectedMetadata.Count; i++)
            {
                Assert.Equal(expectedMetadata[i].Tag, result.Metadata[i].Tag);
                Assert.Equal(expectedMetadata[i].Value, result.Metadata[i].Value);
            }
        }

        Assert.True(positiveCount > 0, "manifest must contain positive vectors");
        Assert.True(negativeCount > 0, "manifest must contain negative vectors");
    }

    // Negative vectors whose own point is "decoded without a key" must actually be decoded
    // without one; every other negative vector decodes with the canonical/vector-supplied key
    // so a missing-key short-circuit doesn't mask the error the vector is meant to exercise.
    private static bool RequiresKey(string id) =>
        id != "negative-missing-key" && id != "negative-encrypted-cap-missing-key";
}
