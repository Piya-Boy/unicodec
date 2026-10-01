using Ubc;

namespace Ubc.Tests.Support;

/// <summary>Reads spec/vectors/vectors.json and encodes/decodes vectors through the .NET SDK.</summary>
public sealed class VectorManifest
{
    public List<Vector> Vectors { get; }

    private VectorManifest(List<Vector> vectors) => Vectors = vectors;

    public static string VectorsRoot() =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", "..", "spec", "vectors"));

    public static VectorManifest Read(string vectorsRoot)
    {
        byte[] bytes = File.ReadAllBytes(Path.Combine(vectorsRoot, "vectors.json"));
        var root = MiniJson.AsObject(MiniJson.Parse(bytes));
        var rawVectors = MiniJson.AsArray(root["vectors"]);
        var vectors = rawVectors.Select(v => Vector.From(MiniJson.AsObject(v))).ToList();
        return new VectorManifest(vectors);
    }

    /// <summary>The key shared by every encrypted positive vector, used to decode negative vectors that omit options.</summary>
    public byte[] CanonicalKey()
    {
        foreach (var vector in Vectors)
        {
            if (vector.ExpectError is null && vector.Options?.Key is not null)
            {
                return vector.Options.Key;
            }
        }
        throw new InvalidOperationException("manifest has no encrypted positive vector");
    }

    public sealed class Vector
    {
        public string Id { get; }
        public string? Input { get; }
        public Options? Options { get; }
        public string Expected { get; }
        public byte[] ExpectedSha256 { get; }
        public string? ExpectError { get; }

        private Vector(string id, string? input, Options? options, string expected, byte[] expectedSha256, string? expectError)
        {
            Id = id;
            Input = input;
            Options = options;
            Expected = expected;
            ExpectedSha256 = expectedSha256;
            ExpectError = expectError;
        }

        public static Vector From(Dictionary<string, object?> raw)
        {
            string id = MiniJson.AsString(raw["id"]);
            string? input = raw.TryGetValue("input", out var i) && i is not null ? MiniJson.AsString(i) : null;
            Options? options = raw.TryGetValue("options", out var o) && o is not null ? Support.Options.From(MiniJson.AsObject(o)) : null;
            string expected = MiniJson.AsString(raw["expected"]);
            byte[] expectedSha256 = Hex(MiniJson.AsString(raw["expectedSha256"]));
            string? expectError = raw.TryGetValue("expectError", out var e) && e is not null ? MiniJson.AsString(e) : null;
            return new Vector(id, input, options, expected, expectedSha256, expectError);
        }

        /// <summary>Encodes this vector's input through the .NET SDK using its declared options.</summary>
        public byte[] Encode(byte[] inputBytes)
        {
            if (Options is null)
            {
                throw new InvalidOperationException(Id + ": positive vector has no options");
            }
            if (Options.Key is not null && Options.BaseNonce is not null)
            {
                return Crypto.EncodeEncryptedWithFixedNonce(inputBytes, Options.Key, Options.BaseNonce, Options.Metadata, Options.ChunkSize);
            }
            if (Options.Key is null && Options.BaseNonce is null)
            {
                return Payload.EncodePlain(inputBytes, Options.Metadata, Options.ChunkSize);
            }
            throw new InvalidOperationException(Id + ": key and baseNonce must be paired");
        }

        /// <summary>
        /// Decodes a container, auto-detecting plain vs encrypted from the header itself
        /// (mirrors Go's single DecodeBytes entry point). key is used only if the container
        /// turns out to be encrypted.
        /// </summary>
        public DecodedVector Decode(byte[] container, byte[]? key)
        {
            try
            {
                bool encrypted = Header.Parse(container).Encrypted;
                if (encrypted)
                {
                    var result = Crypto.DecodeEncrypted(container, new DecodeOptions().WithKey(key));
                    return new DecodedVector(result.Data, result.Metadata, null);
                }
                var plainResult = Payload.DecodePlain(container, null);
                return new DecodedVector(plainResult.Data, plainResult.Metadata, null);
            }
            catch (UbcException e)
            {
                return new DecodedVector(null, null, e.Code);
            }
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

    public sealed class DecodedVector
    {
        public byte[]? Data { get; }
        public List<MetadataEntry>? Metadata { get; }
        public ErrorCode? Error { get; }

        public DecodedVector(byte[]? data, List<MetadataEntry>? metadata, ErrorCode? error)
        {
            Data = data;
            Metadata = metadata;
            Error = error;
        }
    }
}

public sealed class Options
{
    public ulong ChunkSize { get; }
    public byte[]? Key { get; }
    public byte[]? BaseNonce { get; }
    public List<MetadataEntry> Metadata { get; }

    private Options(ulong chunkSize, byte[]? key, byte[]? baseNonce, List<MetadataEntry> metadata)
    {
        ChunkSize = chunkSize;
        Key = key;
        BaseNonce = baseNonce;
        Metadata = metadata;
    }

    public static Options From(Dictionary<string, object?> raw)
    {
        ulong chunkSize = (ulong)MiniJson.AsNumber(raw["chunkSize"]);
        byte[]? key = raw.TryGetValue("key", out var k) && k is not null ? Hex(MiniJson.AsString(k)) : null;
        byte[]? baseNonce = raw.TryGetValue("baseNonce", out var n) && n is not null ? Hex(MiniJson.AsString(n)) : null;
        var metadata = new List<MetadataEntry>();
        if (raw.TryGetValue("metadata", out var m) && m is not null)
        {
            foreach (var rawEntry in MiniJson.AsArray(m))
            {
                var entry = MiniJson.AsObject(rawEntry);
                string tagHex = MiniJson.AsString(entry["tag"]);
                ushort tag = Convert.ToUInt16(tagHex[2..], 16);
                byte[] value = Hex(MiniJson.AsString(entry["valueHex"]));
                metadata.Add(new MetadataEntry(tag, value));
            }
        }
        return new Options(chunkSize, key, baseNonce, metadata);
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
