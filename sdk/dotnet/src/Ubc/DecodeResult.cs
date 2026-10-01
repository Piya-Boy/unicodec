namespace Ubc;

/// <summary>Decoded plaintext and its metadata entries.</summary>
public sealed class DecodeResult
{
    public byte[] Data { get; }
    public List<MetadataEntry> Metadata { get; }

    public DecodeResult(byte[] data, List<MetadataEntry> metadata)
    {
        Data = data;
        Metadata = metadata;
    }
}
