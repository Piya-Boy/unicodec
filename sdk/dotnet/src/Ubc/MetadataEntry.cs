namespace Ubc;

/// <summary>One UBC metadata TLV entry (SPEC.md section 2.2.1).</summary>
public sealed class MetadataEntry
{
    public ushort Tag { get; }
    public byte[] Value { get; }

    public MetadataEntry(ushort tag, byte[] value)
    {
        Tag = tag;
        Value = value;
    }

    public override bool Equals(object? obj) =>
        obj is MetadataEntry other && Tag == other.Tag && Value.AsSpan().SequenceEqual(other.Value);

    public override int GetHashCode() => HashCode.Combine(Tag, Value.Length);
}
