package dev.ubc;

import java.util.Arrays;

/** One UBC metadata TLV entry (SPEC.md section 2.2.1). */
public final class MetadataEntry {
    public final int tag;
    public final byte[] value;

    public MetadataEntry(int tag, byte[] value) {
        this.tag = tag;
        this.value = value;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof MetadataEntry)) {
            return false;
        }
        MetadataEntry that = (MetadataEntry) other;
        return tag == that.tag && Arrays.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return 31 * tag + Arrays.hashCode(value);
    }
}
