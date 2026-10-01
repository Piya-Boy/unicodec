package dev.ubc;

import java.util.List;

/** Decoded plaintext and its metadata entries. */
public final class DecodeResult {
    public final byte[] data;
    public final List<MetadataEntry> metadata;

    public DecodeResult(byte[] data, List<MetadataEntry> metadata) {
        this.data = data;
        this.metadata = metadata;
    }
}
