import 'dart:typed_data';

import 'metadata_entry.dart';

/// Decoded plaintext and its metadata entries.
class DecodeResult {
  DecodeResult(this.data, this.metadata);

  final Uint8List data;
  final List<MetadataEntry> metadata;
}
