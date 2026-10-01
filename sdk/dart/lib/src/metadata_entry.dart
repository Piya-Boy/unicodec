import 'dart:typed_data';

/// One UBC metadata TLV entry (SPEC.md section 2.2.1).
class MetadataEntry {
  MetadataEntry(this.tag, Uint8List value) : value = Uint8List.fromList(value);

  final int tag;
  final Uint8List value;

  @override
  bool operator ==(Object other) {
    if (other is! MetadataEntry || other.tag != tag || other.value.length != value.length) {
      return false;
    }
    for (var i = 0; i < value.length; i++) {
      if (other.value[i] != value[i]) {
        return false;
      }
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(tag, value.length);
}
