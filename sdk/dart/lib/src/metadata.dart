import 'dart:convert';
import 'dart:typed_data';

import 'error_code.dart';
import 'metadata_entry.dart';
import 'ubc_exception.dart';

/// Result of [Metadata.parse]: decoded entries and total bytes consumed from the input.
class MetadataParseResult {
  MetadataParseResult(this.entries, this.consumed);

  final List<MetadataEntry> entries;
  final int consumed;
}

/// UBC metadata TLV block encoding and parsing (SPEC.md section 2.2).
abstract final class Metadata {
  static const int tagFilename = 0x0001;
  static const int tagMimeType = 0x0002;
  static const int tagCreatedAt = 0x0003;

  static Uint8List encode(List<MetadataEntry> entries) {
    final ordered = List<MetadataEntry>.of(entries)
      ..sort((a, b) => a.tag.compareTo(b.tag));
    if (ordered.isEmpty) {
      return Uint8List(0);
    }

    final body = BytesBuilder();
    int? previousTag;
    for (final entry in ordered) {
      _validateEntry(entry);
      if (previousTag == entry.tag) {
        throw const UbcException(ErrorCode.metaMalformed);
      }
      previousTag = entry.tag;
      if (entry.value.length > 0xFFFFFFFF || body.length + 6 + entry.value.length > 0xFFFFFFFF) {
        throw const UbcException(ErrorCode.metaMalformed);
      }
      final entryHeader = ByteData(6)
        ..setUint16(0, entry.tag, Endian.little)
        ..setUint32(2, entry.value.length, Endian.little);
      body
        ..add(entryHeader.buffer.asUint8List())
        ..add(entry.value);
    }
    final bodyBytes = body.toBytes();
    final lengthPrefix = ByteData(4)..setUint32(0, bodyBytes.length, Endian.little);
    return Uint8List.fromList([...lengthPrefix.buffer.asUint8List(), ...bodyBytes]);
  }

  static MetadataParseResult parse(Uint8List data, [int offset = 0, int? maxBytes]) {
    if (data.length - offset < 4) {
      throw const UbcException(ErrorCode.metaMalformed);
    }
    final metadataLength = ByteData.sublistView(data, offset, offset + 4).getUint32(0, Endian.little);
    final available = data.length - offset - 4;
    if (metadataLength == 0 || (maxBytes != null && metadataLength > maxBytes) || metadataLength > available) {
      throw const UbcException(ErrorCode.metaMalformed);
    }

    final end = offset + 4 + metadataLength;
    final entries = <MetadataEntry>[];
    var cursor = offset + 4;
    int? previousTag;
    while (cursor < end) {
      if (end - cursor < 6) {
        throw const UbcException(ErrorCode.metaMalformed);
      }
      final entryHeader = ByteData.sublistView(data, cursor, cursor + 6);
      final tag = entryHeader.getUint16(0, Endian.little);
      final valueLength = entryHeader.getUint32(2, Endian.little);
      cursor += 6;
      if (valueLength > end - cursor || (previousTag != null && tag <= previousTag)) {
        throw const UbcException(ErrorCode.metaMalformed);
      }
      final value = Uint8List.sublistView(data, cursor, cursor + valueLength);
      final entry = MetadataEntry(tag, value);
      _validateEntry(entry);
      entries.add(entry);
      previousTag = tag;
      cursor += valueLength;
    }
    return MetadataParseResult(entries, end - offset);
  }

  static void _validateEntry(MetadataEntry entry) {
    if (entry.tag < 0 || entry.tag > 0xFFFF) {
      throw const UbcException(ErrorCode.metaMalformed);
    }
    if (entry.tag == tagFilename) {
      if (_startsWithBom(entry.value) || entry.value.contains(0)) {
        throw const UbcException(ErrorCode.metaMalformed);
      }
      if (!_isValidUtf8(entry.value)) {
        throw const UbcException(ErrorCode.metaMalformed);
      }
    } else if (entry.tag == tagMimeType) {
      for (final byte in entry.value) {
        if (byte == 0 || byte > 0x7F) {
          throw const UbcException(ErrorCode.metaMalformed);
        }
      }
    } else if (entry.tag == tagCreatedAt) {
      if (entry.value.length != 8) {
        throw const UbcException(ErrorCode.metaMalformed);
      }
    }
  }

  static bool _startsWithBom(Uint8List value) =>
      value.length >= 3 && value[0] == 0xEF && value[1] == 0xBB && value[2] == 0xBF;

  static bool _isValidUtf8(Uint8List value) {
    try {
      const Utf8Decoder(allowMalformed: false).convert(value);
      return true;
    } on FormatException {
      return false;
    }
  }
}
