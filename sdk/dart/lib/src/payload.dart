import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'decode_options.dart';
import 'decode_result.dart';
import 'error_code.dart';
import 'header.dart';
import 'metadata.dart';
import 'metadata_entry.dart';
import 'ubc_exception.dart';

/// One-shot plain (non-encrypted) UBC v1 encoding and decoding (SPEC.md sections 2-4).
abstract final class Payload {
  static const int defaultChunkSize = 1 << 20;
  static const int _footerSize = 36;
  static final Uint8List _footerMagic = Uint8List.fromList('UBCE'.codeUnits);

  static Uint8List encodePlain(Uint8List data, List<MetadataEntry> entries, int chunkSize) {
    if (chunkSize <= 0 || chunkSize > 0xFFFFFFFF) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be a positive uint32');
    }
    final metadata = Metadata.encode(entries);
    final dataLength = data.length;
    final chunkCount = dataLength == 0 ? 0 : (dataLength + chunkSize - 1) ~/ chunkSize;

    final header = Header(
      flags: metadata.isNotEmpty ? Header.flagHasMetadata : 0,
      hashAlgo: Header.hashSha256,
      aeadAlgo: Header.aeadNone,
      chunkSize: chunkSize,
      chunkCount: chunkCount,
      totalSize: dataLength,
      baseNonce: Uint8List(12),
    );
    final headerBytes = header.toBytes();

    final output = BytesBuilder()
      ..add(headerBytes)
      ..add(metadata);

    final rootInput = BytesBuilder()
      ..add(headerBytes)
      ..add(metadata);

    final clenBuffer = ByteData(4);
    for (var offset = 0; offset < dataLength; offset += chunkSize) {
      final length = (dataLength - offset) < chunkSize ? dataLength - offset : chunkSize;
      final chunk = Uint8List.sublistView(data, offset, offset + length);
      clenBuffer.setUint32(0, length, Endian.little);
      output
        ..add(clenBuffer.buffer.asUint8List())
        ..add(chunk);
      rootInput.add(sha256.convert(chunk).bytes);
    }

    final rootDigest = Uint8List.fromList(sha256.convert(rootInput.toBytes()).bytes);
    output
      ..add(rootDigest)
      ..add(_footerMagic);
    return output.toBytes();
  }

  static DecodeResult decodePlain(Uint8List container, [DecodeOptions? options]) {
    final opts = options ?? const DecodeOptions();

    final header = Header.parse(container);
    final headerBytes = Uint8List.sublistView(container, 0, Header.size);
    var offset = Header.size;

    var entries = <MetadataEntry>[];
    var metadataRegion = Uint8List(0);
    if (header.hasMetadata) {
      final result = Metadata.parse(container, offset, _boundedCap(opts.maxMetaBytes));
      entries = result.entries;
      metadataRegion = Uint8List.sublistView(container, offset, offset + result.consumed);
      offset += result.consumed;
    }

    if (header.encrypted) {
      throw const UbcException(ErrorCode.missingKey);
    }
    if (header.chunkCount > opts.maxChunkCount || header.totalSize > opts.maxTotalSize) {
      throw const UbcException(ErrorCode.truncated);
    }

    final rootInput = BytesBuilder()
      ..add(headerBytes)
      ..add(metadataRegion);

    final plaintext = BytesBuilder();
    var remaining = header.totalSize;
    final containerLength = container.length;
    for (var i = 0; i < header.chunkCount; i++) {
      if (containerLength - offset < 4) {
        throw const UbcException(ErrorCode.truncated);
      }
      final chunkLength = ByteData.sublistView(container, offset, offset + 4).getUint32(0, Endian.little);
      offset += 4;
      if (chunkLength > opts.maxChunkLen || chunkLength > containerLength - offset) {
        throw const UbcException(ErrorCode.truncated);
      }
      if (chunkLength > remaining) {
        throw const UbcException(ErrorCode.rootMismatch);
      }
      final chunk = Uint8List.sublistView(container, offset, offset + chunkLength);
      rootInput.add(sha256.convert(chunk).bytes);
      plaintext.add(chunk);
      offset += chunkLength;
      remaining -= chunkLength;
    }

    if (containerLength - offset < _footerSize) {
      throw const UbcException(ErrorCode.truncated);
    }
    final footerRoot = Uint8List.sublistView(container, offset, offset + 32);
    final footerMagic = Uint8List.sublistView(container, offset + 32, offset + _footerSize);
    if (!_bytesEqual(footerMagic, _footerMagic)) {
      throw const UbcException(ErrorCode.truncated);
    }
    final computedRoot = Uint8List.fromList(sha256.convert(rootInput.toBytes()).bytes);
    final plaintextBytes = plaintext.toBytes();
    if (plaintextBytes.length != header.totalSize || !_constantTimeEqual(computedRoot, footerRoot)) {
      throw const UbcException(ErrorCode.rootMismatch);
    }
    if (containerLength != offset + _footerSize) {
      throw const UbcException(ErrorCode.trailingData);
    }
    return DecodeResult(plaintextBytes, entries);
  }

  static int _boundedCap(int cap) => cap > 0xFFFFFFFF ? 0xFFFFFFFF : cap;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

/// Constant-time comparison for the root hash (SPEC.md section 4). package:crypto has no
/// built-in constant-time compare, so this is hand-rolled: XOR every byte and OR the
/// accumulator, never short-circuiting on the first mismatch.
bool _constantTimeEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) {
    return false;
  }
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
