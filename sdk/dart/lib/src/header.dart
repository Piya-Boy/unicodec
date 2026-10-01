import 'dart:typed_data';

import 'error_code.dart';
import 'ubc_exception.dart';

/// UBC v1 fixed 40-byte header (SPEC.md section 2.1).
///
/// Dart's native `int` is a signed 64-bit integer on the VM (this SDK targets the VM, not
/// dart2js/web, where int narrows to 53-bit-safe doubles). chunk_count/total_size are true
/// uint64 per spec; matching the Java/PHP ports' documented tradeoff, every bit pattern is
/// treated as structurally valid (no range rejection) but magnitude comparisons use plain
/// signed operators rather than a hand-rolled unsigned-compare helper — real payloads never
/// approach the 2^63 boundary where the difference would matter.
class Header {
  static const int size = 40;
  static const int version = 1;

  static const int hashSha256 = 0;
  static const int hashHmacSha256 = 1;
  static const int aeadNone = 0;
  static const int aeadAes256Gcm = 1;

  static const int flagEncrypted = 1;
  static const int flagHasMetadata = 1 << 1;

  static const int _allowedFlags = flagEncrypted | flagHasMetadata;
  static const int _maxEncryptedChunkSize = 0xFFFFFFEF;
  static final Uint8List _magic = Uint8List.fromList('UBC1'.codeUnits);
  static final Uint8List _zeroNonce = Uint8List(12);

  Header({
    required this.flags,
    required this.hashAlgo,
    required this.aeadAlgo,
    required this.chunkSize,
    required this.chunkCount,
    required this.totalSize,
    required Uint8List baseNonce,
  }) : baseNonce = Uint8List.fromList(baseNonce) {
    _validate();
  }

  final int flags;
  final int hashAlgo;
  final int aeadAlgo;
  final int chunkSize;
  final int chunkCount;
  final int totalSize;
  final Uint8List baseNonce;

  bool get encrypted => (flags & flagEncrypted) != 0;
  bool get hasMetadata => (flags & flagHasMetadata) != 0;

  Uint8List toBytes() {
    final buffer = Uint8List(size);
    final data = ByteData.view(buffer.buffer);
    buffer.setRange(0, 4, _magic);
    buffer[4] = version;
    buffer[5] = flags;
    buffer[6] = hashAlgo;
    buffer[7] = aeadAlgo;
    data.setUint32(8, chunkSize, Endian.little);
    data.setUint64(12, chunkCount, Endian.little);
    data.setUint64(20, totalSize, Endian.little);
    buffer.setRange(28, 40, baseNonce);
    return buffer;
  }

  static Header parse(Uint8List data, [int offset = 0]) {
    if (data.length - offset < size) {
      throw const UbcException(ErrorCode.truncated);
    }
    for (var i = 0; i < 4; i++) {
      if (data[offset + i] != _magic[i]) {
        throw const UbcException(ErrorCode.badMagic);
      }
    }

    final view = ByteData.sublistView(data, offset, offset + size);
    final headerVersion = view.getUint8(4);
    final flags = view.getUint8(5);
    final hashAlgo = view.getUint8(6);
    final aeadAlgo = view.getUint8(7);
    final chunkSize = view.getUint32(8, Endian.little);
    final chunkCount = view.getUint64(12, Endian.little);
    final totalSize = view.getUint64(20, Endian.little);
    final baseNonce = Uint8List.sublistView(data, offset + 28, offset + 40);

    if (headerVersion != version) {
      throw const UbcException(ErrorCode.unsupportedVersion);
    }
    return Header(
      flags: flags,
      hashAlgo: hashAlgo,
      aeadAlgo: aeadAlgo,
      chunkSize: chunkSize,
      chunkCount: chunkCount,
      totalSize: totalSize,
      baseNonce: baseNonce,
    );
  }

  void _validate() {
    if (hashAlgo != hashSha256 && hashAlgo != hashHmacSha256) {
      throw const UbcException(ErrorCode.unsupportedAlgorithm);
    }
    if (aeadAlgo != aeadNone && aeadAlgo != aeadAes256Gcm) {
      throw const UbcException(ErrorCode.unsupportedAlgorithm);
    }
    if ((flags & ~_allowedFlags) != 0) {
      throw const UbcException(ErrorCode.reservedBits);
    }
    if (chunkSize < 0 || chunkSize > 0xFFFFFFFF) {
      throw const UbcException(ErrorCode.reservedBits);
    }
    if (baseNonce.length != 12) {
      throw const UbcException(ErrorCode.reservedBits);
    }

    if (encrypted) {
      if (aeadAlgo != aeadAes256Gcm ||
          hashAlgo != hashHmacSha256 ||
          chunkSize == 0 ||
          chunkSize > _maxEncryptedChunkSize) {
        throw const UbcException(ErrorCode.reservedBits);
      }
      return;
    }
    if (aeadAlgo != aeadNone ||
        hashAlgo != hashSha256 ||
        chunkSize == 0 ||
        !_bytesEqual(baseNonce, _zeroNonce)) {
      throw const UbcException(ErrorCode.reservedBits);
    }
  }
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
