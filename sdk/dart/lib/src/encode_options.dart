import 'dart:typed_data';

import 'error_code.dart';
import 'payload.dart';
import 'ubc_exception.dart';

/// Options for a streaming Encoder. [baseNonce] exists only for deterministic conformance
/// tests; production callers must leave it null so a CSPRNG nonce is generated.
class EncodeOptions {
  EncodeOptions({
    this.chunkSize = Payload.defaultChunkSize,
    this.key,
    this.baseNonce,
  }) {
    if (chunkSize <= 0 || chunkSize > 0xFFFFFFFF) {
      throw const UbcException(ErrorCode.reservedBits);
    }
    if (key != null && key!.length != 32) {
      throw const UbcException(ErrorCode.reservedBits);
    }
    if (baseNonce != null && baseNonce!.length != 12) {
      throw const UbcException(ErrorCode.reservedBits);
    }
    if (key == null && baseNonce != null) {
      throw const UbcException(ErrorCode.reservedBits);
    }
  }

  final int chunkSize;
  final Uint8List? key;
  final Uint8List? baseNonce;

  EncodeOptions withKey(Uint8List? key) => EncodeOptions(chunkSize: chunkSize, key: key, baseNonce: baseNonce);

  EncodeOptions withChunkSize(int chunkSize) => EncodeOptions(chunkSize: chunkSize, key: key, baseNonce: baseNonce);
}
