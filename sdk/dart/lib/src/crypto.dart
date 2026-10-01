import 'dart:math';
import 'dart:typed_data';

import 'crypto_internal.dart';
import 'decode_options.dart';
import 'decode_result.dart';
import 'error_code.dart';
import 'header.dart';
import 'metadata.dart';
import 'metadata_entry.dart';
import 'root_accumulator.dart';
import 'ubc_exception.dart';

/// One-shot AES-256-GCM encrypted UBC v1 encoding and decoding (SPEC.md sections 3-4).
///
/// Async throughout: package:cryptography's AesGcm only exposes a Future-based public API
/// (see crypto_internal.dart), unlike every prior SDK's synchronous one-shot encode/decode.
abstract final class Crypto {
  static const int _keySize = 32;
  static const int _nonceSize = 12;
  static const int _footerSize = 36;
  static final Uint8List _footerMagic = Uint8List.fromList('UBCE'.codeUnits);

  /// Encodes with a CSPRNG-generated base_nonce. Production callers MUST use this.
  static Future<Uint8List> encodeEncrypted(
    Uint8List data,
    Uint8List key,
    List<MetadataEntry> entries,
    int chunkSize,
  ) {
    final baseNonce = Uint8List(_nonceSize);
    final random = Random.secure();
    for (var i = 0; i < _nonceSize; i++) {
      baseNonce[i] = random.nextInt(256);
    }
    return encodeEncryptedWithFixedNonce(data, key, baseNonce, entries, chunkSize);
  }

  /// Deterministic encoding for conformance vectors/tests only — never reuse a base_nonce in production.
  static Future<Uint8List> encodeEncryptedWithFixedNonce(
    Uint8List data,
    Uint8List key,
    Uint8List baseNonce,
    List<MetadataEntry> entries,
    int chunkSize,
  ) async {
    _validateEncodeKey(key);
    if (baseNonce.length != _nonceSize) {
      throw const UbcException(ErrorCode.reservedBits);
    }
    if (chunkSize <= 0 || chunkSize > 0xFFFFFFEF) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be a positive uint32 <= 0xffff_ffef when encrypted');
    }

    final metadata = Metadata.encode(entries);
    final dataLength = data.length;
    final chunkCount = dataLength == 0 ? 0 : (dataLength + chunkSize - 1) ~/ chunkSize;

    final header = Header(
      flags: Header.flagEncrypted | (metadata.isNotEmpty ? Header.flagHasMetadata : 0),
      hashAlgo: Header.hashHmacSha256,
      aeadAlgo: Header.aeadAes256Gcm,
      chunkSize: chunkSize,
      chunkCount: chunkCount,
      totalSize: dataLength,
      baseNonce: baseNonce,
    );
    final headerBytes = header.toBytes();
    final metadataDigest = CryptoInternal.sha256(metadata);

    final root = RootAccumulator.keyed(CryptoInternal.rootKey(key, baseNonce));
    root.update(headerBytes);
    root.update(metadata);

    final output = BytesBuilder()
      ..add(headerBytes)
      ..add(metadata);

    final clenBuffer = ByteData(4);
    var index = 0;
    for (var offset = 0; offset < dataLength; offset += chunkSize, index++) {
      final length = (dataLength - offset) < chunkSize ? dataLength - offset : chunkSize;
      final chunk = Uint8List.sublistView(data, offset, offset + length);
      final aad = CryptoInternal.chunkAad(headerBytes, metadataDigest, index);
      final ciphertext = await CryptoInternal.gcmEncrypt(key, CryptoInternal.chunkNonce(baseNonce, index), chunk, aad);
      clenBuffer.setUint32(0, ciphertext.length, Endian.little);
      output
        ..add(clenBuffer.buffer.asUint8List())
        ..add(ciphertext);
      root.update(CryptoInternal.sha256(ciphertext));
    }

    output
      ..add(root.finish())
      ..add(_footerMagic);
    return output.toBytes();
  }

  static Future<DecodeResult> decodeEncrypted(Uint8List container, [DecodeOptions? options]) async {
    final opts = options ?? const DecodeOptions();
    final key = opts.key;

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

    if (!header.encrypted || key == null || key.length != _keySize) {
      throw const UbcException(ErrorCode.missingKey);
    }
    if (header.chunkCount > opts.maxChunkCount || header.totalSize > opts.maxTotalSize) {
      throw const UbcException(ErrorCode.truncated);
    }

    final metadataDigest = CryptoInternal.sha256(metadataRegion);
    final baseNonce = header.baseNonce;
    final root = RootAccumulator.keyed(CryptoInternal.rootKey(key, baseNonce));
    root.update(headerBytes);
    root.update(metadataRegion);

    final plaintext = BytesBuilder();
    var remaining = header.totalSize;
    final containerLength = container.length;
    var index = 0;
    for (var i = 0; i < header.chunkCount; i++, index++) {
      if (containerLength - offset < 4) {
        throw const UbcException(ErrorCode.truncated);
      }
      final chunkLength = ByteData.sublistView(container, offset, offset + 4).getUint32(0, Endian.little);
      offset += 4;
      if (chunkLength > opts.maxChunkLen || chunkLength > containerLength - offset) {
        throw const UbcException(ErrorCode.truncated);
      }
      final body = Uint8List.sublistView(container, offset, offset + chunkLength);
      root.update(CryptoInternal.sha256(body));
      if (chunkLength < CryptoInternal.gcmTagSize) {
        throw const UbcException(ErrorCode.chunkAuth);
      }
      final aad = CryptoInternal.chunkAad(headerBytes, metadataDigest, index);
      final plaintextChunk = await CryptoInternal.gcmDecrypt(key, CryptoInternal.chunkNonce(baseNonce, index), body, aad);
      offset += chunkLength;
      if (plaintextChunk.length > remaining) {
        throw const UbcException(ErrorCode.rootMismatch);
      }
      plaintext.add(plaintextChunk);
      remaining -= plaintextChunk.length;
    }

    if (containerLength - offset < _footerSize) {
      throw const UbcException(ErrorCode.truncated);
    }
    final footerRoot = Uint8List.sublistView(container, offset, offset + 32);
    final footerMagic = Uint8List.sublistView(container, offset + 32, offset + _footerSize);
    if (!_bytesEqual(footerMagic, _footerMagic)) {
      throw const UbcException(ErrorCode.truncated);
    }
    final plaintextBytes = plaintext.toBytes();
    if (plaintextBytes.length != header.totalSize || !_constantTimeEqual(root.finish(), footerRoot)) {
      throw const UbcException(ErrorCode.rootMismatch);
    }
    if (containerLength != offset + _footerSize) {
      throw const UbcException(ErrorCode.trailingData);
    }
    return DecodeResult(plaintextBytes, entries);
  }

  /// Internal: exposed only so conformance tests can check this against the shared known-answer fixture.
  static Uint8List rootKeyForTesting(Uint8List key, Uint8List baseNonce) => CryptoInternal.rootKey(key, baseNonce);

  static void _validateEncodeKey(Uint8List key) {
    if (key.length != _keySize) {
      throw const UbcException(ErrorCode.reservedBits);
    }
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
