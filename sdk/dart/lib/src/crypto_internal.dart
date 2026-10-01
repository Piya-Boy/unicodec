import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cryptography;

import 'error_code.dart';
import 'ubc_exception.dart';

/// Shared AES-256-GCM / HMAC-SHA-256 primitives (SPEC.md sections 3-4), used by both the
/// one-shot and streaming encrypted paths. Keeping a single implementation here means the
/// two paths cannot silently diverge on nonce, AAD, or root-key derivation.
abstract final class CryptoInternal {
  static const int gcmTagSize = 16;
  static final List<int> _rootInfo = 'UBC1 root authentication'.codeUnits;
  static const int _nonceSize = 12;
  static final cryptography.AesGcm _aesGcm = cryptography.AesGcm.with256bits();

  static Uint8List rootKey(Uint8List key, Uint8List baseNonce) {
    final prk = crypto.Hmac(crypto.sha256, baseNonce).convert(key).bytes;
    final info = Uint8List.fromList([..._rootInfo, 0x01]);
    return Uint8List.fromList(crypto.Hmac(crypto.sha256, prk).convert(info).bytes);
  }

  static Uint8List chunkNonce(Uint8List baseNonce, int index) {
    final indexBytes = ByteData(_nonceSize);
    indexBytes.setUint64(0, index, Endian.little);
    final nonce = Uint8List(_nonceSize);
    for (var i = 0; i < _nonceSize; i++) {
      nonce[i] = baseNonce[i] ^ indexBytes.getUint8(i);
    }
    return nonce;
  }

  static Uint8List chunkAad(Uint8List headerBytes, Uint8List metadataDigest, int index) {
    final buffer = ByteData(headerBytes.length + metadataDigest.length + 8);
    final result = buffer.buffer.asUint8List();
    result.setRange(0, headerBytes.length, headerBytes);
    result.setRange(headerBytes.length, headerBytes.length + metadataDigest.length, metadataDigest);
    buffer.setUint64(headerBytes.length + metadataDigest.length, index, Endian.little);
    return result;
  }

  // package:cryptography's AesGcm is Future-based only at the public interface (the sync
  // encryptSync/decryptSync methods live on the internal DartAesGcm implementation class,
  // not exposed through the public AesGcm.with256bits() factory's static type) — confirmed
  // by reading the package source before assuming a sync path existed. This forces the
  // Dart port's encrypted one-shot/streaming API to be async, unlike every prior SDK.
  static Future<Uint8List> gcmEncrypt(Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) async {
    final secretBox = await _aesGcm.encrypt(
      plaintext,
      secretKey: cryptography.SecretKeyData(key),
      nonce: nonce,
      aad: aad,
    );
    return Uint8List.fromList([...secretBox.cipherText, ...secretBox.mac.bytes]);
  }

  /// Throws [UbcException] with [ErrorCode.chunkAuth] on tag failure (never leaves partial
  /// plaintext reachable — package:cryptography's decrypt checks the MAC before the
  /// XOR-decrypt loop runs, confirmed by reading its source before relying on it).
  static Future<Uint8List> gcmDecrypt(Uint8List key, Uint8List nonce, Uint8List body, Uint8List aad) async {
    final cipherTextLength = body.length - gcmTagSize;
    final cipherText = Uint8List.sublistView(body, 0, cipherTextLength);
    final mac = cryptography.Mac(Uint8List.sublistView(body, cipherTextLength).toList());
    final secretBox = cryptography.SecretBox(cipherText, nonce: nonce, mac: mac);
    try {
      final plaintext = await _aesGcm.decrypt(
        secretBox,
        secretKey: cryptography.SecretKeyData(key),
        aad: aad,
      );
      return Uint8List.fromList(plaintext);
    } on cryptography.SecretBoxAuthenticationError {
      throw const UbcException(ErrorCode.chunkAuth);
    }
  }

  static Uint8List sha256(Uint8List data) => Uint8List.fromList(crypto.sha256.convert(data).bytes);
}
