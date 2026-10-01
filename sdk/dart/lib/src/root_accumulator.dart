import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// SPEC.md section 4's root_hash accumulator: plain SHA-256 over root_input for plain
/// containers, or a keyed HMAC-SHA-256 (HKDF-derived root_key) for encrypted containers.
///
/// package:crypto exposes no public incremental-hash sink (its chunked-conversion API's
/// DigestSink type is package-internal — confirmed while building Payload.dart), so this
/// accumulates the root input bytes directly and hashes once in [finish].
class RootAccumulator {
  RootAccumulator._(this._hmacKey);

  final Uint8List? _hmacKey;
  final BytesBuilder _buffer = BytesBuilder();
  Uint8List? _finished;

  factory RootAccumulator.plain() => RootAccumulator._(null);

  factory RootAccumulator.keyed(Uint8List rootKey) => RootAccumulator._(rootKey);

  void update(Uint8List data) {
    if (_finished != null) {
      throw StateError('RootAccumulator already finished');
    }
    _buffer.add(data);
  }

  Uint8List finish() {
    final cached = _finished;
    if (cached != null) {
      return cached;
    }
    final input = _buffer.toBytes();
    final key = _hmacKey;
    final result = key == null
        ? Uint8List.fromList(crypto.sha256.convert(input).bytes)
        : Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(input).bytes);
    _finished = result;
    return result;
  }
}
