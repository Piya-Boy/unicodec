import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:test/test.dart';
import 'package:ubc/ubc.dart';

String vectorRoot() => p.normalize(p.join(Directory.current.path, '..', '..', 'spec', 'vectors'));

Uint8List readVector(String relative) => File(p.join(vectorRoot(), relative)).readAsBytesSync();

Uint8List _hex(String value) {
  final result = Uint8List(value.length ~/ 2);
  for (var i = 0; i < value.length; i += 2) {
    result[i ~/ 2] = int.parse(value.substring(i, i + 2), radix: 16);
  }
  return result;
}

final Uint8List _key = _hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
final Uint8List _baseNonce = _hex('f0e0d0c0b0a0908070605040');

void main() {
  test('encodes every encrypted vector byte-exactly', () async {
    expect(
      await Crypto.encodeEncryptedWithFixedNonce(readVector('inputs/empty.bin'), _key, _baseNonce, [], 1 << 20),
      equals(readVector('expected/encrypted-empty.ubc')),
    );
    expect(
      await Crypto.encodeEncryptedWithFixedNonce(readVector('inputs/one-byte.bin'), _key, _baseNonce, [], 1 << 20),
      equals(readVector('expected/encrypted-one-byte.ubc')),
    );
    expect(
      await Crypto.encodeEncryptedWithFixedNonce(readVector('inputs/chunk-1m.bin'), _key, _baseNonce, [], 1 << 20),
      equals(readVector('expected/encrypted-chunk-1m.ubc')),
    );
    expect(
      await Crypto.encodeEncryptedWithFixedNonce(
        readVector('inputs/chunk-1m-plus-one.bin'),
        _key,
        _baseNonce,
        [],
        1 << 20,
      ),
      equals(readVector('expected/encrypted-chunk-1m-plus-one.ubc')),
    );
    expect(
      await Crypto.encodeEncryptedWithFixedNonce(readVector('inputs/multi-3m.bin'), _key, _baseNonce, [], 1 << 20),
      equals(readVector('expected/encrypted-multi-3m.ubc')),
    );

    final entries = [
      MetadataEntry(0x0001, _hex('e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874')),
      MetadataEntry(0x0002, _hex('746578742f706c61696e')),
      MetadataEntry(0x0003, _hex('00a8da769b010000')),
      MetadataEntry(0x1000, _hex('00ff7f')),
    ];
    expect(
      await Crypto.encodeEncryptedWithFixedNonce(readVector('inputs/one-byte.bin'), _key, _baseNonce, entries, 1 << 20),
      equals(readVector('expected/encrypted-metadata.ubc')),
    );
  });

  test('decodes every encrypted vector', () async {
    await _decodeMatchesInput('expected/encrypted-empty.ubc', 'inputs/empty.bin');
    await _decodeMatchesInput('expected/encrypted-one-byte.ubc', 'inputs/one-byte.bin');
    await _decodeMatchesInput('expected/encrypted-chunk-1m.ubc', 'inputs/chunk-1m.bin');
    await _decodeMatchesInput('expected/encrypted-chunk-1m-plus-one.ubc', 'inputs/chunk-1m-plus-one.bin');
    await _decodeMatchesInput('expected/encrypted-multi-3m.ubc', 'inputs/multi-3m.bin');
    await _decodeMatchesInput('expected/encrypted-metadata.ubc', 'inputs/one-byte.bin');
  });

  test('wrong key returns ERR_CHUNK_AUTH on non-empty ciphertext', () async {
    final container = readVector('expected/encrypted-one-byte.ubc');
    final wrongKey = Uint8List.fromList(_key);
    wrongKey[0] ^= 0x01;
    await expectLater(
      Crypto.decodeEncrypted(container, DecodeOptions(key: wrongKey)),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.chunkAuth)),
    );
  });

  test('missing key returns ERR_MISSING_KEY', () async {
    final container = readVector('expected/encrypted-one-byte.ubc');
    await expectLater(
      Crypto.decodeEncrypted(container),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.missingKey)),
    );
  });

  final negativeCases = <String, (ErrorCode, bool)>{
    'negative-chunk-auth.ubc': (ErrorCode.chunkAuth, true),
    'negative-encrypted-short-clen.ubc': (ErrorCode.chunkAuth, true),
    'negative-encrypted-metadata-tamper.ubc': (ErrorCode.chunkAuth, true),
    'negative-missing-key.ubc': (ErrorCode.missingKey, false),
    'negative-encrypted-cap-missing-key.ubc': (ErrorCode.missingKey, false),
  };
  negativeCases.forEach((name, spec) {
    final (expected, suppliesKey) = spec;
    test('negative vector $name uses stable error code', () async {
      final container = readVector('expected/$name');
      final options = suppliesKey ? DecodeOptions(key: _key) : const DecodeOptions();
      await expectLater(
        Crypto.decodeEncrypted(container, options),
        throwsA(isA<UbcException>().having((e) => e.code, 'code', expected)),
      );
    });
  });

  test('encrypted-empty wrong key returns ERR_ROOT_MISMATCH', () async {
    final container = readVector('expected/negative-encrypted-empty-wrong-key.ubc');
    final wrongKey = _hex('ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    await expectLater(
      Crypto.decodeEncrypted(container, DecodeOptions(key: wrongKey)),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.rootMismatch)),
    );
  });

  test('root key matches shared known answer', () {
    final key = _hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    final baseNonce = _hex('f0e0d0c0b0a0908070605040');
    final expectedRootKey = _hex('52c04b400d73df15d8a0db6ba58919f46fe822fff200fb50d8dee097af3c688c');
    expect(Crypto.rootKeyForTesting(key, baseNonce), equals(expectedRootKey));
  });
}

Future<void> _decodeMatchesInput(String container, String input) async {
  final result = await Crypto.decodeEncrypted(readVector(container), DecodeOptions(key: _key));
  expect(result.data, equals(readVector(input)), reason: container);
}
