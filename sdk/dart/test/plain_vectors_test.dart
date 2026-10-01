import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:test/test.dart';
import 'package:ubc/ubc.dart';

String vectorRoot() => p.normalize(p.join(Directory.current.path, '..', '..', 'spec', 'vectors'));

Uint8List readVector(String relative) => File(p.join(vectorRoot(), relative)).readAsBytesSync();

void main() {
  test('encodes every plain vector byte-exactly', () {
    expect(
      Payload.encodePlain(readVector('inputs/empty.bin'), [], 1 << 20),
      equals(readVector('expected/plain-empty.ubc')),
    );
    expect(
      Payload.encodePlain(readVector('inputs/one-byte.bin'), [], 1 << 20),
      equals(readVector('expected/plain-one-byte.ubc')),
    );
    expect(
      Payload.encodePlain(readVector('inputs/chunk-1m.bin'), [], 1 << 20),
      equals(readVector('expected/plain-chunk-1m.ubc')),
    );
    expect(
      Payload.encodePlain(readVector('inputs/chunk-1m-plus-one.bin'), [], 1 << 20),
      equals(readVector('expected/plain-chunk-1m-plus-one.ubc')),
    );
    expect(
      Payload.encodePlain(readVector('inputs/multi-3m.bin'), [], 1 << 20),
      equals(readVector('expected/plain-multi-3m.ubc')),
    );

    final entries = [
      MetadataEntry(0x0001, _hex('e0b8a3e0b8b2e0b8a2e0b887e0b8b2e0b8992d323032362e747874')),
      MetadataEntry(0x0002, _hex('746578742f706c61696e')),
      MetadataEntry(0x0003, _hex('00a8da769b010000')),
      MetadataEntry(0x1000, _hex('00ff7f')),
    ];
    expect(
      Payload.encodePlain(readVector('inputs/one-byte.bin'), entries, 1 << 20),
      equals(readVector('expected/plain-metadata.ubc')),
    );
  });

  test('decodes every plain vector', () {
    _decodeMatchesInput('expected/plain-empty.ubc', 'inputs/empty.bin');
    _decodeMatchesInput('expected/plain-one-byte.ubc', 'inputs/one-byte.bin');
    _decodeMatchesInput('expected/plain-chunk-1m.ubc', 'inputs/chunk-1m.bin');
    _decodeMatchesInput('expected/plain-chunk-1m-plus-one.ubc', 'inputs/chunk-1m-plus-one.bin');
    _decodeMatchesInput('expected/plain-multi-3m.ubc', 'inputs/multi-3m.bin');
    _decodeMatchesInput('expected/plain-metadata.ubc', 'inputs/one-byte.bin');
  });

  test('flipped plain payload returns ERR_ROOT_MISMATCH', () {
    final container = Uint8List.fromList(readVector('expected/plain-chunk-1m.ubc'));
    container[Header.size + 4] ^= 0x01;
    expect(
      () => Payload.decodePlain(container),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.rootMismatch)),
    );
  });

  final negativeCases = <String, ErrorCode>{
    'negative-truncated.ubc': ErrorCode.truncated,
    'negative-root-mismatch.ubc': ErrorCode.rootMismatch,
    'negative-trailing-data.ubc': ErrorCode.trailingData,
    'negative-oversized-clen.ubc': ErrorCode.truncated,
  };
  negativeCases.forEach((name, expected) {
    test('negative vector $name uses stable error code', () {
      final container = readVector('expected/$name');
      expect(
        () => Payload.decodePlain(container),
        throwsA(isA<UbcException>().having((e) => e.code, 'code', expected)),
      );
    });
  });
}

void _decodeMatchesInput(String container, String input) {
  final result = Payload.decodePlain(readVector(container));
  expect(result.data, equals(readVector(input)), reason: container);
}

Uint8List _hex(String value) {
  final result = Uint8List(value.length ~/ 2);
  for (var i = 0; i < value.length; i += 2) {
    result[i ~/ 2] = int.parse(value.substring(i, i + 2), radix: 16);
  }
  return result;
}
