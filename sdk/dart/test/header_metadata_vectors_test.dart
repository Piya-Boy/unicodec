import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:test/test.dart';
import 'package:ubc/ubc.dart';

String vectorRoot() {
  // `dart test` always runs with the package root (sdk/dart/) as the working directory.
  return p.normalize(p.join(Directory.current.path, '..', '..', 'spec', 'vectors'));
}

Uint8List readVector(String name) => File(p.join(vectorRoot(), 'expected', name)).readAsBytesSync();

void main() {
  test('all positive vector headers round-trip byte-exactly', () {
    final expectedDir = Directory(p.join(vectorRoot(), 'expected'));
    final files = expectedDir
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith('.ubc'))
        .toList();
    expect(files, isNotEmpty);
    for (final file in files) {
      final name = p.basename(file.path);
      if (name.startsWith('negative-')) {
        continue;
      }
      final container = file.readAsBytesSync();
      final header = Header.parse(container);
      expect(header.toBytes(), equals(container.sublist(0, Header.size)), reason: name);
    }
  });

  test('vector metadata round-trips byte-exactly', () {
    final container = readVector('plain-metadata.ubc');
    final header = Header.parse(container);
    expect(header.hasMetadata, isTrue);

    final result = Metadata.parse(container, Header.size);
    final reencoded = Metadata.encode(result.entries);
    final expected = container.sublist(Header.size, Header.size + result.consumed);
    expect(reencoded, equals(expected));
  });

  group('header negative vectors use stable error codes', () {
    final cases = <String, ErrorCode>{
      'negative-bad-magic.ubc': ErrorCode.badMagic,
      'negative-version-two.ubc': ErrorCode.unsupportedVersion,
      'negative-hash-algo.ubc': ErrorCode.unsupportedAlgorithm,
      'negative-aead-algo.ubc': ErrorCode.unsupportedAlgorithm,
      'negative-reserved-flag.ubc': ErrorCode.reservedBits,
      'negative-inconsistent-encryption.ubc': ErrorCode.reservedBits,
      'negative-zero-chunk-size.ubc': ErrorCode.reservedBits,
      'negative-encrypted-zero-chunk-size.ubc': ErrorCode.reservedBits,
      'negative-encrypted-oversized-chunk-size.ubc': ErrorCode.reservedBits,
    };
    cases.forEach((name, expected) {
      test(name, () {
        final container = readVector(name);
        expect(
          () => Header.parse(container),
          throwsA(isA<UbcException>().having((e) => e.code, 'code', expected)),
        );
      });
    });
  });

  group('metadata negative vectors use stable error codes', () {
    for (final name in [
      'negative-meta-out-of-order.ubc',
      'negative-meta-duplicate.ubc',
      'negative-meta-overrun.ubc',
      'negative-empty-metadata.ubc',
      'negative-encrypted-reserved-metadata.ubc',
      'negative-reserved-metadata.ubc',
    ]) {
      test(name, () {
        final container = readVector(name);
        expect(
          () => Metadata.parse(container, Header.size),
          throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.metaMalformed)),
        );
      });
    }
  });

  test('metadata encoder sorts tags and rejects duplicates', () {
    final entries = [
      MetadataEntry(0x1000, Uint8List.fromList([1])),
      MetadataEntry(0x0001, Uint8List.fromList('example.txt'.codeUnits)),
    ];
    final encoded = Metadata.encode(entries);
    final result = Metadata.parse(encoded);
    expect(result.entries[0].tag, 0x0001);
    expect(result.entries[1].tag, 0x1000);

    final duplicates = [
      MetadataEntry(1, Uint8List(0)),
      MetadataEntry(1, Uint8List(0)),
    ];
    expect(
      () => Metadata.encode(duplicates),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.metaMalformed)),
    );
  });

  test('metadata length cap is checked before copying entries', () {
    final oversized = Uint8List.fromList([0x01, 0x00, 0x00, 0x01]); // declares > 16 MiB
    expect(
      () => Metadata.parse(oversized, 0, 16 << 20),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.metaMalformed)),
    );

    final metadata = Metadata.encode([MetadataEntry(0x1000, Uint8List.fromList([1]))]);
    expect(
      () => Metadata.parse(metadata, 0, 6),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.metaMalformed)),
    );
  });
}
