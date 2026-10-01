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

/// A request-based source over an in-memory byte array, honoring the requested length
/// (fewer bytes near EOF, empty once exhausted).
Future<Uint8List> Function(int) memorySource(Uint8List data) {
  var offset = 0;
  return (int length) async {
    if (offset >= data.length) {
      return Uint8List(0);
    }
    final end = (offset + length) > data.length ? data.length : offset + length;
    final chunk = Uint8List.sublistView(data, offset, end);
    offset = end;
    return chunk;
  };
}

/// Same as [memorySource] but only ever hands back 1 byte per call, regardless of the
/// requested length.
Future<Uint8List> Function(int) oneByteAtATimeSource(Uint8List data) {
  var offset = 0;
  return (int length) async {
    if (offset >= data.length) {
      return Uint8List(0);
    }
    final chunk = Uint8List.sublistView(data, offset, offset + 1);
    offset += 1;
    return chunk;
  };
}

Future<Uint8List> collectSink() async => Uint8List(0);

void main() {
  test('streamed plain output is byte-exact and fragmented decode round-trips', () async {
    final input = readVector('inputs/multi-3m.bin');
    final sink = BytesBuilder();
    final encoder = Streaming.newEncoder([], EncodeOptions(chunkSize: 1 << 20));
    final third = input.length ~/ 3;
    await encoder.write(Uint8List.sublistView(input, 0, third));
    await encoder.write(Uint8List.sublistView(input, third));
    await encoder.finish((bytes) async => sink.add(bytes));
    final streamed = sink.toBytes();
    expect(streamed, equals(readVector('expected/plain-multi-3m.ubc')));

    final decoder = await Streaming.newDecoder(oneByteAtATimeSource(streamed));
    final decoded = await decoder.readAll();
    expect(decoded, equals(input));
  });

  test('streamed encrypted output is byte-exact and authenticates before release', () async {
    final input = readVector('inputs/chunk-1m-plus-one.bin');
    final sink = BytesBuilder();
    final encoder = Streaming.newEncoder([], EncodeOptions(chunkSize: 1 << 20, key: _key, baseNonce: _baseNonce));
    await encoder.write(input);
    await encoder.finish((bytes) async => sink.add(bytes));
    final streamed = sink.toBytes();
    expect(streamed, equals(readVector('expected/encrypted-chunk-1m-plus-one.ubc')));

    final decoder = await Streaming.newDecoder(memorySource(streamed), DecodeOptions(key: _key));
    final decoded = await decoder.readAll();
    expect(decoded, equals(input));
  });

  test('streamed plain decoder withholds output until root verifies', () async {
    final container = Uint8List.fromList(readVector('expected/plain-chunk-1m.ubc'));
    container[container.length - 1] ^= 0x01; // corrupt footer magic's last byte
    final decoder = await Streaming.newDecoder(memorySource(container));
    await expectLater(
      decoder.readAll(),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.truncated)),
    );
  });

  test('streamed plain decoder withholds output until trailing data is checked', () async {
    final container = Uint8List.fromList([...readVector('expected/plain-chunk-1m.ubc'), 0]);
    final decoder = await Streaming.newDecoder(memorySource(container));
    await expectLater(
      decoder.readAll(),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.trailingData)),
    );
  });

  test('truncated encrypted footer precedes final chunk authentication', () async {
    // Corrupt both the final chunk's GCM tag AND truncate the footer. SPEC.md section 5
    // requires truncation (stage 4) to win over chunk-auth failure (stage 5).
    final container = Uint8List.fromList(readVector('expected/encrypted-one-byte.ubc'));
    final footerStart = container.length - 36;
    container[footerStart - 1] ^= 0x01; // flip the last byte of the only chunk's GCM tag
    final truncated = Uint8List.sublistView(container, 0, container.length - 10);

    final decoder = await Streaming.newDecoder(memorySource(truncated), DecodeOptions(key: _key));
    await expectLater(
      decoder.readAll(),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.truncated)),
    );
  });

  test('streamed encoder with large chunk size only buffers written input', () async {
    // A chunk_size far larger than the actual input must not cause the encoder to
    // allocate a chunk_size-sized buffer (the historical Rust OOM bug this guards against).
    final input = Uint8List.fromList([1, 2, 3]);
    final sink = BytesBuilder();
    final encoder = Streaming.newEncoder([], EncodeOptions(chunkSize: 1 << 28)); // 256 MiB
    await encoder.write(input);
    await encoder.finish((bytes) async => sink.add(bytes));
    final result = Payload.decodePlain(sink.toBytes());
    expect(result.data, equals(input));
  });

  test('streamed decoder enforces caps before allocating chunk data', () async {
    final container = readVector('expected/plain-chunk-1m.ubc');
    final tight = DecodeOptions(maxMetaBytes: 16 << 20, maxChunkLen: 4, maxChunkCount: 1 << 20, maxTotalSize: 1 << 30);
    final decoder = await Streaming.newDecoder(memorySource(container), tight);
    await expectLater(
      decoder.read(4096),
      throwsA(isA<UbcException>().having((e) => e.code, 'code', ErrorCode.truncated)),
    );
  });

  test('verify and inspect have their documented read scopes', () async {
    final container = readVector('expected/plain-metadata.ubc');
    final ok = await Streaming.verify(memorySource(container));
    expect(ok.ok, isTrue);

    final corrupted = Uint8List.fromList(container);
    corrupted[Header.size + 4] ^= 0x01;
    final bad = await Streaming.verify(memorySource(corrupted));
    expect(bad.ok, isFalse);
    expect(bad.error, ErrorCode.rootMismatch);

    // inspect only reads header + metadata; it must not touch (or require) the payload or
    // footer at all, so a source with the footer deliberately mangled still works.
    final mangledFooter = Uint8List.fromList(container);
    mangledFooter[mangledFooter.length - 1] ^= 0x01;
    final info = await Streaming.inspect(memorySource(mangledFooter));
    expect(info.hasMetadata, isTrue);
    expect(info.encrypted, isFalse);
    expect(info.metadata.length, 4);
  });
}
