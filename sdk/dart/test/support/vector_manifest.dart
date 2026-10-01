import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:ubc/ubc.dart';

/// Reads spec/vectors/vectors.json and encodes/decodes vectors through the Dart SDK.
class VectorManifest {
  VectorManifest(this.vectors);

  final List<Vector> vectors;

  static String vectorsRoot() => p.normalize(p.join(Directory.current.path, '..', '..', 'spec', 'vectors'));

  static VectorManifest read(String vectorsRoot) {
    final jsonText = File(p.join(vectorsRoot, 'vectors.json')).readAsStringSync();
    final decoded = json.decode(jsonText) as Map<String, dynamic>;
    final rawVectors = decoded['vectors'] as List<dynamic>;
    final vectors = rawVectors.map((v) => Vector.from(v as Map<String, dynamic>)).toList();
    return VectorManifest(vectors);
  }

  /// The key shared by every encrypted positive vector, used to decode negative vectors that omit options.
  Uint8List canonicalKey() {
    for (final vector in vectors) {
      if (vector.expectError == null && vector.options?.key != null) {
        return vector.options!.key!;
      }
    }
    throw StateError('manifest has no encrypted positive vector');
  }

  Vector find(String id) => vectors.firstWhere((v) => v.id == id, orElse: () => throw StateError('manifest vector is missing: $id'));
}

class Vector {
  Vector({
    required this.id,
    required this.input,
    required this.options,
    required this.expected,
    required this.expectedSha256,
    required this.expectError,
  });

  final String id;
  final String? input;
  final VectorOptions? options;
  final String expected;
  final Uint8List expectedSha256;
  final String? expectError;

  static Vector from(Map<String, dynamic> raw) => Vector(
        id: raw['id'] as String,
        input: raw['input'] as String?,
        options: raw['options'] != null ? VectorOptions.from(raw['options'] as Map<String, dynamic>) : null,
        expected: raw['expected'] as String,
        expectedSha256: _hex(raw['expectedSha256'] as String),
        expectError: raw['expectError'] as String?,
      );

  /// Encodes this vector's input through the Dart SDK using its declared options.
  Future<Uint8List> encode(Uint8List inputBytes) async {
    final opts = options;
    if (opts == null) {
      throw StateError('$id: positive vector has no options');
    }
    if (opts.key != null && opts.baseNonce != null) {
      return Crypto.encodeEncryptedWithFixedNonce(inputBytes, opts.key!, opts.baseNonce!, opts.metadata, opts.chunkSize);
    }
    if (opts.key == null && opts.baseNonce == null) {
      return Payload.encodePlain(inputBytes, opts.metadata, opts.chunkSize);
    }
    throw StateError('$id: key and baseNonce must be paired');
  }

  /// Decodes a container, auto-detecting plain vs encrypted from the header itself
  /// (mirrors Go's single DecodeBytes entry point). key is used only if the container
  /// turns out to be encrypted.
  Future<DecodedVector> decode(Uint8List container, Uint8List? key) async {
    try {
      final encrypted = Header.parse(container).encrypted;
      if (encrypted) {
        final result = await Crypto.decodeEncrypted(container, DecodeOptions(key: key));
        return DecodedVector(result.data, result.metadata, null);
      }
      final result = Payload.decodePlain(container);
      return DecodedVector(result.data, result.metadata, null);
    } on UbcException catch (e) {
      return DecodedVector(null, null, e.code);
    }
  }
}

class VectorOptions {
  VectorOptions({required this.chunkSize, required this.key, required this.baseNonce, required this.metadata});

  final int chunkSize;
  final Uint8List? key;
  final Uint8List? baseNonce;
  final List<MetadataEntry> metadata;

  static VectorOptions from(Map<String, dynamic> raw) {
    final metadata = <MetadataEntry>[];
    final rawMetadata = raw['metadata'] as List<dynamic>?;
    if (rawMetadata != null) {
      for (final rawEntry in rawMetadata) {
        final entry = rawEntry as Map<String, dynamic>;
        final tag = int.parse((entry['tag'] as String).substring(2), radix: 16);
        metadata.add(MetadataEntry(tag, _hex(entry['valueHex'] as String)));
      }
    }
    return VectorOptions(
      chunkSize: raw['chunkSize'] as int,
      key: raw['key'] != null ? _hex(raw['key'] as String) : null,
      baseNonce: raw['baseNonce'] != null ? _hex(raw['baseNonce'] as String) : null,
      metadata: metadata,
    );
  }
}

class DecodedVector {
  DecodedVector(this.data, this.metadata, this.error);

  final Uint8List? data;
  final List<MetadataEntry>? metadata;
  final ErrorCode? error;
}

Uint8List _hex(String value) {
  final result = Uint8List(value.length ~/ 2);
  for (var i = 0; i < value.length; i += 2) {
    result[i ~/ 2] = int.parse(value.substring(i, i + 2), radix: 16);
  }
  return result;
}
