import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';

import 'support/vector_manifest.dart';

/// Drives every vector in spec/vectors/vectors.json through the Dart SDK — the manifest is the contract.
void main() {
  test('every shared manifest vector conforms', () async {
    final root = VectorManifest.vectorsRoot();
    final manifest = VectorManifest.read(root);
    final canonicalKey = manifest.canonicalKey();
    var positiveCount = 0;
    var negativeCount = 0;

    for (final vector in manifest.vectors) {
      final expected = File('$root/${vector.expected}').readAsBytesSync();
      expect(
        crypto.sha256.convert(expected).bytes,
        equals(vector.expectedSha256),
        reason: '${vector.id}: expected artifact SHA-256 differs from vectors.json',
      );

      if (vector.expectError != null) {
        negativeCount++;
        final vectorKey = vector.options?.key;
        final decodeKey = _requiresKey(vector.id) ? (vectorKey ?? canonicalKey) : null;
        final decoded = await vector.decode(expected, decodeKey);
        expect(decoded.error, isNotNull, reason: '${vector.id}: negative vector must not decode successfully');
        expect(decoded.error!.stableId, equals(vector.expectError), reason: '${vector.id}: stable error id differs');
        continue;
      }

      positiveCount++;
      final input = File('$root/${vector.input}').readAsBytesSync();
      final encoded = await vector.encode(input);
      expect(encoded, equals(expected), reason: '${vector.id}: encoded container differs from vectors.json artifact');

      final result = await vector.decode(expected, vector.options!.key);
      expect(result.error, isNull, reason: '${vector.id}: decode failed with ${result.error}');
      expect(result.data, equals(input), reason: '${vector.id}: decoded plaintext differs');
      final expectedMetadata = vector.options!.metadata;
      expect(result.metadata!.length, equals(expectedMetadata.length), reason: '${vector.id}: decoded metadata count differs');
      for (var i = 0; i < expectedMetadata.length; i++) {
        expect(result.metadata![i].tag, equals(expectedMetadata[i].tag), reason: '${vector.id}: metadata tag $i');
        expect(result.metadata![i].value, equals(expectedMetadata[i].value), reason: '${vector.id}: metadata value $i');
      }
    }

    expect(positiveCount, greaterThan(0), reason: 'manifest must contain positive vectors');
    expect(negativeCount, greaterThan(0), reason: 'manifest must contain negative vectors');
  });
}

// Negative vectors whose own point is "decoded without a key" must actually be decoded
// without one; every other negative vector decodes with the canonical/vector-supplied key
// so a missing-key short-circuit doesn't mask the error the vector is meant to exercise.
bool _requiresKey(String id) => id != 'negative-missing-key' && id != 'negative-encrypted-cap-missing-key';
