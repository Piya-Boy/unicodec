import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:path/path.dart' as p;

import '../test/support/vector_manifest.dart';

/// Cross-decode CLI matching the other SDKs' CLIs' contract: --vectors DIR --work DIR
/// --cases a,b,c [--write | --verify]. Invoked by scripts/cross-decode.mjs so Dart
/// participates in the full cross-decode matrix.
Future<void> main(List<String> args) async {
  try {
    await run(args);
    exit(0);
  } catch (e) {
    stderr.writeln(e is Exception || e is Error ? e.toString() : '$e');
    exit(1);
  }
}

Future<void> run(List<String> args) async {
  final arguments = parseArguments(args);
  final manifest = VectorManifest.read(arguments.vectorsRoot);
  final canonicalKey = manifest.canonicalKey();

  for (final id in arguments.caseIds) {
    final vector = manifest.find(id);
    if (vector.expectError != null) {
      throw StateError('negative cross-decode case is not allowed: $id');
    }
    if (vector.input == null) {
      throw StateError('$id: positive vector has no input');
    }
    final input = File(safeChild(arguments.vectorsRoot, vector.input!)).readAsBytesSync();
    final expected = File(safeChild(arguments.vectorsRoot, vector.expected)).readAsBytesSync();
    if (!_bytesEqual(Uint8List.fromList(crypto.sha256.convert(expected).bytes), vector.expectedSha256)) {
      throw StateError('$id: expected artifact SHA-256 differs from vectors.json');
    }

    if (arguments.write) {
      final container = await vector.encode(input);
      if (!_bytesEqual(container, expected)) {
        throw StateError('$id: Dart encode differs from shared artifact');
      }
      File(safeChild(arguments.workDir, '$id.dart.ubc')).writeAsBytesSync(container);
    } else {
      final key = vector.options?.key ?? canonicalKey;
      for (final producer in ['go', 'node', 'python', 'rust', 'java', 'dotnet', 'php', 'dart']) {
        final container = File(safeChild(arguments.workDir, '$id.$producer.ubc')).readAsBytesSync();
        final decoded = await vector.decode(container, key);
        if (decoded.error != null) {
          throw StateError('$id: Dart rejected $producer container with ${decoded.error!.stableId}');
        }
        if (!_bytesEqual(decoded.data!, input)) {
          throw StateError('$id: Dart-decoded $producer plaintext differs from manifest input');
        }
        final expectedMetadata = vector.options?.metadata ?? const [];
        if (!_metadataEquals(decoded.metadata!, expectedMetadata)) {
          throw StateError('$id: Dart-decoded $producer metadata differs from manifest');
        }
        final reencoded = await vector.encode(decoded.data!);
        if (!_bytesEqual(reencoded, expected)) {
          throw StateError('$id: $producer-to-Dart re-encode is not byte-identical');
        }
        if (!_bytesEqual(container, expected)) {
          throw StateError('$id: fresh $producer container differs from shared artifact');
        }
      }
    }
  }
}

bool _metadataEquals(List<dynamic> actual, List<dynamic> expected) {
  if (actual.length != expected.length) {
    return false;
  }
  for (var i = 0; i < actual.length; i++) {
    if (actual[i].tag != expected[i].tag || !_bytesEqual(actual[i].value as Uint8List, expected[i].value as Uint8List)) {
      return false;
    }
  }
  return true;
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

String safeChild(String root, String child) {
  if (child.isEmpty) {
    throw ArgumentError('manifest path must be a non-empty relative path');
  }
  final target = p.normalize(p.join(root, child));
  final normalizedRoot = p.normalize(root) + Platform.pathSeparator;
  if (!target.startsWith(normalizedRoot)) {
    throw ArgumentError('manifest path escapes vectors root: $child');
  }
  return target;
}

bool safeId(String id) => RegExp(r'^[a-z0-9]+(-[a-z0-9]+)*$').hasMatch(id);

String existingDirectory(String? path, String label) {
  if (path == null || path.isEmpty) {
    throw ArgumentError('--$label is required');
  }
  final resolved = p.normalize(p.absolute(path));
  if (!Directory(resolved).existsSync()) {
    throw ArgumentError('$label path is not a directory');
  }
  return resolved;
}

class Arguments {
  Arguments(this.vectorsRoot, this.workDir, this.caseIds, this.write);

  final String vectorsRoot;
  final String workDir;
  final List<String> caseIds;
  final bool write;
}

Arguments parseArguments(List<String> args) {
  String? vectorsRoot;
  String? workDir;
  String? cases;
  bool? write;
  var i = 0;
  while (i < args.length) {
    final argument = args[i];
    switch (argument) {
      case '--vectors':
        vectorsRoot = args[++i];
      case '--work':
        workDir = args[++i];
      case '--cases':
        cases = args[++i];
      case '--write':
        if (write != null) {
          throw ArgumentError('--write/--verify specified more than once');
        }
        write = true;
      case '--verify':
        if (write != null) {
          throw ArgumentError('--write/--verify specified more than once');
        }
        write = false;
      default:
        throw ArgumentError('unexpected argument: $argument');
    }
    i++;
  }
  final resolvedVectorsRoot = existingDirectory(vectorsRoot, 'vectors');
  final resolvedWorkDir = existingDirectory(workDir, 'work');
  if (cases == null) {
    throw ArgumentError('--cases is required');
  }
  if (write == null) {
    throw ArgumentError('exactly one of --write or --verify is required');
  }
  final seen = <String>{};
  final caseIds = <String>[];
  for (final id in cases.split(',')) {
    if (!safeId(id) || !seen.add(id)) {
      throw ArgumentError('unsafe or duplicate case id: $id');
    }
    caseIds.add(id);
  }
  if (caseIds.isEmpty) {
    throw ArgumentError('--cases must not be empty');
  }
  return Arguments(resolvedVectorsRoot, resolvedWorkDir, caseIds, write);
}
