import 'dart:typed_data';

import 'crypto_internal.dart';
import 'decode_options.dart';
import 'error_code.dart';
import 'header.dart';
import 'metadata.dart';
import 'metadata_entry.dart';
import 'root_accumulator.dart';
import 'ubc_exception.dart';

/// A pull-based streaming UBC v1 decoder. Each encrypted chunk is authenticated (GCM tag
/// verified) before any of its plaintext is returned (SPEC.md section 3,
/// verify-before-release). [source] is a request-based byte source: given a requested
/// length, it returns up to that many bytes (fewer at end of stream, empty when exhausted).
class Decoder {
  Decoder._(this._source, this._options);

  /// Creates a decoder and eagerly parses the header + metadata (matching every other
  /// SDK's constructor-time behavior) — Dart constructors cannot be async, so header/
  /// metadata errors that every other SDK's constructor throws synchronously surface here
  /// as a rejected Future instead.
  static Future<Decoder> open(Future<Uint8List> Function(int length) source, [DecodeOptions? options]) async {
    final decoder = Decoder._(source, options ?? const DecodeOptions());
    await decoder._ensureInitialized();
    return decoder;
  }

  final Future<Uint8List> Function(int length) _source;
  final DecodeOptions _options;

  Header? _header;
  Uint8List? _headerBytes;
  Uint8List? _metadataDigest;
  RootAccumulator? _root;
  Uint8List? _baseNonce;
  List<MetadataEntry> _metadata = const [];

  int _chunkIndex = 0;
  int _plaintextSize = 0;
  Uint8List? _pending;
  int _pendingOffset = 0;
  Uint8List? _prefetchedFooter;
  bool _finished = false;
  UbcException? _terminalError;
  bool _initialized = false;

  static const int _footerSize = 36;
  static final Uint8List _footerMagic = Uint8List.fromList('UBCE'.codeUnits);

  List<MetadataEntry> get metadata => _metadata;

  Future<void> _ensureInitialized() async {
    if (_initialized) {
      return;
    }
    _initialized = true;

    final headerBytes = await _readExact(Header.size);
    final header = Header.parse(headerBytes);
    _header = header;
    _headerBytes = headerBytes;

    var entries = <MetadataEntry>[];
    var metadataRegion = Uint8List(0);
    if (header.hasMetadata) {
      metadataRegion = await _readMetadataRegion(_options.maxMetaBytes);
      final result = Metadata.parse(metadataRegion, 0, _boundedCap(_options.maxMetaBytes));
      entries = result.entries;
    }
    _metadata = entries;

    final key = _options.key;
    if (header.encrypted && (key == null || key.length != 32)) {
      throw const UbcException(ErrorCode.missingKey);
    }
    if (header.chunkCount > _options.maxChunkCount || header.totalSize > _options.maxTotalSize) {
      throw const UbcException(ErrorCode.truncated);
    }

    _metadataDigest = CryptoInternal.sha256(metadataRegion);
    _baseNonce = header.encrypted ? header.baseNonce : null;
    _root = header.encrypted ? RootAccumulator.keyed(CryptoInternal.rootKey(key!, _baseNonce!)) : RootAccumulator.plain();
    _root!.update(headerBytes);
    _root!.update(metadataRegion);
  }

  /// Reads up to [length] bytes; returns an empty list at end of stream.
  Future<Uint8List> read(int length) async {
    if (_terminalError != null) {
      throw _terminalError!;
    }
    if (length == 0) {
      return Uint8List(0);
    }
    try {
      await _ensureInitialized();
      while (_pending == null && !_finished) {
        await _loadNextChunk();
      }
    } on UbcException catch (e) {
      _terminalError = e;
      rethrow;
    }
    final pending = _pending;
    if (pending == null) {
      return Uint8List(0);
    }
    final available = pending.length - _pendingOffset;
    final toCopy = available < length ? available : length;
    final output = Uint8List.sublistView(pending, _pendingOffset, _pendingOffset + toCopy);
    _pendingOffset += toCopy;
    if (_pendingOffset == pending.length) {
      _pending = null;
      _pendingOffset = 0;
    }
    return output;
  }

  /// Reads and discards everything, returning the fully assembled plaintext.
  Future<Uint8List> readAll() async {
    final output = BytesBuilder();
    Uint8List chunk;
    while ((chunk = await read(32 << 10)).isNotEmpty) {
      output.add(chunk);
    }
    return output.toBytes();
  }

  Future<void> _loadNextChunk() async {
    final header = _header!;
    if (_chunkIndex == header.chunkCount) {
      await _verifyFooter();
      return;
    }
    final lengthBytes = await _readExact(4);
    final chunkLength = ByteData.sublistView(lengthBytes).getUint32(0, Endian.little);
    if (chunkLength > _options.maxChunkLen) {
      throw const UbcException(ErrorCode.truncated);
    }
    final body = await _readExact(chunkLength);
    _root!.update(CryptoInternal.sha256(body));

    final isLastChunk = _chunkIndex + 1 == header.chunkCount;
    if (header.encrypted && isLastChunk) {
      // Preflight the footer before authenticating the final chunk so a truncated stream
      // surfaces ERR_TRUNCATED rather than a misleading ERR_CHUNK_AUTH — SPEC.md section 5's
      // precedence requires truncation to win over chunk-auth failure.
      _prefetchedFooter = await _readExact(_footerSize);
    }

    Uint8List plain;
    if (header.encrypted) {
      if (body.length < CryptoInternal.gcmTagSize) {
        throw const UbcException(ErrorCode.chunkAuth);
      }
      final aad = CryptoInternal.chunkAad(_headerBytes!, _metadataDigest!, _chunkIndex);
      plain = await CryptoInternal.gcmDecrypt(_options.key!, CryptoInternal.chunkNonce(_baseNonce!, _chunkIndex), body, aad);
    } else {
      plain = body;
    }

    if (plain.length > header.totalSize - _plaintextSize) {
      throw const UbcException(ErrorCode.rootMismatch);
    }
    _plaintextSize += plain.length;
    _chunkIndex++;
    _pending = plain.isEmpty ? null : plain;
    _pendingOffset = 0;
  }

  Future<void> _verifyFooter() async {
    final footer = _prefetchedFooter ?? await _readExact(_footerSize);
    final footerRoot = Uint8List.sublistView(footer, 0, 32);
    final footerMagic = Uint8List.sublistView(footer, 32, _footerSize);
    if (!_bytesEqual(footerMagic, _footerMagic)) {
      throw const UbcException(ErrorCode.truncated);
    }
    if (_plaintextSize != _header!.totalSize || !_constantTimeEqual(_root!.finish(), footerRoot)) {
      throw const UbcException(ErrorCode.rootMismatch);
    }
    final trailing = await _source(1);
    if (trailing.isNotEmpty) {
      throw const UbcException(ErrorCode.trailingData);
    }
    _finished = true;
  }

  Future<Uint8List> _readMetadataRegion(int maxMetaBytes) async {
    final prefix = await _readExact(4);
    final metadataLength = ByteData.sublistView(prefix).getUint32(0, Endian.little);
    if (metadataLength == 0 || metadataLength > maxMetaBytes) {
      throw const UbcException(ErrorCode.metaMalformed);
    }
    Uint8List body;
    try {
      body = await _readExact(metadataLength);
    } on UbcException catch (e) {
      if (e.code == ErrorCode.truncated) {
        throw const UbcException(ErrorCode.metaMalformed);
      }
      rethrow;
    }
    return Uint8List.fromList([...prefix, ...body]);
  }

  Future<Uint8List> _readExact(int length) async {
    final data = BytesBuilder();
    var remaining = length;
    while (remaining > 0) {
      final chunk = await _source(remaining);
      if (chunk.isEmpty) {
        throw const UbcException(ErrorCode.truncated);
      }
      data.add(chunk);
      remaining -= chunk.length;
    }
    return data.toBytes();
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
