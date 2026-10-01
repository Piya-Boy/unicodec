import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'crypto_internal.dart';
import 'error_code.dart';
import 'header.dart';
import 'metadata.dart';
import 'metadata_entry.dart';
import 'encode_options.dart';
import 'root_accumulator.dart';
import 'ubc_exception.dart';

/// A write-then-finish streaming UBC v1 encoder. Plaintext is spooled to a temp file until
/// its final size is known, because the v1 header precedes the payload and carries both
/// size and chunk count (SPEC.md section 2.1).
///
/// Uses a Dart temp file as the spool: no deleteOnExit()/finalizer safety net is attempted
/// here (Dart has neither) — callers MUST call [finish] (which always purges the spool, in
/// a try/finally, even on error) exactly once. An abandoned Encoder that is never finished
/// leaks its spool file, same caveat as any `dart:io` temp file a program forgets to clean
/// up; this is documented rather than silently assumed acceptable.
class Encoder {
  Encoder(this._entries, [EncodeOptions? options]) : _options = options ?? EncodeOptions() {
    _metadata = Metadata.encode(_entries);
  }

  final List<MetadataEntry> _entries;
  final EncodeOptions _options;
  late final Uint8List _metadata;
  File? _spoolFile;
  RandomAccessFile? _spool;
  int _totalSize = 0;
  bool _finished = false;

  Future<void> write(Uint8List data) async {
    if (_finished) {
      throw StateError('encoder is already finished');
    }
    _spool ??= await (_spoolFile = await File(
      '${Directory.systemTemp.path}${Platform.pathSeparator}ubc-encoder-${_randomSuffix()}.spool',
    ).create())
        .open(mode: FileMode.write);
    await _spool!.writeFrom(data);
    _totalSize += data.length;
  }

  /// Computes the header/payload/root/footer and writes the complete container to [sink],
  /// then purges the spool. Must be called exactly once.
  Future<void> finish(Future<void> Function(Uint8List) sink) async {
    if (_finished) {
      throw StateError('encoder is already finished');
    }
    _finished = true;
    try {
      await _finishInto(sink);
    } finally {
      await _purgeSpool();
    }
  }

  Future<void> _finishInto(Future<void> Function(Uint8List) sink) async {
    final chunkSize = _options.chunkSize;
    final encrypted = _options.key != null;
    if (encrypted && chunkSize > 0xFFFFFFEF) {
      throw const UbcException(ErrorCode.reservedBits);
    }
    final chunkCount = _totalSize == 0 ? 0 : (_totalSize + chunkSize - 1) ~/ chunkSize;
    final Uint8List baseNonce;
    if (encrypted) {
      baseNonce = _options.baseNonce ?? _randomNonce();
    } else {
      baseNonce = Uint8List(12);
    }

    final header = Header(
      flags: (encrypted ? Header.flagEncrypted : 0) | (_metadata.isNotEmpty ? Header.flagHasMetadata : 0),
      hashAlgo: encrypted ? Header.hashHmacSha256 : Header.hashSha256,
      aeadAlgo: encrypted ? Header.aeadAes256Gcm : Header.aeadNone,
      chunkSize: chunkSize,
      chunkCount: chunkCount,
      totalSize: _totalSize,
      baseNonce: baseNonce,
    );
    final headerBytes = header.toBytes();
    await sink(headerBytes);
    await sink(_metadata);

    final metadataDigest = CryptoInternal.sha256(_metadata);
    final root = encrypted
        ? RootAccumulator.keyed(CryptoInternal.rootKey(_options.key!, baseNonce))
        : RootAccumulator.plain();
    root.update(headerBytes);
    root.update(_metadata);

    final spool = _spool;
    if (spool != null) {
      await spool.setPosition(0);
    }
    final buffer = Uint8List(min(_totalSize, chunkSize));
    final clenBuffer = ByteData(4);
    var index = 0;
    for (var written = 0; written < _totalSize; written += chunkSize, index++) {
      final length = (_totalSize - written) < chunkSize ? _totalSize - written : chunkSize;
      final chunk = await _readExact(spool!, buffer, length);
      Uint8List body;
      if (encrypted) {
        final aad = CryptoInternal.chunkAad(headerBytes, metadataDigest, index);
        body = await CryptoInternal.gcmEncrypt(_options.key!, CryptoInternal.chunkNonce(baseNonce, index), chunk, aad);
      } else {
        body = chunk;
      }
      clenBuffer.setUint32(0, body.length, Endian.little);
      await sink(clenBuffer.buffer.asUint8List());
      await sink(body);
      root.update(CryptoInternal.sha256(body));
    }

    await sink(root.finish());
    await sink(Uint8List.fromList('UBCE'.codeUnits));
  }

  Future<Uint8List> _readExact(RandomAccessFile file, Uint8List buffer, int length) async {
    var total = 0;
    while (total < length) {
      final read = await file.readInto(buffer, total, length);
      if (read == 0) {
        throw const UbcException(ErrorCode.truncated);
      }
      total += read;
    }
    return Uint8List.sublistView(buffer, 0, length);
  }

  Future<void> _purgeSpool() async {
    final spool = _spool;
    if (spool != null) {
      try {
        await spool.close();
      } on FileSystemException {
        // best-effort close; the file delete below still runs
      }
    }
    final spoolFile = _spoolFile;
    if (spoolFile != null) {
      try {
        await spoolFile.delete();
      } on FileSystemException {
        // best-effort delete; nothing further to do if the OS won't release the handle
      }
    }
  }

  static Uint8List _randomNonce() {
    final nonce = Uint8List(12);
    final random = Random.secure();
    for (var i = 0; i < 12; i++) {
      nonce[i] = random.nextInt(256);
    }
    return nonce;
  }

  static String _randomSuffix() {
    final random = Random.secure();
    final bytes = List<int>.generate(16, (_) => random.nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
