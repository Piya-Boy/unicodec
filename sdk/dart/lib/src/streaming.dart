import 'dart:typed_data';

import 'container_info.dart';
import 'decode_options.dart';
import 'decoder.dart';
import 'encode_options.dart';
import 'encoder.dart';
import 'error_code.dart';
import 'header.dart';
import 'metadata.dart';
import 'metadata_entry.dart';
import 'ubc_exception.dart';
import 'verify_report.dart';

const int _readBlockSize = 32 << 10;

/// Factory, verify, and inspect entry points over Encoder/Decoder.
abstract final class Streaming {
  static Encoder newEncoder(List<MetadataEntry> entries, [EncodeOptions? options]) => Encoder(entries, options);

  static Future<Decoder> newDecoder(
    Future<Uint8List> Function(int length) source, [
    DecodeOptions? options,
  ]) =>
      Decoder.open(source, options);

  /// Fully decodes and discards the plaintext, reporting whether the container is valid.
  static Future<VerifyReport> verify(Future<Uint8List> Function(int length) source, [DecodeOptions? options]) async {
    try {
      final decoder = await Decoder.open(source, options);
      // discard; verification is in read()'s side effects (auth + root check)
      while ((await decoder.read(_readBlockSize)).isNotEmpty) {}
    } on UbcException catch (e) {
      return VerifyReport(false, e.code);
    }
    return VerifyReport(true, null);
  }

  /// Reads only the header and metadata — never touches payload or footer.
  static Future<ContainerInfo> inspect(
    Future<Uint8List> Function(int length) source, [
    DecodeOptions? options,
  ]) async {
    final opts = options ?? const DecodeOptions();
    final headerBytes = await _readExact(source, Header.size);
    final header = Header.parse(headerBytes);
    var entries = <MetadataEntry>[];
    if (header.hasMetadata) {
      final prefix = await _readExact(source, 4);
      final metadataLength = ByteData.sublistView(prefix).getUint32(0, Endian.little);
      if (metadataLength == 0 || metadataLength > opts.maxMetaBytes) {
        throw const UbcException(ErrorCode.metaMalformed);
      }
      Uint8List body;
      try {
        body = await _readExact(source, metadataLength);
      } on UbcException catch (e) {
        if (e.code == ErrorCode.truncated) {
          throw const UbcException(ErrorCode.metaMalformed);
        }
        rethrow;
      }
      final region = Uint8List.fromList([...prefix, ...body]);
      final result = Metadata.parse(region, 0, _boundedCap(opts.maxMetaBytes));
      entries = result.entries;
    }
    return ContainerInfo(
      version: Header.version,
      encrypted: header.encrypted,
      hasMetadata: header.hasMetadata,
      hashAlgo: header.hashAlgo,
      aeadAlgo: header.aeadAlgo,
      chunkSize: header.chunkSize,
      chunkCount: header.chunkCount,
      totalSize: header.totalSize,
      metadata: entries,
    );
  }

  static Future<Uint8List> _readExact(Future<Uint8List> Function(int length) source, int length) async {
    final data = BytesBuilder();
    var remaining = length;
    while (remaining > 0) {
      final chunk = await source(remaining);
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
