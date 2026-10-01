import 'dart:typed_data';

/// Resource limits applied while decoding untrusted containers.
class DecodeOptions {
  const DecodeOptions({
    this.maxMetaBytes = defaultMaxMetaBytes,
    this.maxChunkLen = defaultMaxChunkLen,
    this.maxChunkCount = defaultMaxChunkCount,
    this.maxTotalSize = defaultMaxTotalSize,
    this.key,
  });

  static const int defaultMaxMetaBytes = 16 << 20;
  static const int defaultMaxChunkLen = 64 << 20;
  static const int defaultMaxChunkCount = 1 << 20;
  static const int defaultMaxTotalSize = 1 << 30;

  final int maxMetaBytes;
  final int maxChunkLen;
  final int maxChunkCount;
  final int maxTotalSize;
  final Uint8List? key;

  DecodeOptions withKey(Uint8List? key) => DecodeOptions(
        maxMetaBytes: maxMetaBytes,
        maxChunkLen: maxChunkLen,
        maxChunkCount: maxChunkCount,
        maxTotalSize: maxTotalSize,
        key: key,
      );
}
