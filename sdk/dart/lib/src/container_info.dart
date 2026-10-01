import 'metadata_entry.dart';

/// Header and metadata summary returned by Streaming.inspect.
class ContainerInfo {
  ContainerInfo({
    required this.version,
    required this.encrypted,
    required this.hasMetadata,
    required this.hashAlgo,
    required this.aeadAlgo,
    required this.chunkSize,
    required this.chunkCount,
    required this.totalSize,
    required this.metadata,
  });

  final int version;
  final bool encrypted;
  final bool hasMetadata;
  final int hashAlgo;
  final int aeadAlgo;
  final int chunkSize;
  final int chunkCount;
  final int totalSize;
  final List<MetadataEntry> metadata;
}
