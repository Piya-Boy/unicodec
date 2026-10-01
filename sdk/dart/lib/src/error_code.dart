/// Stable UBC error identifiers (SPEC.md section 5). Identical across every SDK.
enum ErrorCode {
  badMagic('ERR_BAD_MAGIC'),
  unsupportedVersion('ERR_UNSUPPORTED_VER'),
  unsupportedAlgorithm('ERR_UNSUPPORTED_ALGO'),
  reservedBits('ERR_RESERVED_BITS'),
  truncated('ERR_TRUNCATED'),
  rootMismatch('ERR_ROOT_MISMATCH'),
  chunkAuth('ERR_CHUNK_AUTH'),
  missingKey('ERR_MISSING_KEY'),
  metaMalformed('ERR_META_MALFORMED'),
  trailingData('ERR_TRAILING_DATA');

  const ErrorCode(this.stableId);

  /// The stable, cross-SDK identifier string (e.g. "ERR_BAD_MAGIC").
  final String stableId;
}
